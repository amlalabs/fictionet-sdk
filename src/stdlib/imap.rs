//! IMAP: reading and writing commands and responses, with no I/O.
//!
//! `Command` and `Response` implement `Wire`. `Inputs` and `Responses` decode
//! commands, literals, and replies. Their framing modes do not implement an
//! authenticated mailbox session, a `Service`, storage, or TLS.
//!
//! IMAP is how mail clients read mail kept on a server, usually over TCP
//! port 143. A client sends commands. Each is a line that starts with a
//! tag the client picks, then a command name and its arguments. The
//! server sends untagged responses, lines that start with `*`, which carry
//! data and news. It ends each command with a tagged response: the same
//! tag, then `OK`, `NO` or `BAD`. This module follows RFC 3501 (IMAP4rev1)
//! and RFC 9051 (IMAP4rev2), with the non-synchronizing literals of RFC
//! 7888 and the binary literals of RFC 3516.
//!
//! An argument is an atom (`INBOX`, `1:*`, `\Seen`, `BODY[HEADER]`), a
//! quoted string (`"Sent Items"`), a parenthesized list, or a literal. A
//! literal is `{n}` at the end of a line, then exactly n bytes, and the
//! line goes on after them. For a synchronizing literal, `{n}`, the client
//! waits for a continuation request (a line that starts with `+`) before
//! it sends the bytes. For a non-synchronizing one, `{n+}`, it does not
//! wait. A binary literal, `~{n}`, may also hold NUL bytes.
//!
//! Run a server's connection bytes through
//! [`Stream<Inputs>`](fictionet::stdlib::codec::Stream). Each item is a [`Command`],
//! a literal continuation, or a syntax error. Send a [`Response`] for each
//! command. Clients read [`Stream<Responses>`](fictionet::stdlib::codec::Stream).
//! Mailboxes, messages, and command execution belong to world code.
//!
//! Readers require CRLF and bound lines, literals, messages, and nesting.
//! Syntax errors at known boundaries allow the next command. An oversized
//! synchronizing literal can be refused while the client waits; other
//! overflows end the stream. Commands apply RFC 9051's non-synchronizing
//! literal limit. Server responses cannot use non-synchronizing literals.
//! Select raw AUTHENTICATE answers or IDLE `DONE` with
//! [`Inputs::expect_line`] between items.
//!
//! ```
//! use fictionet::stdlib::{codec::{Stream, Wire}, imap::{Inputs, Input, Response, Status}};
//!
//! let mut stream = Stream::new(Inputs::new());
//! let line = b"a1 LOGIN alice {6}\r\n";
//! assert_eq!(stream.push(line), line.len());
//! assert!(matches!(stream.next(), Some(Ok(Ok(Input::Continue { size: 6, .. })))));
//! assert_eq!(Response::continue_req("Ready").to_bytes().unwrap(), b"+ Ready\r\n");
//! assert_eq!(stream.push(b"secret\r\n"), 8);
//! let Some(Ok(Ok(Input::Command(command)))) = stream.next() else { panic!() };
//! assert_eq!(command.tag, "a1");
//! assert!(command.is("login"));
//! assert_eq!(command.args[1].as_bytes(), Some(&b"secret"[..]));
//! assert_eq!(Response::tagged("a1", Status::Ok, "LOGIN completed").to_bytes().unwrap(),
//!            b"a1 OK LOGIN completed\r\n");
//! ```

extern crate alloc;

use self::alloc::{string::String, sync::Arc, vec::Vec};
use fictionet::stdlib::codec::{self, Decode, Wire};

/// The TCP port IMAP servers listen on.
pub const PORT: u16 = 143;
/// The most bytes a command or response may hold outside its literals:
/// every line, with its line ending, and every literal's `{n}`.
pub const MAX_TEXT: usize = 64 * 1024;
/// The longest literal a reader takes.
pub const MAX_LITERAL: usize = 1024 * 1024;
/// The most bytes one command or response may hold, literals included.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// The longest quoted string a reader takes, counted after escapes are
/// undone. Longer strings must use [`Value::Literal`] or [`Value::Binary`].
pub const MAX_QUOTED: usize = 8 * 1024;
/// How deeply parenthesized lists may nest.
pub const MAX_DEPTH: usize = 32;

/// One argument of a command or one item of a data response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A bare word, such as `INBOX`, `NIL`, `42`, `1:*`, `\Seen` or
    /// `BODY[HEADER.FIELDS (FROM)]`. The section in square brackets after
    /// `BODY`, `BODY.PEEK`, `BINARY`, `BINARY.PEEK` or `BINARY.SIZE` may
    /// hold spaces, parentheses and quoted strings; a reader writes a
    /// literal there, such as a header name sent as `{4}`, as a quoted
    /// string. Anywhere else `[` is an ordinary character, as in `foo[`.
    /// The writer refuses strings that cannot remain atoms.
    Atom(String),
    /// A UTF-8 string in double quotes, with escapes undone. NUL, CR,
    /// LF, invalid UTF-8, and lengths over [`MAX_QUOTED`] are refused.
    Quoted(Vec<u8>),
    /// A string sent as a literal. NUL and lengths over [`MAX_LITERAL`]
    /// are refused. Non-synchronizing commands also obey [`MAX_NON_SYNC`].
    Literal {
        /// The literal's bytes.
        data: Vec<u8>,
        /// Whether it was `{n+}`, which the client sends without waiting.
        /// Servers always write `{n}`, so this is false in responses.
        non_sync: bool,
    },
    /// A binary literal, `~{n}` (RFC 3516 and RFC 9051 `literal8`), as
    /// in APPEND and in a FETCH `BINARY[...]` response. It may hold any
    /// bytes, NUL included, up to [`MAX_LITERAL`].
    Binary {
        /// The literal's bytes.
        data: Vec<u8>,
        /// Whether it was `~{n+}`, which the client sends without
        /// waiting. This must be false in responses.
        non_sync: bool,
    },
    /// A parenthesized list. Nesting beyond [`MAX_DEPTH`] is refused.
    ///
    /// In a response, the lists at the start of a list are written next
    /// to each other with no space, as IMAP wants for the body parts of a
    /// multipart BODYSTRUCTURE, `((...)(...) "MIXED")`, and for the
    /// addresses in an ENVELOPE, `((...)(...))`. Every other item is set
    /// off by a space. A response reader takes lists with or without a
    /// space between them.
    List(Vec<Value>),
}

impl Value {
    /// An atom.
    pub fn atom(s: &str) -> Value {
        Value::Atom(s.to_string())
    }

    /// A quoted string when the bytes are UTF-8 without NUL, CR, or LF and
    /// fit [`MAX_QUOTED`]. Otherwise, a synchronizing [`Value::Literal`].
    /// The writer still refuses NUL and lengths over [`MAX_LITERAL`].
    /// Use [`Value::Binary`] for bytes that include NUL.
    pub fn string(b: &[u8]) -> Value {
        if b.len() <= MAX_QUOTED && text_str(b).is_ok() {
            Value::Quoted(b.to_vec())
        } else {
            Value::Literal {
                data: b.to_vec(),
                non_sync: false,
            }
        }
    }

    /// A number, as an atom.
    pub fn number(n: u64) -> Value {
        Value::Atom(n.to_string())
    }

    /// `NIL`, the empty value.
    pub fn nil() -> Value {
        Value::atom("NIL")
    }

    /// The bytes of an atom, quoted string or literal of either kind. Check
    /// [`Value::is_nil`] first where `NIL` may come.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Atom(a) => Some(a.as_bytes()),
            Value::Quoted(b) | Value::Literal { data: b, .. } | Value::Binary { data: b, .. } => Some(b),
            Value::List(_) => None,
        }
    }

    /// The bytes of [`Value::as_bytes`], if they are UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()?).ok()
    }

    /// The number an atom of digits holds, if it fits in a `u64`.
    pub fn as_number(&self) -> Option<u64> {
        let Value::Atom(a) = self else { return None };
        if a.is_empty() || !a.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        a.parse().ok()
    }

    /// The items of a list.
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(items) => Some(items),
            _ => None,
        }
    }

    /// Whether this is the atom `NIL`, in any case.
    pub fn is_nil(&self) -> bool {
        matches!(self, Value::Atom(a) if a.eq_ignore_ascii_case("NIL"))
    }
}

/// A command from a client: `tag SP name *(SP argument) CRLF`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// The client's tag, which the tagged response repeats.
    pub tag: String,
    /// The command name, in upper case, such as `LOGIN` or `UID`.
    pub name: String,
    /// The arguments, in order. For `UID FETCH`, the first is `FETCH`.
    pub args: Vec<Value>,
}

impl Command {
    /// A command with `tag`, `name` and `args`.
    pub fn new(tag: &str, name: &str, args: Vec<Value>) -> Command {
        Command { tag: tag.to_string(), name: name.to_ascii_uppercase(), args }
    }

    /// Whether the command's name is `name`, in any case.
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    fn parse_message(b: &[u8]) -> Result<Command, Error> {
        let tag = tag_of(b);
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let syntax = |reason| Error::Syntax { tag: tag.clone(), reason };
        let mut c = Cursor { b, i: 0, lits: 0 };
        let t = c.take_while(tag_char);
        if t.is_empty() {
            return Err(syntax("a command starts with a tag"));
        }
        let tag_s = ascii(t);
        if c.peek() != Some(b' ') {
            return Err(syntax("a space must follow the tag"));
        }
        c.i += 1;
        let name = c.take_while(atom_char);
        if name.is_empty() {
            return Err(syntax("a command name must follow the tag"));
        }
        let name = ascii(name).to_ascii_uppercase();
        let args = parse_values(&mut c, true).map_err(|e| e.into_error(tag.clone()))?;
        if b.len().saturating_sub(c.lits) > MAX_TEXT {
            return Err(Error::TooLong);
        }
        Ok(Command { tag: tag_s, name, args })
    }

    /// Finds continuation boundaries in one complete encoded command.
    /// Each offset is just after a synchronizing literal's marker and CRLF.
    /// Send bytes up to each offset, then wait for the peer's continuation.
    /// Refuses any input rejected by this command's exact parser.
    pub fn continuation_offsets(bytes: &[u8]) -> Result<Vec<usize>, Error> {
        Self::parse(bytes)?;
        let mut commands = Inputs::new();
        let mut offsets = Vec::new();
        let mut at = 0usize;
        loop {
            match commands
                .decode(bytes.get(at..).ok_or(Error::Incomplete)?, true)
                .map_err(Error::Framing)?
            {
                codec::Step::Item(Ok(Input::Continue { .. }), used) => {
                    at = at.checked_add(used).ok_or(Error::Incomplete)?;
                    offsets.push(at);
                }
                codec::Step::Skip(used) => {
                    at = at.checked_add(used).ok_or(Error::Incomplete)?
                }
                codec::Step::Item(Ok(Input::Command(_)), _) => return Ok(offsets),
                codec::Step::Item(Err(e), _) => return Err(e),
                _ => return Err(Error::Incomplete),
            }
        }
    }
}

/// The state a status response reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The command worked, or (untagged) a note.
    Ok,
    /// The command failed.
    No,
    /// The command was not understood, or (untagged) a protocol error.
    Bad,
    /// The greeting of a connection that is already logged in. Untagged
    /// only.
    Preauth,
    /// The server is closing the connection. Untagged only.
    Bye,
}

impl Status {
    /// The status as it is written: `OK`, `NO`, `BAD`, `PREAUTH` or `BYE`.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::No => "NO",
            Status::Bad => "BAD",
            Status::Preauth => "PREAUTH",
            Status::Bye => "BYE",
        }
    }

    fn from_word(w: &[u8]) -> Option<Status> {
        [Status::Ok, Status::No, Status::Bad, Status::Preauth, Status::Bye]
            .into_iter()
            .find(|s| w.eq_ignore_ascii_case(s.as_str().as_bytes()))
    }
}

/// A response from a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// A continuation request, `+ text`: the server waits for more from
    /// the client, such as a literal's bytes or an AUTHENTICATE answer.
    Continue {
        /// The text after `+ `, which may be base64.
        text: String,
    },
    /// A status response, such as `a1 OK [READ-WRITE] SELECT completed`
    /// or `* BYE logging out`.
    Status {
        /// The tag of the command it ends, or `None` for `*`. A writer
        /// refuses tagged `PREAUTH` or `BYE`.
        tag: Option<String>,
        /// The status.
        status: Status,
        /// The response code inside square brackets, such as
        /// `UIDVALIDITY 3857529045`, without the brackets.
        code: Option<String>,
        /// The human-readable text after the code.
        text: String,
    },
    /// An untagged data response, such as `* 23 EXISTS`: the items after
    /// `* `. A first atom that reads as a status word is refused. An empty
    /// list is written as `*`, which this module also accepts when reading.
    Data(Vec<Value>),
}

impl Response {
    /// A tagged status response that ends command `tag`.
    pub fn tagged(tag: &str, status: Status, text: &str) -> Response {
        Response::Status { tag: Some(tag.to_string()), status, code: None, text: text.to_string() }
    }

    /// An untagged status response, such as a greeting or `BYE`.
    pub fn untagged(status: Status, text: &str) -> Response {
        Response::Status { tag: None, status, code: None, text: text.to_string() }
    }

    /// This response with a response code, if it is a status response.
    pub fn with_code(mut self, code: &str) -> Response {
        if let Response::Status { code: c, .. } = &mut self {
            *c = Some(code.to_string());
        }
        self
    }

    /// The greeting a server sends first: `* OK text`.
    pub fn greeting(text: &str) -> Response {
        Response::untagged(Status::Ok, text)
    }

    /// `* BYE text`, sent before the server closes the connection.
    pub fn bye(text: &str) -> Response {
        Response::untagged(Status::Bye, text)
    }

    /// A continuation request, `+ text`.
    pub fn continue_req(text: &str) -> Response {
        Response::Continue { text: text.to_string() }
    }

    /// `* CAPABILITY` and the capabilities, such as `IMAP4rev2`.
    pub fn capability(caps: &[&str]) -> Response {
        let mut v = vec![Value::atom("CAPABILITY")];
        v.extend(caps.iter().map(|c| Value::atom(c)));
        Response::Data(v)
    }

    /// `* n EXISTS`: the mailbox holds `n` messages.
    pub fn exists(n: u32) -> Response {
        Response::Data(vec![Value::number(n.into()), Value::atom("EXISTS")])
    }

    /// `* n RECENT` (IMAP4rev1 only).
    pub fn recent(n: u32) -> Response {
        Response::Data(vec![Value::number(n.into()), Value::atom("RECENT")])
    }

    /// `* n EXPUNGE`: message `n` is gone.
    pub fn expunge(n: u32) -> Response {
        Response::Data(vec![Value::number(n.into()), Value::atom("EXPUNGE")])
    }

    /// `* FLAGS (...)`: the flags the mailbox knows, such as `\Seen`.
    pub fn flags(flags: &[&str]) -> Response {
        let list = flags.iter().map(|f| Value::atom(f)).collect();
        Response::Data(vec![Value::atom("FLAGS"), Value::List(list)])
    }

    /// `* LIST (attributes) delimiter mailbox`. A missing delimiter is
    /// `NIL`, and so is a control character, which the delimiter's
    /// quoted form cannot hold. The mailbox goes out as an atom only when
    /// IMAP allows one there; a name with a space, `%`, `*` or `\` goes
    /// out quoted, as does `NIL`. Names that cannot be quoted use a
    /// synchronizing literal, as in [`Value::string`]. The writer refuses
    /// NUL and lengths over [`MAX_LITERAL`] in those names.
    pub fn list(attributes: &[&str], delimiter: Option<char>, mailbox: &[u8]) -> Response {
        let attrs = attributes.iter().map(|a| Value::atom(a)).collect();
        let delim = match delimiter {
            Some(d) if !d.is_control() => Value::string(d.to_string().as_bytes()),
            _ => Value::nil(),
        };
        let astring = mailbox.iter().all(|&b| atom_char(b) || b == b']') && !mailbox.eq_ignore_ascii_case(b"NIL");
        let name = if astring && atom_ok(mailbox) { Value::Atom(ascii(mailbox)) } else { Value::string(mailbox) };
        Response::Data(vec![Value::atom("LIST"), Value::List(attrs), delim, name])
    }

    /// `* SEARCH` and the matching message numbers.
    pub fn search(numbers: &[u32]) -> Response {
        let mut v = vec![Value::atom("SEARCH")];
        v.extend(numbers.iter().map(|&n| Value::number(n.into())));
        Response::Data(v)
    }

    /// `* n FETCH (items)`, where `items` alternate names and values.
    pub fn fetch(n: u32, items: Vec<Value>) -> Response {
        Response::Data(vec![Value::number(n.into()), Value::atom("FETCH"), Value::List(items)])
    }

    fn parse_message(b: &[u8]) -> Result<Response, Error> {
        let tag = tag_of(b);
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let syntax = |reason| Error::Syntax { tag: tag.clone(), reason };
        let first_lf = b.iter().position(|&x| x == b'\n');
        let first = content(&b[..first_lf.map_or(b.len(), |p| p + 1)]);
        let kind = classify(first);
        if kind == Kind::Data {
            if b.first() != Some(&b'*') {
                return Err(syntax("a response starts with *, + or a tag and a status"));
            }
            let mut c = Cursor { b, i: 1, lits: 0 };
            // A server never waits for a continuation request.
            let values = parse_values(&mut c, false).map_err(|e| match e.into_error(tag.clone()) {
                Error::LiteralTooLarge { tag, size, .. } => Error::LiteralTooLarge { tag, size, waiting: false },
                e => e,
            })?;
            if b.len().saturating_sub(c.lits) > MAX_TEXT {
                return Err(Error::TooLong);
            }
            return Ok(Response::Data(values));
        }
        if b.len() > MAX_TEXT {
            return Err(Error::TooLong);
        }
        if !b.ends_with(b"\r\n") || first_lf != Some(b.len() - 1) {
            return Err(syntax("a status line must be one line ending in CRLF"));
        }
        let line = &b[..b.len() - 2];
        if kind == Kind::Continue {
            let text = match line.get(1..) {
                Some([]) | None => "",
                Some([b' ', rest @ ..]) => text_str(rest).map_err(syntax)?,
                Some(_) => return Err(syntax("a space must follow +")),
            };
            return Ok(Response::Continue { text: text.to_string() });
        }
        // classify() found a tag or `*`, a space, a status word, and then
        // a space or the end of the line.
        let sp = line.iter().position(|&x| x == b' ').unwrap_or(line.len());
        let rtag = if &line[..sp] == b"*" { None } else { Some(ascii(&line[..sp])) };
        let rest = line.get(sp + 1..).unwrap_or(&[]);
        let w = rest.iter().position(|&x| x == b' ').unwrap_or(rest.len());
        let status = Status::from_word(&rest[..w]).ok_or_else(|| syntax("unknown status"))?;
        if rtag.is_some() && matches!(status, Status::Preauth | Status::Bye) {
            return Err(syntax("PREAUTH and BYE are never tagged"));
        }
        let (code, text) = resp_text(rest.get(w + 1..).unwrap_or(&[])).map_err(syntax)?;
        Ok(Response::Status { tag: rtag, status, code, text })
    }
}

/// Why bytes are not a command or response, or a value cannot be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The command or response breaks the grammar. The stream goes on
    /// after it, and a server answers `tag BAD`, or `* BAD` with no tag.
    Syntax {
        /// The tag at the start of the line, if there is a well-formed
        /// one.
        tag: Option<String>,
        /// What is wrong.
        reason: &'static str,
    },
    /// A literal is longer than [`MAX_LITERAL`], or would push its
    /// command past [`MAX_MESSAGE`].
    LiteralTooLarge {
        /// The tag at the start of the command, if there is one.
        tag: Option<String>,
        /// The size the literal announced.
        size: u64,
        /// Whether the sender waits for a continuation request before it
        /// sends the bytes. If so, the decoder drops the command and the
        /// stream goes on: the server answers `tag NO` or `tag BAD`, and
        /// the client never sends them. If not, the stream is broken.
        waiting: bool,
    },
    /// A command or response holds more than [`MAX_TEXT`] bytes outside
    /// its literals, or more than [`MAX_MESSAGE`] in all. The stream is
    /// broken.
    TooLong,
    /// Line framing or assembly failed while reading one value.
    Framing(FrameError),
    /// No complete value was present.
    Incomplete,
    /// Bytes follow the value.
    Trailing,
    /// The value cannot fit its wire grammar and limits without changing.
    Unwritable,
}

impl Error {
    /// The tag of the command the error is about, if known.
    pub fn tag(&self) -> Option<&str> {
        match self {
            Error::Syntax { tag, .. } | Error::LiteralTooLarge { tag, .. } => tag.as_deref(),
            Error::TooLong
            | Error::Framing(_)
            | Error::Incomplete
            | Error::Trailing
            | Error::Unwritable => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Syntax { reason, .. } => write!(f, "IMAP syntax error: {reason}"),
            Error::LiteralTooLarge { size, .. } => write!(f, "literal of {size} bytes is too large"),
            Error::TooLong => write!(f, "IMAP command or response is too long"),
            Error::Framing(_) => f.write_str("IMAP framing failed"),
            Error::Incomplete => f.write_str("incomplete IMAP value"),
            Error::Trailing => f.write_str("bytes after IMAP value"),
            Error::Unwritable => f.write_str("IMAP value cannot be written without changing it"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Framing(e) => Some(e),
            _ => None,
        }
    }
}

/// One command, literal continuation, or raw line from [`Inputs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// A whole command.
    Command(Command),
    /// The client sent `{size}` and waits for a continuation request.
    /// Send one, such as [`Response::continue_req`], and read the next item,
    /// or call [`Inputs::refuse_literal`] and answer `tag NO`.
    /// Every line ending in `{size}` requests a continuation, even if its
    /// start breaks the grammar; the whole command then yields [`Error::Syntax`].
    Continue {
        /// The command tag, if well-formed. Continuations share one copy.
        tag: Option<Arc<str>>,
        /// The literal's size, at most [`MAX_LITERAL`].
        size: usize,
    },
    /// A raw line without CRLF, selected by [`Inputs::expect_line`].
    Line(Vec<u8>),
}

/// What a response's first line says it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Continue,
    Status,
    Data,
}

/// Sorts a response by its first line, without the line ending.
fn classify(line: &[u8]) -> Kind {
    if line.first() == Some(&b'+') {
        return Kind::Continue;
    }
    let n = if line.first() == Some(&b'*') { 1 } else { line.iter().take_while(|&&x| tag_char(x)).count() };
    if n == 0 || line.get(n) != Some(&b' ') {
        return Kind::Data;
    }
    let rest = &line[n + 1..];
    let w = rest.iter().position(|&x| x == b' ').unwrap_or(rest.len());
    if Status::from_word(&rest[..w]).is_some() { Kind::Status } else { Kind::Data }
}

/// A line without its LF, and without a CR before it.
fn content(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// The literal a line announces at its end: `{n}` or `{n+}`, then CRLF.
/// A size too large for a `u64` reads as `u64::MAX`.
fn marker(line: &[u8], allow_non_sync: bool) -> Option<(u64, bool)> {
    let s = line.strip_suffix(b"\r\n")?.strip_suffix(b"}")?;
    let (s, non_sync) = match s.strip_suffix(b"+") {
        Some(s) if allow_non_sync => (s, true),
        Some(_) => return None,
        None => (s, false),
    };
    let digits = s.iter().rev().take_while(|b| b.is_ascii_digit()).count();
    let open = s.len().checked_sub(digits + 1)?;
    if digits == 0 || s[open] != b'{' {
        return None;
    }
    Some((number(&s[s.len() - digits..]), non_sync))
}

/// The value of ASCII digits, or `u64::MAX` if it does not fit.
fn number(digits: &[u8]) -> u64 {
    digits
        .iter()
        .fold(0u64, |n, &d| n.checked_mul(10).and_then(|n| n.checked_add(u64::from(d - b'0'))).unwrap_or(u64::MAX))
}

/// A byte an atom may hold (RFC 9051 `ATOM-CHAR`).
fn atom_char(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && !matches!(b, b'(' | b')' | b'{' | b'%' | b'*' | b'"' | b'\\' | b']')
}

/// A byte a tag may hold: `ASTRING-CHAR` except `+`.
fn tag_char(b: u8) -> bool {
    (atom_char(b) || b == b']') && b != b'+'
}

/// A byte an argument word may hold outside a section. It is wider than
/// `ATOM-CHAR`, to take flags, sequence sets and list patterns.
fn word_char(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && !matches!(b, b'(' | b')' | b'{' | b'"')
}

/// The words a section in square brackets follows (RFC 9051 `fetch-att`
/// and `msg-att-static`).
const SECTIONED: &[&[u8]] = &[b"BODY", b"BODY.PEEK", b"BINARY", b"BINARY.PEEK", b"BINARY.SIZE"];

/// Reads the word at the cursor. After one of [`SECTIONED`], a `[` opens
/// a section that runs to its `]` and may hold spaces, parentheses,
/// quoted strings and, when `literals` is `Some`, literals, which go into
/// the word as quoted strings. `Some(true)` takes non-synchronizing ones
/// too. With `None` a literal is an error, so a word that reads back the
/// same is one a writer may send as an atom.
fn scan_word(c: &mut Cursor<'_>, literals: Option<bool>) -> Result<String, Fault> {
    let start = c.i;
    let mut out = String::new();
    while let Some(x) = c.peek() {
        if x == b'[' && SECTIONED.iter().any(|w| c.b[start..c.i].eq_ignore_ascii_case(w)) {
            c.i += 1;
            out.push('[');
            scan_section(c, &mut out, literals)?;
            out.push(']');
        } else if word_char(x) {
            c.i += 1;
            out.push(char::from(x));
        } else {
            break;
        }
    }
    Ok(out)
}

/// Reads a section after its `[`, through its `]`, into `out`.
fn scan_section(c: &mut Cursor<'_>, out: &mut String, literals: Option<bool>) -> Result<(), Fault> {
    loop {
        match c.peek() {
            Some(b']') => {
                c.i += 1;
                return Ok(());
            }
            Some(b'"') => push_quoted(out, &parse_quoted(c)?),
            Some(b'{') if literals.is_some() => {
                let (data, _) = parse_literal(c, literals == Some(true), false)?;
                let quotable = data.len() <= MAX_QUOTED && !data.iter().any(|&b| matches!(b, b'\r' | b'\n'));
                if !quotable || std::str::from_utf8(&data).is_err() {
                    return Err(Fault::Syntax("a literal in a section must be a short line of UTF-8"));
                }
                push_quoted(out, &data);
            }
            Some(x) if (0x20..=0x7e).contains(&x) && x != b'{' => {
                c.i += 1;
                out.push(char::from(x));
            }
            _ => return Err(Fault::Syntax("an atom has [ without ]")),
        }
    }
}

/// Adds `"s"` to `out`, with `"` and `\` escaped. `s` is UTF-8.
fn push_quoted(out: &mut String, s: &[u8]) {
    out.push('"');
    for ch in String::from_utf8_lossy(s).chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
}

/// Whether `s` is written as an atom.
fn atom_ok(s: &[u8]) -> bool {
    let mut c = Cursor { b: s, i: 0, lits: 0 };
    !s.is_empty() && matches!(scan_word(&mut c, None), Ok(w) if c.i == s.len() && w.as_bytes() == s)
}

/// The well-formed tag at the start of `b`, if it has one.
fn tag_of(b: &[u8]) -> Option<String> {
    let n = b.iter().take(MAX_TEXT).take_while(|&&x| tag_char(x)).count();
    (n > 0 && b.get(n) == Some(&b' ')).then(|| ascii(&b[..n]))
}

fn ascii(b: &[u8]) -> String {
    b.iter().map(|&x| char::from(x)).collect()
}

/// Text from a response line: no NUL, CR or LF, and UTF-8.
fn text_str(b: &[u8]) -> Result<&str, &'static str> {
    if b.iter().any(|&x| matches!(x, 0 | b'\r' | b'\n')) {
        return Err("text holds NUL, CR or LF");
    }
    std::str::from_utf8(b).map_err(|_| "text is not UTF-8")
}

/// The code and text after a status word and its space.
fn resp_text(rest: &[u8]) -> Result<(Option<String>, String), &'static str> {
    if rest.first() == Some(&b'[')
        && let Some(close) = rest.iter().position(|&x| x == b']')
    {
        let after = &rest[close + 1..];
        if close > 1 && (after.is_empty() || after[0] == b' ') {
            let code = text_str(&rest[1..close])?;
            let text = text_str(after.get(1..).unwrap_or(&[]))?;
            return Ok((Some(code.to_string()), text.to_string()));
        }
    }
    Ok((None, text_str(rest)?.to_string()))
}

/// What went wrong inside a command or response.
enum Fault {
    Syntax(&'static str),
    TooLarge { size: u64, non_sync: bool },
}

impl Fault {
    fn into_error(self, tag: Option<String>) -> Error {
        match self {
            Fault::Syntax(reason) => Error::Syntax { tag, reason },
            Fault::TooLarge { size, non_sync } => Error::LiteralTooLarge { tag, size, waiting: !non_sync },
        }
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
    /// Bytes of the literals read so far.
    lits: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn take_while(&mut self, f: fn(u8) -> bool) -> &'a [u8] {
        let b: &'a [u8] = self.b;
        let start = self.i.min(b.len());
        let n = b[start..].iter().take_while(|&&x| f(x)).count();
        self.i = start + n;
        &b[start..start + n]
    }

    /// Whether only the final CRLF is left.
    fn at_end(&self) -> bool {
        self.b.get(self.i..) == Some(b"\r\n")
    }
}

/// Reads `*(SP value)` and the final CRLF, which must end the bytes.
/// Lists are read with a stack, not by recursion. A command is read with
/// `client` set: it may hold non-synchronizing literals. In a response a
/// list may follow a list with no space between them, as the parts of a
/// multipart body and the addresses of an envelope do.
fn parse_values(c: &mut Cursor<'_>, client: bool) -> Result<Vec<Value>, Fault> {
    let mut levels: Vec<Vec<Value>> = vec![Vec::new()];
    loop {
        let after_list = matches!(levels.last().and_then(|l| l.last()), Some(Value::List(_)));
        let adjacent = !client && after_list && c.peek() == Some(b'(');
        if levels.len() == 1 {
            if c.at_end() {
                c.i += 2;
                break;
            }
            if !adjacent {
                if c.peek() != Some(b' ') {
                    return Err(Fault::Syntax("expected a space or the end of the line"));
                }
                c.i += 1;
            }
        } else {
            if c.peek() == Some(b')') {
                c.i += 1;
                let list = levels.pop().unwrap_or_default();
                if let Some(parent) = levels.last_mut() {
                    parent.push(Value::List(list));
                }
                continue;
            }
            if levels.last().is_some_and(|l| !l.is_empty()) && !adjacent {
                if c.peek() != Some(b' ') {
                    return Err(Fault::Syntax("expected a space or ) in a list"));
                }
                c.i += 1;
            }
        }
        let v = match c.peek() {
            Some(b'(') => {
                if levels.len() > MAX_DEPTH {
                    return Err(Fault::Syntax("lists nest too deeply"));
                }
                c.i += 1;
                levels.push(Vec::new());
                continue;
            }
            Some(b'"') => Value::Quoted(parse_quoted(c)?),
            Some(b'{') => {
                let (data, non_sync) = parse_literal(c, client, false)?;
                Value::Literal { data, non_sync }
            }
            Some(b'~') if c.b.get(c.i + 1) == Some(&b'{') => {
                c.i += 1;
                let (data, non_sync) = parse_literal(c, client, true)?;
                Value::Binary { data, non_sync }
            }
            _ => {
                let w = scan_word(c, Some(client))?;
                if w.is_empty() {
                    return Err(Fault::Syntax("expected a value"));
                }
                Value::Atom(w)
            }
        };
        if let Some(l) = levels.last_mut() {
            l.push(v);
        }
    }
    Ok(levels.pop().unwrap_or_default())
}

fn parse_quoted(c: &mut Cursor<'_>) -> Result<Vec<u8>, Fault> {
    c.i += 1;
    let mut out = Vec::new();
    loop {
        let Some(x) = c.peek() else { return Err(Fault::Syntax("a quoted string has no closing quote")) };
        c.i += 1;
        match x {
            b'"' if std::str::from_utf8(&out).is_err() => {
                return Err(Fault::Syntax("a quoted string is not UTF-8"));
            }
            b'"' => return Ok(out),
            b'\\' => match c.peek() {
                Some(e @ (b'"' | b'\\')) => {
                    out.push(e);
                    c.i += 1;
                }
                _ => return Err(Fault::Syntax("only \\\" and \\\\ may be escaped")),
            },
            0 | b'\r' | b'\n' => return Err(Fault::Syntax("a quoted string holds NUL, CR or LF")),
            _ => out.push(x),
        }
        if out.len() > MAX_QUOTED {
            return Err(Fault::Syntax("a quoted string is too long"));
        }
    }
}

/// Reads a literal from its `{`: its bytes, and whether it was
/// non-synchronizing. Only a `binary` one, after `~`, may hold NUL.
fn parse_literal(c: &mut Cursor<'_>, allow_non_sync: bool, binary: bool) -> Result<(Vec<u8>, bool), Fault> {
    c.i += 1;
    let digits = c.take_while(|b| b.is_ascii_digit());
    if digits.is_empty() {
        return Err(Fault::Syntax("a literal's size must follow {"));
    }
    let size = number(digits);
    let non_sync = c.peek() == Some(b'+');
    if non_sync {
        if !allow_non_sync {
            return Err(Fault::Syntax("a server literal cannot be non-synchronizing"));
        }
        c.i += 1;
    }
    if c.b.get(c.i..).is_none_or(|r| !r.starts_with(b"}\r\n")) {
        return Err(Fault::Syntax("a literal's size must end with } and CRLF"));
    }
    c.i += 3;
    if size > MAX_LITERAL as u64 {
        return Err(Fault::TooLarge { size, non_sync });
    }
    let n = size as usize;
    let data = c.b.get(c.i..c.i.saturating_add(n)).ok_or(Fault::Syntax("a literal is cut short"))?;
    if !binary && data.contains(&0) {
        return Err(Fault::Syntax("a literal holds NUL"));
    }
    c.i += n;
    c.lits += n;
    Ok((data.to_vec(), non_sync))
}

/// The longest non-synchronizing literal a client sends, unless the
/// server says it takes longer ones (RFC 9051, section 4.3).
/// [`Inputs`] enforces this limit without enabling the LITERAL+ extension.
pub const MAX_NON_SYNC: usize = 4096;

/// Local maximum line size, including CRLF, for the shared decoders.
/// RFC 9051 defines no universal line maximum. The aggregate text limit
/// [`MAX_TEXT`] also applies across all lines of one message.
pub const MAX_LINE: usize = MAX_TEXT;
/// Maximum assembled bytes and cached tag bytes in a shared decoder.
pub const MAX_HELD: usize = MAX_MESSAGE + MAX_LINE;

/// Why [`Inputs`] or [`Responses`] cannot continue. It ends the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A line exceeded its limit, ended early, or broke literal framing.
    Line(codec::LineError),
    /// A command or response held more than [`MAX_TEXT`] bytes outside
    /// its literals, or more than [`MAX_MESSAGE`] in all.
    TooLong,
    /// A literal the sender does not wait to send is longer than
    /// [`MAX_NON_SYNC`] or [`MAX_LITERAL`], or would push its command or
    /// response past [`MAX_MESSAGE`].
    LiteralTooLarge {
        /// The tag at the start of the command, if there is one.
        tag: Option<String>,
        /// The size the literal announced.
        size: u64,
    },
    /// Storage for a bounded message could not be allocated.
    Allocation,
    /// EOF interrupted a literal or the command or response containing it.
    Incomplete,
    /// A raw line was requested while a command or literal was in progress.
    State,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Line(_) => f.write_str("IMAP line framing failed"),
            Self::TooLong => f.write_str("IMAP command or response is too long"),
            Self::LiteralTooLarge { size, .. } => write!(f, "literal of {size} bytes is too large"),
            Self::Allocation => f.write_str("IMAP assembly allocation failed"),
            Self::Incomplete => f.write_str("incomplete IMAP literal or message"),
            Self::State => f.write_str("IMAP raw line requires a command boundary"),
        }
    }
}
impl core::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Line(e) => Some(e),
            _ => None,
        }
    }
}

impl Wire for Command {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one whole command with counted literals and final CRLF.
    /// Refuses trailing bytes, invalid grammar, non-synchronizing literals
    /// over [`MAX_NON_SYNC`], and text, literal, message, or nesting overflow.
    /// A section literal must fit its canonical quoted form.
    fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        let mut commands = Inputs::new();
        loop {
            match commands.decode(bytes, true).map_err(Error::Framing)? {
                codec::Step::Item(Ok(Input::Continue { .. }), used) | codec::Step::Skip(used) => {
                    bytes = bytes.get(used..).ok_or(Error::Incomplete)?;
                }
                codec::Step::Item(command, used) => {
                    let command = command?;
                    if used != bytes.len() {
                        return Err(Error::Trailing);
                    }
                    return match command {
                        Input::Command(command) => Ok(command),
                        Input::Continue { .. } | Input::Line(_) => Err(Error::Incomplete),
                    };
                }
                _ => return Err(Error::Incomplete),
            }
        }
    }

    /// Appends a complete command. Refuses invalid tags, names, values,
    /// normalization, and all text, literal, message, or nesting overflows.
    /// Errors leave `out` unchanged. Use [`Self::continuation_offsets`] on
    /// the encoded bytes to wait before synchronizing literal payloads.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut writer = Writer::new(false);
        writer.token(&self.tag, tag_char)?;
        writer.text(b" ")?;
        writer.token(&self.name, atom_char)?;
        if self.name.bytes().any(|b| b.is_ascii_lowercase()) {
            return Err(Error::Unwritable);
        }
        writer.args(&self.args)?;
        writer.text(b"\r\n")?;
        if Self::parse_message(&writer.out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        out.try_reserve(writer.out.len())
            .map_err(|_| Error::Unwritable)?;
        out.extend_from_slice(&writer.out);
        Ok(())
    }
}

impl Wire for Response {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one whole response with CRLF framing and counted literal bytes.
    /// Refuses trailing bytes, invalid grammar, non-synchronizing literals,
    /// and text, literal, message, or nesting overflow. A section literal
    /// must fit its canonical quoted form.
    fn parse(mut bytes: &[u8]) -> Result<Self, Error> {
        let mut responses = Responses::new();
        loop {
            match responses.decode(bytes, true).map_err(Error::Framing)? {
                codec::Step::Item(response, used) => {
                    let response = response?;
                    if used != bytes.len() {
                        return Err(Error::Trailing);
                    }
                    return Ok(response);
                }
                codec::Step::Skip(used) => {
                    bytes = bytes.get(used..).ok_or(Error::Incomplete)?
                }
                _ => return Err(Error::Incomplete),
            }
        }
    }

    /// Appends one response. Refuses invalid tags, codes, text, values,
    /// tagged BYE or PREAUTH, non-synchronizing literals, normalization,
    /// and all size or nesting overflows. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut writer = Writer::new(true);
        match self {
            Self::Continue { text } => {
                writer.text(b"+ ")?;
                writer.response_text(text)?;
            }
            Self::Status {
                tag,
                status,
                code,
                text,
            } => {
                if let Some(tag) = tag {
                    if matches!(status, Status::Preauth | Status::Bye) {
                        return Err(Error::Unwritable);
                    }
                    writer.token(tag, tag_char)?;
                } else {
                    writer.text(b"*")?;
                }
                writer.text(b" ")?;
                writer.text(status.as_str().as_bytes())?;
                // Keep the longest accepted empty status line writable.
                if writer.out.len() < MAX_TEXT - 2 {
                    writer.text(b" ")?;
                }
                if let Some(code) = code {
                    if code.is_empty() || code.len() > MAX_TEXT || code.contains(']') {
                        return Err(Error::Unwritable);
                    }
                    writer.text(b"[")?;
                    writer.response_text(code)?;
                    writer.text(b"] ")?;
                }
                writer.response_text(text)?;
            }
            Self::Data(values) => {
                if matches!(values.first(), Some(Value::Atom(a)) if Status::from_word(a.as_bytes()).is_some())
                {
                    return Err(Error::Unwritable);
                }
                writer.text(b"*")?;
                writer.args(values)?;
            }
        }
        writer.text(b"\r\n")?;
        if Self::parse_message(&writer.out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        out.try_reserve(writer.out.len())
            .map_err(|_| Error::Unwritable)?;
        out.extend_from_slice(&writer.out);
        Ok(())
    }
}

// One bounded serializer for command arguments and response data.
struct Writer {
    out: Vec<u8>,
    text: usize,
    server: bool,
}

impl Writer {
    fn new(server: bool) -> Self {
        Self {
            out: Vec::new(),
            text: 0,
            server,
        }
    }

    fn append(&mut self, bytes: &[u8], literal: bool) -> Result<(), Error> {
        let total = self
            .out
            .len()
            .checked_add(bytes.len())
            .filter(|&n| n <= MAX_MESSAGE)
            .ok_or(Error::Unwritable)?;
        if !literal {
            self.text = self
                .text
                .checked_add(bytes.len())
                .filter(|&n| n <= MAX_TEXT)
                .ok_or(Error::Unwritable)?;
        }
        if total > self.out.capacity() {
            let target = total
                .max(self.out.capacity().saturating_mul(2))
                .min(MAX_MESSAGE);
            self.out
                .try_reserve_exact(target.saturating_sub(self.out.len()))
                .map_err(|_| Error::Unwritable)?;
        }
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    fn text(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.append(bytes, false)
    }

    fn token(&mut self, value: &str, allowed: fn(u8) -> bool) -> Result<(), Error> {
        if value.is_empty() || value.len() > MAX_TEXT || !value.bytes().all(allowed) {
            return Err(Error::Unwritable);
        }
        self.text(value.as_bytes())
    }

    fn response_text(&mut self, value: &str) -> Result<(), Error> {
        if value.len() > MAX_TEXT || text_str(value.as_bytes()).is_err() {
            return Err(Error::Unwritable);
        }
        self.text(value.as_bytes())
    }

    fn args(&mut self, values: &[Value]) -> Result<(), Error> {
        for value in values {
            self.text(b" ")?;
            self.value(value)?;
        }
        Ok(())
    }

    fn value(&mut self, value: &Value) -> Result<(), Error> {
        let mut stack: Vec<(std::slice::Iter<'_, Value>, bool, bool)> = Vec::new();
        let mut next = Some(value);
        loop {
            if let Some(value) = next.take() {
                match value {
                    Value::List(items) => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(Error::Unwritable);
                        }
                        self.text(b"(")?;
                        stack.push((items.iter(), true, true));
                    }
                    Value::Atom(atom) => {
                        if atom.len() > MAX_TEXT || !atom_ok(atom.as_bytes()) {
                            return Err(Error::Unwritable);
                        }
                        self.text(atom.as_bytes())?;
                    }
                    Value::Quoted(bytes) => {
                        if bytes.len() > MAX_QUOTED || text_str(bytes).is_err() {
                            return Err(Error::Unwritable);
                        }
                        self.text(b"\"")?;
                        for byte in bytes {
                            if matches!(byte, b'"' | b'\\') {
                                self.text(b"\\")?;
                            }
                            self.text(std::slice::from_ref(byte))?;
                        }
                        self.text(b"\"")?;
                    }
                    Value::Literal { data, non_sync } => self.literal(data, *non_sync, false)?,
                    Value::Binary { data, non_sync } => self.literal(data, *non_sync, true)?,
                }
            }
            let Some((iter, first, run)) = stack.last_mut() else {
                return Ok(());
            };
            match iter.next() {
                Some(item) => {
                    let open = matches!(item, Value::List(_));
                    let space = !(*first || (self.server && *run && open));
                    *first = false;
                    *run &= open;
                    next = Some(item);
                    if space {
                        self.text(b" ")?;
                    }
                }
                None => {
                    stack.pop();
                    self.text(b")")?;
                }
            }
        }
    }

    fn literal(&mut self, data: &[u8], non_sync: bool, binary: bool) -> Result<(), Error> {
        if data.len() > MAX_LITERAL
            || (non_sync && (self.server || data.len() > MAX_NON_SYNC))
            || (!binary && data.contains(&0))
        {
            return Err(Error::Unwritable);
        }
        if binary {
            self.text(b"~")?;
        }
        self.text(b"{")?;
        self.text(data.len().to_string().as_bytes())?;
        if non_sync {
            self.text(b"+")?;
        }
        self.text(b"}\r\n")?;
        self.append(data, true)
    }
}

// A parsed value must also fit after canonical re-encoding. In particular,
// a literal inside a section becomes quoted text in an Atom and may expand.
fn codec_command(bytes: &[u8]) -> Result<Command, Error> {
    let command = Command::parse_message(bytes)?;
    if command.write(&mut Vec::new()).is_err() {
        return Err(Error::Syntax {
            tag: Some(command.tag),
            reason: "command cannot be written unchanged",
        });
    }
    Ok(command)
}

fn codec_response(bytes: &[u8]) -> Result<Response, Error> {
    let response = Response::parse_message(bytes)?;
    if response.write(&mut Vec::new()).is_err() {
        return Err(Error::Syntax {
            tag: None,
            reason: "response cannot be written unchanged",
        });
    }
    Ok(response)
}

enum MailFrame {
    Continue { tag: Option<Arc<str>>, size: usize },
    Message(Vec<u8>),
}

// Lines own only the scan cursor. Counted literal bytes bypass Lines and
// enter this bounded assembly only when a Skip consumes them.
struct MessageLines {
    lines: codec::Lines,
    message: Vec<u8>,
    text: usize,
    remaining: usize,
    response: bool,
    partial: bool,
    kind: Option<Kind>,
    tag: Option<Arc<str>>,
    waiting: bool,
}

impl MessageLines {
    fn new(response: bool) -> Self {
        Self {
            lines: codec::Lines::new(MAX_LINE - 2, codec::Ending::Crlf),
            message: Vec::new(),
            text: 0,
            remaining: 0,
            response,
            partial: false,
            kind: None,
            tag: None,
            waiting: false,
        }
    }

    fn reset(&mut self) {
        self.lines = codec::Lines::new(MAX_LINE - 2, codec::Ending::Crlf);
        self.message = Vec::new();
        self.text = 0;
        self.remaining = 0;
        self.partial = false;
        self.kind = None;
        self.tag = None;
        self.waiting = false;
    }

    fn held(&self) -> usize {
        self.message
            .len()
            .saturating_add(self.tag.as_ref().map_or(0, |tag| tag.len()))
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        let size = self
            .message
            .len()
            .checked_add(bytes.len())
            .filter(|&n| n <= MAX_MESSAGE)
            .ok_or(FrameError::TooLong)?;
        if size > self.message.capacity() {
            let target = size
                .max(self.message.capacity().saturating_mul(2))
                .min(MAX_MESSAGE);
            self.message
                .try_reserve_exact(target.saturating_sub(self.message.len()))
                .map_err(|_| FrameError::Allocation)?;
        }
        self.message.extend_from_slice(bytes);
        Ok(())
    }

    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
    ) -> Result<codec::Step<Result<MailFrame, Error>>, FrameError> {
        if self.remaining != 0 {
            if input.is_empty() {
                return if eof {
                    Err(FrameError::Incomplete)
                } else {
                    Ok(codec::Step::Need)
                };
            }
            let used = self.remaining.min(input.len());
            let part = input.get(..used).unwrap_or_default();
            self.append(part)?;
            self.remaining = self.remaining.saturating_sub(used);
            self.waiting = false;
            return Ok(codec::Step::Skip(used));
        }
        let step = match self.lines.decode(input, eof) {
            Ok(step) => step,
            Err(never) => match never {},
        };
        let (mut line, used) = match step {
            codec::Step::Item(Ok(line), used) => (line, used),
            codec::Step::Item(Err(codec::LineError::BareLf), used) => {
                let mut candidate = input
                    .get(..used)
                    .unwrap_or_default()
                    .strip_suffix(b"\n")
                    .unwrap_or_default()
                    .to_vec();
                candidate.extend_from_slice(b"\r\n");
                let literals = !self.response
                    || self.kind.unwrap_or_else(|| classify(content(&candidate))) == Kind::Data;
                if literals && marker(&candidate, !self.response).is_some() {
                    return Err(FrameError::Line(codec::LineError::BareLf));
                }
                let error = Error::Syntax {
                    tag: self
                        .tag
                        .as_deref()
                        .map(String::from)
                        .or_else(|| tag_of(&candidate)),
                    reason: "a line must end with CRLF",
                };
                self.reset();
                return Ok(codec::Step::Item(Err(error), used));
            }
            codec::Step::Item(Err(e), _) => return Err(FrameError::Line(e)),
            codec::Step::Need if eof && !self.message.is_empty() => {
                return Err(FrameError::Incomplete);
            }
            codec::Step::Need => {
                self.partial = !input.is_empty();
                return Ok(codec::Step::Need);
            }
            codec::Step::Skip(used) => return Ok(codec::Step::Skip(used)),
            codec::Step::End => return Ok(codec::Step::End),
        };
        self.partial = false;
        self.waiting = false;
        if self.message.is_empty() {
            self.kind = Some(classify(&line));
            self.tag = tag_of(&line).map(Arc::from);
        }
        line.extend_from_slice(b"\r\n");
        self.text = self
            .text
            .checked_add(line.len())
            .filter(|&n| n <= MAX_TEXT)
            .ok_or(FrameError::TooLong)?;
        let end = self
            .message
            .len()
            .checked_add(line.len())
            .filter(|&n| n <= MAX_MESSAGE)
            .ok_or(FrameError::TooLong)?;
        let literal = (!self.response || self.kind == Some(Kind::Data))
            .then(|| marker(&line, !self.response))
            .flatten();
        if let Some((size, non_sync)) = literal {
            let limit = if non_sync { MAX_NON_SYNC } else { MAX_LITERAL };
            let count = usize::try_from(size)
                .ok()
                .filter(|&n| n <= limit)
                .filter(|&n| end.checked_add(n).is_some_and(|total| total <= MAX_MESSAGE));
            let Some(count) = count else {
                let tag = self.tag.as_deref().map(String::from);
                if !self.response && !non_sync {
                    self.reset();
                    let error = Error::LiteralTooLarge { tag, size, waiting: true };
                    return Ok(codec::Step::Item(Err(error), used));
                }
                return Err(FrameError::LiteralTooLarge { tag, size });
            };
            self.append(&line)?;
            self.remaining = count;
            if !self.response && !non_sync {
                self.waiting = true;
                return Ok(codec::Step::Item(
                    Ok(MailFrame::Continue {
                        tag: self.tag.clone(),
                        size: count,
                    }),
                    used,
                ));
            }
            return Ok(codec::Step::Skip(used));
        }
        self.append(&line)?;
        let message = core::mem::take(&mut self.message);
        self.reset();
        Ok(codec::Step::Item(Ok(MailFrame::Message(message)), used))
    }
}

/// Reads commands and literal continuation events over [`codec::Lines`].
///
/// CRLF is required outside literals. Lines are bounded by [`MAX_LINE`],
/// aggregate text by [`MAX_TEXT`], each literal by [`MAX_LITERAL`], and
/// the assembly by [`MAX_MESSAGE`]. Non-synchronizing literals also obey
/// [`MAX_NON_SYNC`]. Literal bytes may contain CRLF and bypass Lines.
/// Retained state is bounded by [`MAX_HELD`]. Bytewise input takes linear time.
///
/// Syntax failures at known message boundaries are error items. An oversized
/// synchronizing literal is also an item: the client is still waiting, so
/// the world can refuse it. Line overflow, oversized non-synchronizing
/// literals, and EOF during an assembly end the stream. After a continuation
/// event, send the continuation and read on, or call
/// [`refuse_literal`](Self::refuse_literal) between items.
/// For AUTHENTICATE answers and IDLE's `DONE`, call
/// [`expect_line`](Self::expect_line) between items. It returns one
/// [`Input::Line`] under the same [`MAX_LINE`] limit, then resumes commands.
///
/// ```
/// use fictionet::stdlib::{codec::Stream, imap::{Inputs, Input}};
/// let mut stream = Stream::new(Inputs::new());
/// let bytes = b"a LOGIN user {3}\r\nabc\r\n";
/// assert_eq!(stream.push(bytes), bytes.len());
/// assert!(matches!(stream.next(), Some(Ok(Ok(Input::Continue { size: 3, .. })))));
/// assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(_))))));
/// ```
pub struct Inputs {
    framing: MessageLines,
    raw_line: bool,
}

impl Default for Inputs {
    fn default() -> Self {
        Self::new()
    }
}

impl Inputs {
    /// Creates a command decoder with no pending literal.
    pub fn new() -> Self {
        Self {
            framing: MessageLines::new(false),
            raw_line: false,
        }
    }

    /// Selects one raw AUTHENTICATE answer or IDLE `DONE` line.
    /// Call between items. Refuses a partial command, a pending literal, or
    /// an already selected raw line without changing the mode. Literal-looking
    /// text in this line is returned unchanged, without a continuation event.
    pub fn expect_line(&mut self) -> Result<(), FrameError> {
        if self.raw_line
            || self.framing.partial
            || !self.framing.message.is_empty()
            || self.framing.waiting
            || self.framing.remaining != 0
        {
            return Err(FrameError::State);
        }
        self.raw_line = true;
        Ok(())
    }

    /// Drops the command at its synchronizing literal boundary.
    /// Returns false unless the last continuation is still waiting.
    /// Unread bytes remain in the stream and will be read as commands.
    pub fn refuse_literal(&mut self) -> bool {
        if !self.framing.waiting {
            return false;
        }
        self.framing.reset();
        true
    }
}

impl Decode for Inputs {
    type Item = Result<Input, Error>;
    type Error = FrameError;
    const NAME: &'static str = "IMAP commands";

    fn capacity(&self) -> usize {
        MAX_LINE
    }

    fn held(&self) -> usize {
        self.framing.held()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<codec::Step<Self::Item>, FrameError> {
        if self.raw_line {
            let step = match self.framing.lines.decode(input, eof) {
                Ok(step) => step,
                Err(never) => match never {},
            };
            return Ok(match step {
                codec::Step::Item(line, used) => {
                    self.raw_line = false;
                    self.framing.reset();
                    let line = match line {
                        Ok(line) => Ok(Input::Line(line)),
                        Err(codec::LineError::BareLf) => Err(Error::Syntax {
                            tag: None,
                            reason: "a line must end with CRLF",
                        }),
                        Err(e) => return Err(FrameError::Line(e)),
                    };
                    codec::Step::Item(line, used)
                }
                codec::Step::Need => {
                    self.framing.partial = !input.is_empty();
                    codec::Step::Need
                }
                codec::Step::Skip(used) => codec::Step::Skip(used),
                codec::Step::End => codec::Step::End,
            });
        }
        Ok(match self.framing.decode(input, eof)? {
            codec::Step::Item(frame, used) => codec::Step::Item(
                frame.and_then(|frame| match frame {
                    MailFrame::Continue { tag, size } => Ok(Input::Continue { tag, size }),
                    MailFrame::Message(bytes) => codec_command(&bytes).map(Input::Command),
                }),
                used,
            ),
            codec::Step::Skip(used) => codec::Step::Skip(used),
            codec::Step::Need => codec::Step::Need,
            codec::Step::End => codec::Step::End,
        })
    }
}

/// Reads responses over CRLF lines and counted literals.
///
/// Uses the same line, literal, assembly, and retained-state limits as
/// [`Inputs`]. Server literals must use `{n}`, never `{n+}`, and do not
/// generate continuation events. A data response ending in `{n+}` is a
/// syntax error item; the following line remains a separate response.
/// A status or continuation response ending in `{n}` is ordinary text.
/// Malformed complete responses are error items. Line overflow, oversized
/// literals, and incomplete assemblies end the stream.
pub struct Responses {
    framing: MessageLines,
}

impl Default for Responses {
    fn default() -> Self {
        Self::new()
    }
}

impl Responses {
    /// Creates a response decoder with no pending literal.
    pub fn new() -> Self {
        Self {
            framing: MessageLines::new(true),
        }
    }
}

impl Decode for Responses {
    type Item = Result<Response, Error>;
    type Error = FrameError;
    const NAME: &'static str = "IMAP responses";

    fn capacity(&self) -> usize {
        MAX_LINE
    }

    fn held(&self) -> usize {
        self.framing.held()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<codec::Step<Self::Item>, FrameError> {
        Ok(match self.framing.decode(input, eof)? {
            codec::Step::Item(frame, used) => codec::Step::Item(
                frame.and_then(|frame| match frame {
                    MailFrame::Message(bytes) => codec_response(&bytes),
                    MailFrame::Continue { .. } => Err(Error::Syntax {
                        tag: None,
                        reason: "unexpected continuation event",
                    }),
                }),
                used,
            ),
            codec::Step::Skip(used) => codec::Step::Skip(used),
            codec::Step::Need => codec::Step::Need,
            codec::Step::End => codec::Step::End,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{
        Fail, Lcg, Step, Stream,
    };
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn cmd(bytes: &[u8]) -> Command {
        Command::parse(bytes).unwrap()
    }
    fn atoms(values: &[&str]) -> Vec<Value> {
        values.iter().map(|s| Value::atom(s)).collect()
    }
    fn syntax(bytes: &[u8]) -> bool {
        Command::parse(bytes).is_err()
    }
    fn events(bytes: &[u8]) -> Vec<Result<Input, Error>> {
        let (items, failure) = decode_all(Inputs::new, bytes);
        assert_eq!(failure, None);
        items
    }
    fn responses(bytes: &[u8]) -> Vec<Result<Response, Error>> {
        let (items, failure) = decode_all(Responses::new, bytes);
        assert_eq!(failure, None);
        items
    }
    #[test]
    fn rfc_commands() {
        let c = cmd(b"a001 login SMITH SESAME\r\n");
        assert_eq!(c, Command { tag: "a001".into(), name: "LOGIN".into(), args: atoms(&["SMITH", "SESAME"]) });
        assert!(c.is("Login"));
        assert_eq!(cmd(b"a002 NOOP\r\n").args, vec![]);
        let c = cmd(b"A142 SELECT INBOX\r\n");
        assert_eq!(c.args, atoms(&["INBOX"]));
        let c = cmd(b"A101 LIST \"\" \"\"\r\n");
        assert_eq!(c.args, vec![Value::Quoted(vec![]), Value::Quoted(vec![])]);
        let c = cmd(b"A682 LIST \"\" *\r\n");
        assert_eq!(c.args, vec![Value::Quoted(vec![]), Value::atom("*")]);
        let c = cmd(b"A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])\r\n");
        assert_eq!(c.args, vec![Value::atom("2:4"), Value::List(atoms(&["FLAGS", "BODY[HEADER.FIELDS (DATE FROM)]"]))]);
        let c = cmd(b"A003 STORE 2:4 +FLAGS (\\Deleted)\r\n");
        assert_eq!(c.args, vec![Value::atom("2:4"), Value::atom("+FLAGS"), Value::List(atoms(&["\\Deleted"]))]);
        let c = cmd(b"A999 UID FETCH 4827313:4828442 FLAGS\r\n");
        assert_eq!(c.name, "UID");
        assert_eq!(c.args, atoms(&["FETCH", "4827313:4828442", "FLAGS"]));
        assert_eq!(c.args[1].as_number(), None);
        let c = cmd(b"A003 APPEND saved-messages (\\Seen) {12}\r\nHello Joe!\r\n\r\n");
        assert_eq!(
            c.args,
            vec![
                Value::atom("saved-messages"),
                Value::List(atoms(&["\\Seen"])),
                Value::Literal { data: b"Hello Joe!\r\n".to_vec(), non_sync: false },
            ]
        );
        let c = cmd(b"a LOGIN {5+}\r\nalice \"p\\\"w\\\\\"\r\n");
        assert_eq!(
            c.args,
            vec![Value::Literal { data: b"alice".to_vec(), non_sync: true }, Value::Quoted(b"p\"w\\".to_vec())]
        );
        assert_eq!(c.args[1].as_str(), Some("p\"w\\"));
        let c = cmd(b"x SEARCH (OR 1 2) NIL () 42\r\n");
        assert!(c.args[1].is_nil());
        assert_eq!(c.args[2].as_list(), Some(&[][..]));
        assert_eq!(c.args[3].as_number(), Some(42));
        assert_eq!(c.args[0].as_list().map(|l| l.len()), Some(3));
    }

    #[test]
    fn rfc_responses() {
        let r = Response::parse(b"* OK IMAP4rev2 Service Ready\r\n").unwrap();
        assert_eq!(r, Response::greeting("IMAP4rev2 Service Ready"));
        assert_eq!(Response::parse(b"* 172 EXISTS\r\n").unwrap(), Response::exists(172));
        let r = Response::parse(b"* OK [UIDVALIDITY 3857529045] UIDs valid\r\n").unwrap();
        assert_eq!(r, Response::untagged(Status::Ok, "UIDs valid").with_code("UIDVALIDITY 3857529045"));
        let r = Response::parse(b"A142 ok [READ-WRITE] SELECT completed\r\n").unwrap();
        assert_eq!(r, Response::tagged("A142", Status::Ok, "SELECT completed").with_code("READ-WRITE"));
        let r = Response::parse(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n").unwrap();
        assert_eq!(r, Response::flags(&["\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft"]));
        let r = Response::parse(b"* LIST (\\Noselect) \"/\" \"\"\r\n").unwrap();
        assert_eq!(r, Response::list(&["\\Noselect"], Some('/'), b""));
        assert_eq!(Response::parse(b"* SEARCH 2 84 882\r\n").unwrap(), Response::search(&[2, 84, 882]));
        assert_eq!(
            Response::parse(b"* CAPABILITY IMAP4rev2 STARTTLS AUTH=GSSAPI\r\n").unwrap(),
            Response::capability(&["IMAP4rev2", "STARTTLS", "AUTH=GSSAPI"])
        );
        let r = Response::parse(b"+ Ready for additional command text\r\n").unwrap();
        assert_eq!(r, Response::continue_req("Ready for additional command text"));
        assert_eq!(Response::parse(b"+\r\n").unwrap(), Response::continue_req(""));
        assert_eq!(
            Response::parse(b"* BYE IMAP4rev2 Server logging out\r\n").unwrap(),
            Response::bye("IMAP4rev2 Server logging out")
        );
        let r = Response::parse(b"* 12 FETCH (FLAGS (\\Seen) BODY[HEADER] {13}\r\nSubject: hi\r\n)\r\n").unwrap();
        assert_eq!(
            r,
            Response::fetch(
                12,
                vec![
                    Value::atom("FLAGS"),
                    Value::List(atoms(&["\\Seen"])),
                    Value::atom("BODY[HEADER]"),
                    Value::Literal { data: b"Subject: hi\r\n".to_vec(), non_sync: false },
                ]
            )
        );
        // Codes are recognized only when a space or the end follows ].
        let r = Response::parse(b"a NO [x]y\r\n").unwrap();
        assert_eq!(r, Response::tagged("a", Status::No, "[x]y"));
        assert_eq!(Response::parse(b"a BAD\r\n").unwrap(), Response::tagged("a", Status::Bad, ""));
        assert_eq!(
            Response::parse(b"* PREAUTH [ALERT]\r\n").unwrap(),
            Response::untagged(Status::Preauth, "").with_code("ALERT")
        );
        assert_eq!(Response::parse(b"*\r\n").unwrap(), Response::Data(vec![]));
    }

    #[test]
    fn round_trips() {
        let commands: &[&[u8]] = &[
            b"a001 LOGIN SMITH SESAME\r\n",
            b"A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])\r\n",
            b"A003 APPEND saved-messages (\\Seen) {12}\r\nHello Joe!\r\n\r\n",
            b"a LOGIN {5+}\r\nalice \"p\\\"w\\\\\"\r\n",
            b"x SEARCH (OR 1 (2 (3))) NIL () 42\r\n",
            b"y ID (\"name\" \"x\" \"version\" NIL)\r\n",
        ];
        for &b in commands {
            let c = cmd(b);
            assert_eq!(c.to_bytes().unwrap(), b, "{}", String::from_utf8_lossy(b));
        }
        let responses: &[&[u8]] = &[
            b"* OK IMAP4rev2 Service Ready\r\n",
            b"* OK [UIDVALIDITY 3857529045] UIDs valid\r\n",
            b"A142 OK [READ-WRITE] SELECT completed\r\n",
            b"* 12 FETCH (FLAGS (\\Seen) BODY[HEADER] {13}\r\nSubject: hi\r\n)\r\n",
            b"+ Ready\r\n",
            b"* NO [ALERT] \r\n",
            b"a OK \r\n",
            b"*\r\n",
            b"a NO [x]y\r\n",
        ];
        for &b in responses {
            assert_eq!(
                Response::parse(b).unwrap().to_bytes().unwrap(),
                b,
                "{}",
                String::from_utf8_lossy(b)
            );
        }
    }

    #[test]
    fn status_word_is_followed_by_a_space() {
        // resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text, and
        // resp-text = ["[" resp-text-code "]" SP] [text].
        assert_eq!(
            Response::tagged("a3", Status::No, "").to_bytes().unwrap(),
            b"a3 NO \r\n"
        );
        assert_eq!(Response::bye("").to_bytes().unwrap(), b"* BYE \r\n");
        let r = Response::untagged(Status::No, "").with_code("ALERT");
        assert_eq!(r.to_bytes().unwrap(), b"* NO [ALERT] \r\n");
        assert_eq!(Response::parse(&r.to_bytes().unwrap()), Ok(r));
        let r = Response::tagged("a", Status::Ok, "");
        assert_eq!(Response::parse(&r.to_bytes().unwrap()), Ok(r));
    }

    #[test]
    fn list_writes_a_valid_mailbox_and_delimiter() {
        // mailbox = "INBOX" / astring: list wildcards and \ are not
        // ASTRING-CHARs, so such names go quoted.
        assert_eq!(
            Response::list(&[], Some('/'), b"a%b").to_bytes().unwrap(),
            b"* LIST () \"/\" \"a%b\"\r\n"
        );
        assert_eq!(
            Response::list(&[], Some('/'), b"a\\b").to_bytes().unwrap(),
            b"* LIST () \"/\" \"a\\\\b\"\r\n"
        );
        assert_eq!(
            Response::list(&[], Some('/'), b"x*").to_bytes().unwrap(),
            b"* LIST () \"/\" \"x*\"\r\n"
        );
        assert_eq!(
            Response::list(&[], Some('/'), b"[Gmail]/All")
                .to_bytes()
                .unwrap(),
            b"* LIST () \"/\" [Gmail]/All\r\n"
        );
        // The delimiter is DQUOTE QUOTED-CHAR DQUOTE or NIL, never a
        // literal.
        assert_eq!(
            Response::list(&[], Some('\n'), b"INBOX")
                .to_bytes()
                .unwrap(),
            b"* LIST () NIL INBOX\r\n"
        );
        assert_eq!(
            Response::list(&[], Some('\0'), b"INBOX")
                .to_bytes()
                .unwrap(),
            b"* LIST () NIL INBOX\r\n"
        );
    }

    #[test]
    fn list_quotes_a_mailbox_named_nil() {
        // An atom NIL reads as the empty value.
        assert_eq!(
            Response::list(&[], Some('/'), b"NIL").to_bytes().unwrap(),
            b"* LIST () \"/\" \"NIL\"\r\n"
        );
        assert_eq!(
            Response::list(&[], Some('/'), b"nil").to_bytes().unwrap(),
            b"* LIST () \"/\" \"nil\"\r\n"
        );
    }

    #[test]
    fn lists_next_to_lists() {
        // body-type-mpart = 1*body SP media-subtype, and env-from =
        // "(" 1*address ")": the lists come with no space between them.
        let b: &[u8] = b"* 1 FETCH (BODYSTRUCTURE ((\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 1 1)(\"TEXT\" \"HTML\" NIL NIL NIL \"7BIT\" 1 1) \"ALTERNATIVE\"))\r\n";
        let r = Response::parse(b).unwrap();
        let Response::Data(v) = &r else { panic!() };
        let body = &v[2].as_list().unwrap()[1];
        assert_eq!(body.as_list().map(<[Value]>::len), Some(3));
        assert_eq!(r.to_bytes().unwrap(), b);
        assert_eq!(responses(b), vec![Ok(r.clone())]);
        let b: &[u8] = b"* 2 FETCH (ENVELOPE (NIL \"hi\" ((NIL NIL \"a\" \"x.org\")(NIL NIL \"b\" \"x.org\")) ((NIL NIL \"a\" \"x.org\")) NIL ((NIL NIL \"c\" \"x.org\")) NIL NIL NIL NIL))\r\n";
        assert_eq!(Response::parse(b).unwrap().to_bytes().unwrap(), b);
        let b: &[u8] = b"* NAMESPACE ((\"\" \"/\")(\"#shared/\" \"/\")) NIL NIL\r\n";
        assert_eq!(Response::parse(b).unwrap().to_bytes().unwrap(), b);
        // A space between them is taken too.
        let r = Response::parse(b"* X ((a) (b))\r\n").unwrap();
        assert_eq!(
            r,
            Response::Data(vec![
                Value::atom("X"),
                Value::List(vec![Value::List(atoms(&["a"])), Value::List(atoms(&["b"]))])
            ])
        );
        assert_eq!(r.to_bytes().unwrap(), b"* X ((a)(b))\r\n");
        // A list after other items, as in body-ext, keeps its space.
        let r = Response::Data(vec![Value::List(vec![Value::nil(), Value::List(vec![]), Value::List(vec![])])]);
        assert_eq!(r.to_bytes().unwrap(), b"* (NIL () ())\r\n");
        // Commands keep spaces between lists, as search-key wants.
        let c = Command::new(
            "a",
            "SEARCH",
            vec![Value::List(vec![Value::List(atoms(&["SEEN"])), Value::List(atoms(&["NEW"]))])],
        );
        assert_eq!(c.to_bytes().unwrap(), b"a SEARCH ((SEEN) (NEW))\r\n");
        assert!(syntax(b"a SEARCH ((SEEN)(NEW))\r\n"));
        // Deeper lists are refused without substituting NIL.
        let mut value = Value::List(vec![Value::List(vec![]), Value::List(vec![])]);
        for _ in 0..MAX_DEPTH - 1 {
            value = Value::List(vec![value]);
        }
        assert_eq!(contract::check_refused(&Response::Data(vec![value])), Error::Unwritable);
    }
    #[test]
    fn brackets_open_sections_only_after_fetch_items() {
        // astring takes `[`; only fetch-att and msg-att names open a
        // section.
        assert_eq!(cmd(b"a SELECT foo[\r\n").args, atoms(&["foo["]));
        assert_eq!(
            cmd(b"a SELECT foo[bar baz]\r\n").args,
            atoms(&["foo[bar", "baz]"])
        );
        assert_eq!(
            Command::new("a", "SELECT", vec![Value::atom("foo[")])
                .to_bytes()
                .unwrap(),
            b"a SELECT foo[\r\n"
        );
        assert_eq!(contract::check_refused(&Command::new("a", "X", vec![Value::atom("BODY[")])), Error::Unwritable);
        // header-fld-name is an astring, so it may be quoted or a literal.
        let b: &[u8] = b"a FETCH 1 BODY.PEEK[HEADER.FIELDS ({4}\r\nFrom \"a]b\")]\r\n";
        let ev = events(b);
        assert_eq!(
            ev[0],
            Ok(Input::Continue {
                tag: Some("a".into()),
                size: 4
            })
        );
        let want = Command::new(
            "a",
            "FETCH",
            vec![
                Value::atom("1"),
                Value::atom("BODY.PEEK[HEADER.FIELDS (\"From\" \"a]b\")]"),
            ],
        );
        assert_eq!(ev[1], Ok(Input::Command(want.clone())));
        assert_eq!(cmd(&want.to_bytes().unwrap()), want);
        assert_eq!(
            cmd(b"a FETCH 1 body[1]<0.10>\r\n").args[1],
            Value::atom("body[1]<0.10>")
        );
        assert!(syntax(b"a FETCH 1 BODY[HEADER.FIELDS ({2}\r\na\nb)]\r\n"));
        let r = Response::parse(b"* 1 FETCH (BODY[HEADER.FIELDS (\"X\")] NIL)\r\n").unwrap();
        assert_eq!(
            r.to_bytes().unwrap(),
            b"* 1 FETCH (BODY[HEADER.FIELDS (\"X\")] NIL)\r\n"
        );
    }

    #[test]
    fn binary_literals() {
        // literal8 = "~{" number64 "}" CRLF *OCTET (RFC 9051 section 9),
        // in FETCH BINARY responses and in APPEND.
        let b: &[u8] = b"* 1 FETCH (BINARY[1] ~{3}\r\na\0b)\r\n";
        let r = Response::parse(b).unwrap();
        let bin = Value::Binary { data: b"a\0b".to_vec(), non_sync: false };
        assert_eq!(r, Response::fetch(1, vec![Value::atom("BINARY[1]"), bin.clone()]));
        assert_eq!(r.to_bytes().unwrap(), b);
        assert_eq!(responses(b), vec![Ok(r)]);
        let b: &[u8] = b"a APPEND INBOX ~{3+}\r\na\0b\r\n";
        let c = cmd(b);
        assert_eq!(c.args[1], Value::Binary { data: b"a\0b".to_vec(), non_sync: true });
        assert_eq!(c.to_bytes().unwrap(), b);
        let ev = events(b"a APPEND INBOX ~{3}\r\na\0b\r\n");
        assert!(matches!(ev[0], Ok(Input::Continue { size: 3, .. })));
        assert!(matches!(&ev[1], Ok(Input::Command(c)) if c.args[1] == bin));
        // Servers never write ~{n+}.
        let r = Response::fetch(1, vec![Value::atom("BINARY[]"), Value::Binary { data: vec![0], non_sync: true }]);
        assert_eq!(contract::check_refused(&r), Error::Unwritable);
        // A plain literal still may not hold NUL, and ~ alone is a word.
        assert!(syntax(b"a X {1}\r\n\0\r\n"));
        assert_eq!(cmd(b"a X ~ ~a\r\n").args, atoms(&["~", "~a"]));
    }

    #[test]
    fn tags_are_written_whole() {
        // The tagged response repeats the tag (RFC 9051 section 2.2.2).
        let mut b = "t".repeat(MAX_TEXT - 11).into_bytes();
        b.extend_from_slice(b" NOOP\r\n");
        let c = cmd(&b);
        let r = Response::tagged(&c.tag, Status::Ok, "done");
        let out = r.to_bytes().unwrap();
        assert!(out.len() <= MAX_TEXT);
        assert_eq!(Response::parse(&out), Ok(r));
        // The longest tag a command can carry, and the longest a status
        // response can.
        let mut b = "t".repeat(MAX_TEXT - 4).into_bytes();
        b.extend_from_slice(b" X\r\n");
        assert_eq!(cmd(&b).to_bytes().unwrap(), b);
        let mut b = "t".repeat(MAX_TEXT - 5).into_bytes();
        b.extend_from_slice(b" OK\r\n");
        let r = Response::parse(&b).unwrap();
        assert_eq!(r.to_bytes().unwrap(), b);
        let r = Response::tagged(&"t".repeat(MAX_TEXT), Status::Bad, "x").with_code("C");
        assert_eq!(contract::check_refused(&r), Error::Unwritable);
    }

    fn strings_needing_literals() -> Vec<Vec<u8>> {
        vec![
            b"a\r\nb".to_vec(),
            b"a\rb".to_vec(),
            b"a\nb".to_vec(),
            b"a\xffb".to_vec(),
            vec![b' '; MAX_QUOTED + 1],
        ]
    }

    #[test]
    fn fetch_strings_use_literals_when_needed() {
        for body in strings_needing_literals() {
            let response = Response::fetch(1, vec![Value::atom("BODY[]"), Value::string(&body)]);
            let expected = [
                format!("* 1 FETCH (BODY[] {{{}}}\r\n", body.len()).as_bytes(),
                &body,
                b")\r\n",
            ]
            .concat();
            assert_eq!(response.to_bytes().unwrap(), expected);
            assert_eq!(Response::parse(&expected), Ok(response.clone()));
            assert_eq!(responses(&expected), vec![Ok(response)]);
            contract::check_decode_with_alloc_limit(Responses::new, &expected, 2 * MAX_LINE);
        }
        assert_eq!(
            Value::string(&vec![b'a'; MAX_QUOTED]),
            Value::Quoted(vec![b'a'; MAX_QUOTED])
        );
    }

    #[test]
    fn list_mailboxes_use_literals_when_needed() {
        for mailbox in strings_needing_literals() {
            let response = Response::list(&[], None, &mailbox);
            let expected = [
                format!("* LIST () NIL {{{}}}\r\n", mailbox.len()).as_bytes(),
                &mailbox,
                b"\r\n",
            ]
            .concat();
            assert_eq!(response.to_bytes().unwrap(), expected);
            assert_eq!(Response::parse(&expected), Ok(response.clone()));
            assert_eq!(responses(&expected), vec![Ok(response)]);
            contract::check_decode_with_alloc_limit(Responses::new, &expected, 2 * MAX_LINE);
        }
    }

    #[test]
    fn writers() {
        for (value, bytes) in [
            (Response::exists(23), b"* 23 EXISTS\r\n".as_slice()),
            (Response::recent(1), b"* 1 RECENT\r\n"),
            (Response::expunge(3), b"* 3 EXPUNGE\r\n"),
            (Response::greeting("ready"), b"* OK ready\r\n"),
            (
                Response::tagged("a2", Status::Ok, "done").with_code("READ-ONLY"),
                b"a2 OK [READ-ONLY] done\r\n",
            ),
            (Response::continue_req(""), b"+ \r\n"),
            (
                Response::list(&["\\HasNoChildren"], Some('.'), b"Sent Items"),
                b"* LIST (\\HasNoChildren) \".\" \"Sent Items\"\r\n",
            ),
            (
                Response::list(&[], None, b"INBOX"),
                b"* LIST () NIL INBOX\r\n",
            ),
            (Response::Data(vec![]), b"*\r\n"),
        ] {
            assert_eq!(value.to_bytes().unwrap(), bytes);
            contract::check_wire_value(&value);
        }
        let fetch = Response::fetch(
            1,
            vec![
                Value::atom("BODY[]"),
                Value::Literal {
                    data: b"a\r\nb".to_vec(),
                    non_sync: false,
                },
            ],
        );
        assert_eq!(
            fetch.to_bytes().unwrap(),
            b"* 1 FETCH (BODY[] {4}\r\na\r\nb)\r\n"
        );
        let command = Command::new(
            "t1",
            "append",
            vec![
                Value::atom("INBOX"),
                Value::Literal {
                    data: b"hi".to_vec(),
                    non_sync: true,
                },
            ],
        );
        assert_eq!(
            command.to_bytes().unwrap(),
            b"t1 APPEND INBOX {2+}\r\nhi\r\n"
        );
        for command in [
            Command::new("t2", "SELECT", vec![Value::atom("My Box"), Value::atom("")]),
            Command::new("a b", "", vec![]),
            Command::new("", "no op", vec![]),
        ] {
            assert_eq!(contract::check_refused(&command), Error::Unwritable);
        }
        for response in [
            Response::tagged("a", Status::Bye, "x"),
            Response::greeting("a\r\nb"),
            Response::untagged(Status::Ok, "x").with_code("A]B"),
            Response::Data(atoms(&["OK", "x"])),
        ] {
            assert_eq!(contract::check_refused(&response), Error::Unwritable);
        }
    }

    #[test]
    fn command_errors() {
        for (bytes, tag, reason) in [
            (b"\r\n".as_slice(), None, "a command starts with a tag"),
            (b"a\r\n", None, "a space must follow the tag"),
            (b"a \r\n", Some("a"), "a command name must follow the tag"),
            (b"a NOOP \r\n", Some("a"), "expected a value"),
            (b"a NOOP\n", Some("a"), "a line must end with CRLF"),
            (b"a X (b\r\n", Some("a"), "expected a space or ) in a list"),
            (
                b"a X (b)c\r\n",
                Some("a"),
                "expected a space or the end of the line",
            ),
            (b"a X ( b)\r\n", Some("a"), "expected a value"),
            (
                b"a X \"ab\r\n",
                Some("a"),
                "a quoted string holds NUL, CR or LF",
            ),
            (
                b"a X \"a\\b\"\r\n",
                Some("a"),
                "only \\\" and \\\\ may be escaped",
            ),
            (b"a X {}\r\n", Some("a"), "a literal's size must follow {"),
            (
                b"a X {3}x\r\n",
                Some("a"),
                "a literal's size must end with } and CRLF",
            ),
            (b"a X BODY[1\r\n", Some("a"), "an atom has [ without ]"),
            (b"+ X\r\n", None, "a command starts with a tag"),
            (b"* X\r\n", None, "a command starts with a tag"),
        ] {
            let error = Error::Syntax {
                tag: tag.map(String::from),
                reason,
            };
            assert_eq!(
                Command::parse(bytes),
                Err(error.clone()),
                "{bytes:?}"
            );
            assert_eq!(decode_all(Inputs::new, bytes), (vec![Err(error)], None));
            contract::check_decode_with_alloc_limit(Inputs::new, bytes, 2 * MAX_LINE);
        }
        assert_eq!(
            Command::parse(b"a NOOP\r\nb NOOP\r\n"),
            Err(Error::Trailing)
        );
        for (bytes, error) in [
            (
                b"a X \"ab".as_slice(),
                FrameError::Line(codec::LineError::Unterminated),
            ),
            (b"a X {3}\r\nab", FrameError::Incomplete),
        ] {
            assert_eq!(Command::parse(bytes), Err(Error::Framing(error)));
            contract::check_decode_with_alloc_limit(Inputs::new, bytes, 2 * MAX_LINE);
        }
        for (depth, valid) in [(MAX_DEPTH, true), (MAX_DEPTH + 1, false)] {
            let bytes = [
                b"a X ".to_vec(),
                vec![b'('; depth],
                vec![b')'; depth],
                b"\r\n".to_vec(),
            ]
            .concat();
            if valid {
                assert_eq!(cmd(&bytes).to_bytes().unwrap(), bytes);
            } else {
                let error = Error::Syntax {
                    tag: Some("a".into()),
                    reason: "lists nest too deeply",
                };
                assert_eq!(
                    Command::parse(&bytes),
                    Err(error.clone())
                );
                assert_eq!(decode_all(Inputs::new, &bytes), (vec![Err(error)], None));
            }
        }
        let quoted = [
            b"a X \"".to_vec(),
            vec![b'q'; MAX_QUOTED + 1],
            b"\"\r\n".to_vec(),
        ]
        .concat();
        let error = Error::Syntax {
            tag: Some("a".into()),
            reason: "a quoted string is too long",
        };
        assert_eq!(
            Command::parse(&quoted),
            Err(error.clone())
        );
        assert_eq!(decode_all(Inputs::new, &quoted), (vec![Err(error)], None));
        assert_eq!(
            Command::parse(b"a X {99999999999999999999999}\r\n"),
            Err(Error::LiteralTooLarge {
                tag: Some("a".into()),
                size: u64::MAX,
                waiting: true
            })
        );
        assert!(matches!(
            Command::parse(b"a X {1048577+}\r\n"),
            Err(Error::Framing(FrameError::LiteralTooLarge { .. }))
        ));
        for bytes in [vec![b'z'; MAX_TEXT + 4], vec![b'a'; MAX_MESSAGE + 1]] {
            assert!(matches!(
                Command::parse(&bytes),
                Err(Error::Framing(FrameError::Line(_)))
            ));
        }
    }

    #[test]
    fn response_errors() {
        for bytes in [
            b"".as_slice(),
            b"a FOO\r\n",
            b"* OK x",
            b"* OK x\n",
            b"* OK \0\r\n",
            b"* OK \xff\r\n",
            b"* OK [\xff] x\r\n",
            b"* OK x\r\ny\r\n",
            b"+x\r\n",
            b"a BYE x\r\n",
            b"a PREAUTH x\r\n",
            b"* 1 FETCH (BODY[] {2+}\r\nhi)\r\n",
            b"*1 EXISTS\r\n",
        ] {
            assert!(Response::parse(bytes).is_err(), "{bytes:?}");
        }
        for bytes in [vec![b'z'; MAX_TEXT + 5], vec![b'*'; MAX_MESSAGE + 1]] {
            assert!(matches!(
                Response::parse(&bytes),
                Err(Error::Framing(FrameError::Line(_)))
            ));
        }
        assert!(matches!(
            Response::parse(b"* 1 FETCH (BODY[] {2000000}\r\n"),
            Err(Error::Framing(FrameError::LiteralTooLarge {
                size: 2000000,
                ..
            }))
        ));
    }

    #[test]
    fn every_truncated_prefix() {
        for bytes in [
            b"A003 APPEND saved-messages (\\Seen) {12}\r\nHello Joe!\r\n\r\n".as_slice(),
            b"a LOGIN {5+}\r\nalice \"p\\\"w\\\\\"\r\n",
            b"A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])\r\n",
        ] {
            for cut in 0..bytes.len() {
                assert!(Command::parse(&bytes[..cut]).is_err());
                let (items, _) = decode_all(Inputs::new, &bytes[..cut]);
                assert!(
                    items
                        .iter()
                        .all(|e| matches!(e, Ok(Input::Continue { .. })))
                );
            }
            contract::check_decode_with_alloc_limit(Inputs::new, bytes, 2 * MAX_LINE);
        }
        for bytes in [
            b"* 12 FETCH (FLAGS (\\Seen) BODY[HEADER] {13}\r\nSubject: hi\r\n)\r\n".as_slice(),
            b"A142 OK [READ-WRITE] SELECT completed\r\n",
            b"+ Ready\r\n",
        ] {
            for cut in 0..bytes.len() {
                assert!(Response::parse(&bytes[..cut]).is_err());
                assert!(decode_all(Responses::new, &bytes[..cut]).0.is_empty());
            }
            contract::check_decode_with_alloc_limit(Responses::new, bytes, 2 * MAX_LINE);
        }
    }

    #[test]
    fn decoder_and_continuations() {
        let wire = b"a1 NOOP\r\na2 LOGIN {5}\r\nalice {3+}\r\npwd\r\na3 X\r\n";
        let expected = vec![
            Ok(Input::Command(Command::new("a1", "NOOP", vec![]))),
            Ok(Input::Continue {
                tag: Some("a2".into()),
                size: 5,
            }),
            Ok(Input::Command(Command::new(
                "a2",
                "LOGIN",
                vec![
                    Value::Literal {
                        data: b"alice".to_vec(),
                        non_sync: false,
                    },
                    Value::Literal {
                        data: b"pwd".to_vec(),
                        non_sync: true,
                    },
                ],
            ))),
            Ok(Input::Command(Command::new("a3", "X", vec![]))),
        ];
        assert_eq!(events(wire), expected);
        contract::check_decode_with_alloc_limit(Inputs::new, wire, 2 * MAX_LINE);
        let mut stream = Stream::new(Inputs::new());
        let wire = b"b1 APPEND INBOX {10}\r\nb2 NOOP\r\n";
        assert_eq!(stream.push(wire), wire.len());
        assert!(matches!(
            stream.next(),
            Some(Ok(Ok(Input::Continue { size: 10, .. })))
        ));
        assert!(stream.decoder().refuse_literal());
        assert!(!stream.decoder().refuse_literal());
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(Input::Command(Command::new("b2", "NOOP", vec![])))))
        );
        let wire = b"b3 APPEND INBOX {10}\r\n";
        assert_eq!(stream.push(wire), wire.len());
        assert!(matches!(
            stream.next(),
            Some(Ok(Ok(Input::Continue { size: 10, .. })))
        ));
        assert!(stream.decoder().refuse_literal());
        assert!(stream.held() == 0 && stream.buffered() == 0);
        assert_eq!(stream.next(), None);
        let items = events(b"c1 APPEND INBOX {2000000}\r\nc2 NOOP\r\n");
        let error = items[0].as_ref().unwrap_err();
        assert_eq!(error.tag(), Some("c1"));
        assert!(matches!(
            error,
            Error::LiteralTooLarge { waiting: true, .. }
        ));
        assert!(matches!(items[1], Ok(Input::Command(_))));
        let mut stream = Stream::new(Inputs::new());
        let wire = b"c1 APPEND INBOX {2000000+}\r\nc2 NOOP\r\n";
        assert_eq!(stream.push(wire), wire.len());
        assert!(matches!(
            stream.next(),
            Some(Err(Fail::Protocol(FrameError::LiteralTooLarge { .. })))
        ));
        assert_eq!(stream.next(), None);
        assert!(stream.failed().is_some());
        let items = events(b"e1 X (\r\ne2 NOOP\r\n");
        assert_eq!(items[0].as_ref().unwrap_err().tag(), Some("e1"));
        assert!(matches!(items[1], Ok(Input::Command(_))));
        let mut stream = Stream::new(Inputs::new());
        assert_eq!(stream.push(&vec![b'a'; MAX_TEXT - 1]), MAX_TEXT - 1);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"a"), 1);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(FrameError::Line(
                codec::LineError::TooLong { max: MAX_LINE - 2 }
            ))))
        );
    }

    #[test]
    fn raw_lines() {
        let mut stream = Stream::new(Inputs::new());
        let wire = b"a AUTHENTICATE PLAIN\r\nAGFsaWNlAHNlY3JldA==\r\nDONE\r\nb NOOP\r\n";
        assert_eq!(stream.push(wire), wire.len());
        assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(_))))));
        for line in [b"AGFsaWNlAHNlY3JldA==".as_slice(), b"DONE"] {
            stream.decoder().expect_line().unwrap();
            assert_eq!(stream.next(), Some(Ok(Ok(Input::Line(line.to_vec())))));
        }
        assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(_))))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"c X {3}\r\n"), 9);
        assert!(matches!(
            stream.next(),
            Some(Ok(Ok(Input::Continue { .. })))
        ));
        assert_eq!(stream.decoder().expect_line(), Err(FrameError::State));
    }

    #[test]
    fn response_decoder() {
        let wire = b"* OK hi {3}\r\n* 1 FETCH (BODY[] {3}\r\nabc)\r\n+ go\r\nt OK done\r\n";
        let expected = vec![
            Ok(Response::greeting("hi {3}")),
            Ok(Response::fetch(
                1,
                vec![
                    Value::atom("BODY[]"),
                    Value::Literal {
                        data: b"abc".to_vec(),
                        non_sync: false,
                    },
                ],
            )),
            Ok(Response::continue_req("go")),
            Ok(Response::tagged("t", Status::Ok, "done")),
        ];
        assert_eq!(responses(wire), expected);
        contract::check_decode_with_alloc_limit(Responses::new, wire, 2 * MAX_LINE);
        assert!(matches!(
            decode_all(Responses::new, b"* 1 FETCH (BODY[] {2000000}\r\n").1,
            Some(Fail::Protocol(FrameError::LiteralTooLarge { .. }))
        ));
        let items = responses(b"* 1 FETCH (BODY[] {3+}\r\nabc)\r\n");
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(Result::is_err));
        let mut stream = Stream::new(Responses::new());
        assert_eq!(stream.push(&vec![b'*'; MAX_TEXT + 1]), MAX_LINE);
        assert!(matches!(
            stream.next(),
            Some(Err(Fail::Protocol(FrameError::Line(_))))
        ));
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn writers_refuse_size_and_nesting_overflow() {
        assert_eq!(contract::check_refused(&Command::new(
            "a",
            "APPEND",
            vec![Value::Literal {
                data: vec![b'x'; MAX_LITERAL + 10],
                non_sync: true,
            }],
        )), Error::Unwritable);
        assert_eq!(contract::check_refused(&Response::Data(vec![
            Value::Literal {
                data: vec![b'y'; MAX_LITERAL],
                non_sync: false
            };
            6
        ])), Error::Unwritable);
        assert_eq!(contract::check_refused(&Command::new(
            "a",
            "X",
            vec![Value::atom(&"z".repeat(1000)); 100],
        )), Error::Unwritable);
        assert_eq!(contract::check_refused(&Response::greeting(&"é".repeat(MAX_TEXT)).with_code(&"c".repeat(MAX_TEXT))), Error::Unwritable);
        assert_eq!(contract::check_refused(&Response::continue_req(&"é".repeat(MAX_TEXT))), Error::Unwritable);
        assert_eq!(contract::check_refused(&Command::new(
            &"t".repeat(MAX_TEXT * 2),
            &"n".repeat(MAX_TEXT),
            vec![Value::nil()],
        )), Error::Unwritable);
        let mut value = Value::nil();
        for _ in 0..MAX_DEPTH + 5 {
            value = Value::List(vec![value]);
        }
        assert_eq!(contract::check_refused(&Command::new("a", "X", vec![value])), Error::Unwritable);
        assert_eq!(contract::check_refused(&Command::new(
            "a",
            "X",
            vec![Value::Quoted(vec![b'q'; MAX_QUOTED + 1])],
        )), Error::Unwritable);
    }

    #[test]
    fn literals_never_hold_nul() {
        assert!(matches!(
            Command::parse(b"a X {3}\r\na\0b\r\n"),
            Err(Error::Syntax {
                reason: "a literal holds NUL",
                ..
            })
        ));
        assert!(Response::parse(b"* 1 FETCH (BODY[] {1}\r\n\0)\r\n").is_err());
        let items = events(b"a X {1+}\r\n\0\r\nb NOOP\r\n");
        assert!(matches!(items[0], Err(Error::Syntax { .. })));
        assert_eq!(
            items[1],
            Ok(Input::Command(Command::new("b", "NOOP", vec![])))
        );
        assert_eq!(contract::check_refused(&Command::new(
            "a",
            "X",
            vec![
                Value::string(b"a\0b"),
                Value::Literal {
                    data: b"\0c\0".to_vec(),
                    non_sync: true,
                },
            ],
        )), Error::Unwritable);
        assert_eq!(contract::check_refused(&Response::fetch(
            1,
            vec![Value::atom("BODY[]"), Value::string(b"x\r\n\0")],
        )), Error::Unwritable);
    }

    #[test]
    fn quoted_strings_are_utf8() {
        for bytes in [b"a X \"\xff\"\r\n".as_slice(), b"a X \"a\xc3\"\r\n"] {
            assert!(matches!(
                Command::parse(bytes),
                Err(Error::Syntax {
                    reason: "a quoted string is not UTF-8",
                    ..
                })
            ));
        }
        assert!(Response::parse(b"* X \"a\xc3\"\r\n").is_err());
        let command = cmd("a X \"é\"\r\n".as_bytes());
        assert_eq!(command.args[0].as_str(), Some("é"));
        assert_eq!(cmd(&command.to_bytes().unwrap()), command);
        assert_eq!(contract::check_refused(&Command::new(
            "a",
            "X",
            vec![Value::Quoted(b"\xff".to_vec())],
        )), Error::Unwritable);
        assert_eq!(contract::check_refused(&Response::Data(vec![
            Value::atom("X"),
            Value::Quoted(b"a\x80".to_vec()),
        ])), Error::Unwritable);
        let command = Command::new(
            "a",
            "X",
            vec![Value::Literal {
                data: vec![0xff],
                non_sync: true,
            }],
        );
        assert_eq!(cmd(&command.to_bytes().unwrap()), command);
    }

    #[test]
    fn many_messages_in_one_push() {
        let count = 200_000;
        let wire = b"a NOOP\r\n".repeat(count);
        let items = events(&wire);
        assert_eq!(items.len(), count);
        assert!(
            items
                .iter()
                .all(|e| *e == Ok(Input::Command(Command::new("a", "NOOP", vec![]))))
        );
        let items = responses(&b"* 1 EXISTS\r\n".repeat(count));
        assert_eq!(items.len(), count);
        assert!(items.iter().all(|e| *e == Ok(Response::exists(1))));
        let mut stream = Stream::new(Inputs::new());
        assert_eq!(stream.push(b"a NOOP\r\nb NO"), 12);
        assert!(stream.next().is_some());
        assert_eq!(stream.push(b"OP\r\n"), 4);
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(Input::Command(Command::new("b", "NOOP", vec![])))))
        );
    }

    #[test]
    fn raw_lines_are_partition_invariant() {
        let make = || {
            let mut c = Inputs::new();
            c.expect_line().unwrap();
            c
        };
        for bytes in [
            b"abc\r\nx NOOP\r\n".as_slice(),
            b"DONE\nx NOOP\r\n",
            &vec![b'a'; MAX_TEXT],
        ] {
            contract::check_decode_with_alloc_limit(make, bytes, 2 * MAX_LINE);
        }
        assert_eq!(
            decode_all(make, b"abc\r\nx NOOP\r\n").0[0],
            Ok(Input::Line(b"abc".to_vec()))
        );
        assert!(matches!(
            decode_all(make, b"DONE\nx NOOP\r\n").0[0],
            Err(Error::Syntax { .. })
        ));
        assert!(matches!(
            decode_all(make, &vec![b'a'; MAX_TEXT]).1,
            Some(Fail::Protocol(FrameError::Line(
                codec::LineError::TooLong { .. }
            )))
        ));
    }

    #[test]
    fn decoders_release_assemblies_and_bound_input_allocation() {
        let bytes = [
            b"a APPEND INBOX {1048576}\r\n".to_vec(),
            vec![b'm'; MAX_LITERAL],
            b"\r\n".to_vec(),
        ]
        .concat();
        contract::check_decode_with_alloc_limit(Inputs::new, &bytes, 2 * MAX_LINE);
        let mut stream = Stream::new(Inputs::new());
        codec::pump(&mut stream, &bytes, |_| {}).unwrap();
        assert_eq!(stream.held(), 0);
        assert_eq!(stream.buffered(), 0);
        assert!(stream.into_parts().0.allocated() <= 2 * MAX_LINE);
    }

    #[test]
    fn writers_stop_at_their_limits() {
        let value = Value::List(vec![
            Value::Literal {
                data: vec![b'z'; MAX_LITERAL],
                non_sync: false
            };
            100
        ]);
        assert_eq!(contract::check_refused(&Response::Data(vec![value])), Error::Unwritable);
        assert_eq!(contract::check_refused(&Response::Data(vec![Value::List(vec![Value::atom(
            &"a".repeat(MAX_TEXT + 1),
        )])])), Error::Unwritable);
    }

    #[test]
    fn client_literals_and_continuations() {
        let long = vec![b'\n'; MAX_NON_SYNC + 1];
        let command = Command::new(
            "a",
            "X",
            vec![Value::Literal {
                data: long.clone(),
                non_sync: false,
            }],
        );
        assert!(command.to_bytes().unwrap().starts_with(b"a X {4097}\r\n"));
        assert_eq!(contract::check_refused(&Command::new(
            "a",
            "X",
            vec![Value::Literal {
                data: long,
                non_sync: true,
            }],
        )), Error::Unwritable);
        let command = Command::new(
            "a",
            "X",
            vec![Value::Literal {
                data: vec![b'\n'; MAX_NON_SYNC],
                non_sync: true,
            }],
        );
        assert!(command.to_bytes().unwrap().starts_with(b"a X {4096+}\r\n"));
        let command = Command::new(
            "a",
            "LOGIN",
            vec![
                Value::Literal {
                    data: b"alice".to_vec(),
                    non_sync: false,
                },
                Value::Literal {
                    data: b"x".to_vec(),
                    non_sync: true,
                },
                Value::Binary {
                    data: b"p\0w".to_vec(),
                    non_sync: false,
                },
            ],
        );
        let bytes = command.to_bytes().unwrap();
        let offsets = Command::continuation_offsets(&bytes).unwrap();
        assert_eq!(offsets.len(), 2);
        assert_eq!(&bytes[..offsets[0]], b"a LOGIN {5}\r\n");
        assert_eq!(&bytes[offsets[0]..offsets[1]], b"alice {1+}\r\nx ~{3}\r\n");
        assert_eq!(&bytes[offsets[1]..], b"p\0w\r\n");
        assert_eq!(
            Command::continuation_offsets(b"a NOOP\r\n").unwrap(),
            vec![]
        );
        let big = Value::Literal {
            data: vec![b'y'; MAX_LITERAL],
            non_sync: false,
        };
        assert_eq!(contract::check_refused(&Command::new("a", "X", vec![big; 6])), Error::Unwritable);
    }

    #[test]
    fn continuations_share_one_tag() {
        let tag = "t".repeat(32 * 1024);
        let mut stream = Stream::new(Inputs::new());
        let head = format!("{tag} LOGIN");
        assert_eq!(stream.push(head.as_bytes()), head.len());
        let mut seen: Option<Arc<str>> = None;
        for _ in 0..100 {
            assert_eq!(stream.push(b" {0}\r\n"), 6);
            let Some(Ok(Ok(Input::Continue {
                tag: Some(next),
                size: 0,
            }))) = stream.next()
            else {
                panic!()
            };
            assert_eq!(&*next, tag);
            if let Some(previous) = &seen {
                assert!(Arc::ptr_eq(previous, &next));
            }
            seen = Some(next);
        }
        assert_eq!(stream.push(b"\r\n"), 2);
        assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(c)))) if c.args.len() == 100));
        assert_eq!(stream.push(b"b X {0}\r\n"), 9);
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(Input::Continue {
                tag: Some("b".into()),
                size: 0
            })))
        );
    }

    struct Refusals<'a> {
        commands: Inputs,
        choices: &'a [u8],
        at: usize,
        refuse: bool,
    }
    impl Decode for Refusals<'_> {
        type Item = Result<Input, Error>;
        type Error = FrameError;
        const NAME: &'static str = "IMAP refusal test world";
        fn capacity(&self) -> usize {
            self.commands.capacity()
        }
        fn held(&self) -> usize {
            self.commands.held()
        }
        fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<Self::Item>, FrameError> {
            if core::mem::take(&mut self.refuse) {
                assert!(self.commands.refuse_literal());
                assert!(!self.commands.refuse_literal());
            }
            let step = self.commands.decode(bytes, eof)?;
            if let Step::Item(item, _) = &step {
                self.refuse = matches!(item, Ok(Input::Continue { .. }))
                    && self.choices.get(self.at).is_some_and(|b| b & 1 == 1);
                self.at = self.at.saturating_add(1);
            }
            Ok(step)
        }
    }

    #[test]
    fn refusals_in_a_stream() {
        let make = || Refusals {
            commands: Inputs::new(),
            choices: &[1],
            at: 0,
            refuse: false,
        };
        let bytes = b"a APPEND X {3}\r\nabc\r\nb NOOP\r\n";
        let (items, failure) = decode_all(make, bytes);
        assert_eq!(failure, None);
        assert_eq!(
            items[0],
            Ok(Input::Continue {
                tag: Some("a".into()),
                size: 3
            })
        );
        assert!(matches!(items[1], Err(Error::Syntax { .. })));
        assert_eq!(
            items[2],
            Ok(Input::Command(Command::new("b", "NOOP", vec![])))
        );
        contract::check_decode_with_alloc_limit(make, bytes, 2 * MAX_LINE);
        let mut rng = Lcg::new(7);
        for _ in 0..5000 {
            let bytes = generated_stream(&mut rng);
            let choices = rng.bytes(8);
            contract::check_decode_with_alloc_limit(
                || Refusals {
                    commands: Inputs::new(),
                    choices: &choices,
                    at: 0,
                    refuse: false,
                },
                &bytes,
                2 * MAX_LINE,
            );
        }
    }

    fn generated_stream(rng: &mut Lcg) -> Vec<u8> {
        const PIECES: &[&[u8]] = &[
            b"a1",
            b" ",
            b" ",
            b"\r\n",
            b"\r\n",
            b"\n",
            b"\r",
            b"*",
            b"+",
            b"(",
            b")",
            b"\"",
            b"\\",
            b"{",
            b"}",
            b"{3}\r\n",
            b"{2+}\r\n",
            b"{0}\r\n",
            b"OK",
            b"NO",
            b"BYE",
            b"[",
            b"]",
            b"FETCH",
            b"BODY[HEADER]",
            b"\\Seen",
            b"NIL",
            b"1:*",
            b"x",
            b"\0",
            b"\xff",
            b"\xc3\xa9",
            b"\"q\"",
            b"[CODE]",
            b"{99999999}\r\n",
            b"%",
            b"LOGIN",
            b"~{3}\r\nx\0\xff",
            b"~{2+}\r\n\0x",
            b"\"q\\\"\\\\\"",
        ];
        let seeds: &[&[u8]] = &[
            b"a LOGIN {3}\r\nabc {2+}\r\nhi\r\nb NOOP\r\n",
            b"a APPEND INBOX ~{3}\r\na\0\xff\r\n",
            b"a X ~{2+}\r\n\0x \"q\\\"\\\\\"\r\n",
            b"a APPEND INBOX {99999999}\r\n",
            b"* 1 FETCH (BINARY[] ~{3}\r\na\0\xff)\r\n",
            b"* OK [CODE] x\r\n",
            b"* 1 FETCH (BODY[] {3}\r\nabc)\r\n",
            b"a FETCH 1 BODY[HEADER.FIELDS (FROM)]\r\n",
        ];
        let mut bytes = seeds[rng.index(seeds.len())].to_vec();
        if rng.coin() {
            for _ in 0..rng.index(32) {
                bytes.extend_from_slice(PIECES[rng.index(PIECES.len())]);
            }
        }
        for _ in 0..rng.index(5) {
            mutate(rng, &mut bytes);
        }
        bytes
    }

    #[test]
    fn generated_streams_obey_contracts() {
        let mut rng = Lcg::new(0x1ee7_1ee7);
        let (mut commands, mut replies) = (0, 0);
        for _ in 0..1024 {
            let bytes = generated_stream(&mut rng);
            contract::check_decode_with_alloc_limit(Inputs::new, &bytes, 2 * MAX_LINE);
            contract::check_decode_with_alloc_limit(Responses::new, &bytes, 2 * MAX_LINE);
            contract::check_wire::<Command>(&bytes);
            contract::check_wire::<Response>(&bytes);
            for item in decode_all(Inputs::new, &bytes).0 {
                if let Ok(Input::Command(command)) = item {
                    commands += 1;
                    assert_eq!(Command::parse(&command.to_bytes().unwrap()), Ok(command));
                }
            }
            for reply in decode_all(Responses::new, &bytes).0.into_iter().flatten() {
                replies += 1;
                assert_eq!(Response::parse(&reply.to_bytes().unwrap()), Ok(reply));
            }
        }
        assert!(commands > 100);
        assert!(replies > 100);
    }

    #[test]
    fn random_values_round_trip() {
        let mut rng = Lcg::new(42);
        let words = [
            "INBOX",
            "a b",
            "",
            "\\Seen",
            "x[y]",
            "BODY[x y]",
            "foo[",
            "OK",
            "é",
            "{3}",
            "a\r\nb",
            "NIL",
            "q\"\\",
            "n\0",
            "\0",
        ];
        let (mut commands_written, mut responses_written) = (0, 0);
        for _ in 0..1000 {
            let mut args = Vec::new();
            for _ in 0..rng.index(6) {
                let word = words[rng.index(words.len())];
                let mut value = match rng.index(5) {
                    0 => Value::atom(word),
                    1 => Value::string(word.as_bytes()),
                    2 => Value::Literal {
                        data: word.as_bytes().to_vec(),
                        non_sync: rng.coin(),
                    },
                    3 => Value::Binary {
                        data: rng.bytes(32),
                        non_sync: rng.coin(),
                    },
                    _ => Value::List(vec![Value::atom(word), Value::string(word.as_bytes())]),
                };
                for _ in 0..rng.index(3) {
                    value = Value::List(vec![value]);
                }
                args.push(value);
            }
            let tags = ["a", "A1", "t2", "tag.3"];
            let tag = tags[rng.index(tags.len())];
            let command = Command::new(tag, "X", args.clone());
            contract::check_wire_value(&command);
            if command.to_bytes().is_ok() {
                commands_written += 1;
            }
            let response = Response::Data(args);
            contract::check_wire_value(&response);
            if let Ok(bytes) = response.to_bytes() {
                assert_eq!(
                    decode_all(Responses::new, &bytes),
                    (vec![Ok(response)], None)
                );
                responses_written += 1;
            }
            let text = rng.text(128);
            contract::check_wire_value(&Response::Status {
                tag: Some(tag.into()),
                status: Status::No,
                code: Some(text.clone()),
                text: text.clone(),
            });
            contract::check_wire_value(&Response::continue_req(&text));
        }
        assert!(
            commands_written > 500,
            "{commands_written} commands written"
        );
        assert!(
            responses_written > 100,
            "{responses_written} responses written"
        );
    }
}
