//! IMAP: reading and writing commands and responses, with no I/O.
//!
//! IMAP is how mail clients read mail kept on a server, usually over TCP
//! port 143. A client sends commands. Each is a line that starts with a
//! tag the client picks, then a command name and its arguments. The
//! server sends untagged responses, lines that start with `*`, which carry
//! data and news. It ends each command with a tagged response: the same
//! tag, then `OK`, `NO` or `BAD`. This module follows RFC 3501 (IMAP4rev1)
//! and RFC 9051 (IMAP4rev2), with the non-synchronizing literals of RFC
//! 7888.
//!
//! An argument is an atom (`INBOX`, `1:*`, `\Seen`, `BODY[HEADER]`), a
//! quoted string (`"Sent Items"`), a parenthesized list, or a literal. A
//! literal is `{n}` at the end of a line, then exactly n bytes, and the
//! line goes on after them. For a synchronizing literal, `{n}`, the client
//! waits for a continuation request (a line that starts with `+`) before
//! it sends the bytes. For a non-synchronizing one, `{n+}`, it does not
//! wait.
//!
//! Nothing here reads a socket. A world that plays a mail server feeds
//! the bytes it reads from a TCP connection to a [`Decoder`] and takes
//! [`Event`]s out: a whole [`Command`], or a note that the client waits
//! for a continuation request. It writes each [`Response`]'s bytes back.
//! Which mailboxes and messages exist, and what each command does, is up
//! to world code. A world that plays a client does the reverse with a
//! [`ResponseDecoder`].
//!
//! Every reader checks lengths and nesting against the limits below,
//! because the agent can send any bytes it likes. A command that breaks
//! the grammar is an [`Error`] the server answers with `BAD`, and the
//! stream goes on. A line or literal past the limits breaks the stream
//! ([`Error::is_fatal`]), and a real server sends `* BYE` and closes it.
//!
//! ```
//! use fictionet::stdlib::imap::{Decoder, Event, Response, Status};
//!
//! let mut decoder = Decoder::new();
//! // The password comes as a synchronizing literal, so the client waits.
//! decoder.feed(b"a1 LOGIN alice {6}\r\n");
//! let Some(Ok(Event::Continue { size, .. })) = decoder.next_event() else { panic!() };
//! assert_eq!(size, 6);
//! assert_eq!(Response::continue_req("Ready").to_bytes(), b"+ Ready\r\n");
//! decoder.feed(b"secret\r\n");
//! let Some(Ok(Event::Command(command))) = decoder.next_event() else { panic!() };
//! assert_eq!(command.tag, "a1");
//! assert!(command.is("login"));
//! assert_eq!(command.args[0].as_bytes(), Some(&b"alice"[..]));
//! assert_eq!(command.args[1].as_bytes(), Some(&b"secret"[..]));
//! let reply = Response::tagged("a1", Status::Ok, "LOGIN completed");
//! assert_eq!(reply.to_bytes(), b"a1 OK LOGIN completed\r\n");
//! assert_eq!(decoder.next_event(), None);
//! ```

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
/// undone. Writers send longer strings as literals.
pub const MAX_QUOTED: usize = 8 * 1024;
/// How deeply parenthesized lists may nest.
pub const MAX_DEPTH: usize = 32;

/// One argument of a command or one item of a data response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A bare word, such as `INBOX`, `NIL`, `42`, `1:*`, `\Seen` or
    /// `BODY[HEADER.FIELDS (FROM)]`. A section in square brackets may hold
    /// spaces and parentheses. A reader rejects a `[` with no `]` after
    /// it on the line, such as `SELECT foo[`, though IMAP allows it. A
    /// writer sends a string that is not a word as a quoted string or a
    /// literal.
    Atom(String),
    /// A string in double quotes, with its escapes undone. A writer sends
    /// one that cannot be quoted (it holds CR or LF, is not UTF-8, or is
    /// longer than [`MAX_QUOTED`]) as a literal. A writer leaves out NUL
    /// bytes, which IMAP never carries.
    ///
    /// A reader takes UTF-8 with no NUL, CR or LF, as RFC 9051 allows.
    /// Other 8-bit bytes must come as a literal.
    Quoted(Vec<u8>),
    /// A string sent as a literal. It never holds NUL: a reader rejects
    /// one that does, and a writer leaves NUL bytes out. A writer cuts it
    /// to [`MAX_LITERAL`].
    Literal {
        /// The literal's bytes.
        data: Vec<u8>,
        /// Whether it was `{n+}`, which the client sends without waiting.
        /// Servers always write `{n}`, so this is false in responses.
        non_sync: bool,
    },
    /// A parenthesized list. A writer sends a list nested deeper than
    /// [`MAX_DEPTH`] as `NIL`.
    List(Vec<Value>),
}

impl Value {
    /// An atom.
    pub fn atom(s: &str) -> Value {
        Value::Atom(s.to_string())
    }

    /// A string, written quoted when it can be and as a literal otherwise.
    pub fn string(b: &[u8]) -> Value {
        Value::Quoted(b.to_vec())
    }

    /// A number, as an atom.
    pub fn number(n: u64) -> Value {
        Value::Atom(n.to_string())
    }

    /// `NIL`, the empty value.
    pub fn nil() -> Value {
        Value::atom("NIL")
    }

    /// The bytes of an atom, quoted string or literal. Check
    /// [`Value::is_nil`] first where `NIL` may come.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Atom(a) => Some(a.as_bytes()),
            Value::Quoted(b) | Value::Literal { data: b, .. } => Some(b),
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

    /// Reads one whole command: its lines, each ending in CRLF, with the
    /// bytes of each literal after the line that announces it, and
    /// nothing after the last line. A [`Decoder`] finds where commands
    /// end in a stream.
    pub fn parse(b: &[u8]) -> Result<Command, Error> {
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

    /// The command's bytes, for a world that plays a client. Literals go
    /// out with the rest, so a world that waits for continuation requests
    /// should use non-synchronizing ones. A byte the tag or name cannot
    /// hold is written as `x` or `X`, and an empty one as that letter.
    /// Arguments that would push the command past [`MAX_TEXT`] or
    /// [`MAX_MESSAGE`] are left out, from the first that does not fit.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = clean(&self.tag, tag_char, b'x', MAX_TEXT - 5);
        out.push(b' ');
        let name = clean(&self.name.to_ascii_uppercase(), atom_char, b'X', MAX_TEXT - 2 - out.len());
        out.extend_from_slice(&name);
        write_args(&mut out, &self.args, false, false);
        out.extend_from_slice(b"\r\n");
        out
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
        /// never tags `PREAUTH` or `BYE`.
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
    /// `* `. A writer quotes a first item that reads as a status word. One
    /// with no items is written `*`, which IMAP does not allow but readers
    /// here take.
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
    /// out quoted, as does `NIL`.
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

    /// Reads one whole response: one line ending in CRLF, or for a data
    /// response, its lines with each literal's bytes after the line that
    /// announces it. A [`ResponseDecoder`] finds where responses end in a
    /// stream.
    pub fn parse(b: &[u8]) -> Result<Response, Error> {
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

    /// The response's bytes. A status word is always followed by a
    /// space, as is a code, even with no text after it. CR, LF and NUL in
    /// text become spaces, and a `]` in a code becomes a space. Text that
    /// starts with a bracketed word and has no code reads back as a code.
    /// Text past [`MAX_TEXT`] is cut, and data items that would not fit
    /// are left out, from the first that does not.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Response::Continue { text } => {
                out.extend_from_slice(b"+ ");
                out.extend_from_slice(fit(&clean_text(text), MAX_TEXT - 4).as_bytes());
            }
            Response::Status { tag, status, code, text } => {
                match tag {
                    Some(t) if !matches!(status, Status::Preauth | Status::Bye) => {
                        out = clean(t, tag_char, b'x', MAX_TEXT - 12);
                    }
                    _ => out.push(b'*'),
                }
                out.push(b' ');
                out.extend_from_slice(status.as_str().as_bytes());
                // The grammar wants a space after the status word, and
                // after a code, even when no text follows.
                out.push(b' ');
                if let Some(code) = code {
                    let code: String = clean_text(code).chars().map(|c| if c == ']' { ' ' } else { c }).collect();
                    let code = fit(&code, (MAX_TEXT - 2 - out.len()).saturating_sub(3));
                    if !code.is_empty() {
                        out.push(b'[');
                        out.extend_from_slice(code.as_bytes());
                        out.extend_from_slice(b"] ");
                    }
                }
                let room = (MAX_TEXT - 2).saturating_sub(out.len());
                let text = clean_text(text);
                out.extend_from_slice(fit(&text, room).as_bytes());
            }
            Response::Data(values) => {
                out.push(b'*');
                write_args(&mut out, values, true, true);
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

/// Why bytes are not a command or response.
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
}

impl Error {
    /// Whether the stream cannot be read any further.
    pub fn is_fatal(&self) -> bool {
        match self {
            Error::Syntax { .. } => false,
            Error::LiteralTooLarge { waiting, .. } => !waiting,
            Error::TooLong => true,
        }
    }

    /// The tag of the command the error is about, if known.
    pub fn tag(&self) -> Option<&str> {
        match self {
            Error::Syntax { tag, .. } | Error::LiteralTooLarge { tag, .. } => tag.as_deref(),
            Error::TooLong => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Syntax { reason, .. } => write!(f, "IMAP syntax error: {reason}"),
            Error::LiteralTooLarge { size, .. } => write!(f, "literal of {size} bytes is too large"),
            Error::TooLong => write!(f, "IMAP command or response is too long"),
        }
    }
}

impl std::error::Error for Error {}

/// What a [`Decoder`] has for the world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A whole command.
    Command(Command),
    /// The client sent `{size}` and waits for a continuation request. The
    /// world sends one, such as [`Response::continue_req`], and keeps
    /// calling [`Decoder::next_event`]. Or it refuses with
    /// [`Decoder::refuse_literal`] and answers `tag NO`. The decoder asks
    /// for every line that ends in `{size}`, even one whose start breaks
    /// the grammar; that command is an [`Error::Syntax`] once it is whole.
    Continue {
        /// The tag of the command, if it has a well-formed one.
        tag: Option<String>,
        /// The literal's size, at most [`MAX_LITERAL`].
        size: usize,
    },
}

/// Splits the byte stream a client sends into commands. Feed it the bytes
/// a connection reads, in order, and take events out until it has none.
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    buf: Buf,
    framer: Framer,
    waiting: bool,
    failed: Option<Error>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the connection. After a fatal error they are
    /// dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            self.buf.feed(bytes);
        }
    }

    /// The next event, or `None` when the decoder needs more bytes. A
    /// syntax error, or a synchronizing literal too large to take, drops
    /// that command and the stream goes on. After a fatal error it keeps
    /// returning that error. A decoder holds at most one command's bytes,
    /// plus what one `feed` added.
    pub fn next_event(&mut self) -> Option<Result<Event, Error>> {
        if let Some(e) = &self.failed {
            return Some(Err(e.clone()));
        }
        loop {
            let step = self.framer.step(self.buf.data(), false);
            if !matches!(step, Step::More) {
                self.waiting = false;
            }
            match step {
                Step::More => return None,
                Step::Literal { non_sync: false, size } => {
                    self.waiting = true;
                    return Some(Ok(Event::Continue { tag: tag_of(self.buf.data()), size }));
                }
                Step::Literal { .. } => {}
                Step::Done(end) => {
                    let r = Command::parse(self.buf.data().get(..end).unwrap_or(&[]));
                    self.buf.consume(end);
                    return Some(r.map(Event::Command));
                }
                Step::TooLarge { size, non_sync, line_end } => {
                    let e = Error::LiteralTooLarge { tag: tag_of(self.buf.data()), size, waiting: !non_sync };
                    if non_sync {
                        return Some(Err(self.fail(e)));
                    }
                    self.buf.consume(line_end);
                    self.framer = Framer::default();
                    return Some(Err(e));
                }
                Step::TooLong => return Some(Err(self.fail(Error::TooLong))),
            }
        }
    }

    /// Drops the command whose literal the last [`Event::Continue`] was
    /// about, so the server can refuse it. Bytes the client sent after
    /// the line with `{n}` stay, and are read as commands. It returns
    /// whether there was such a command.
    pub fn refuse_literal(&mut self) -> bool {
        if !self.waiting {
            return false;
        }
        self.waiting = false;
        self.buf.consume(self.framer.line_start);
        self.framer = Framer::default();
        true
    }

    /// The next raw line, without its CRLF, for what is not a command:
    /// the client's answers during AUTHENTICATE, and `DONE` after IDLE.
    /// It returns `None` while part of a command is held, or until a whole
    /// line has come. A line longer than [`MAX_TEXT`] is fatal.
    pub fn next_line(&mut self) -> Option<Result<Vec<u8>, Error>> {
        if let Some(e) = &self.failed {
            return Some(Err(e.clone()));
        }
        if self.framer.text != 0 || self.framer.literal_end.is_some() {
            return None;
        }
        // With no command part held, the framer has looked for LF up to
        // `scan` and found none.
        let data = self.buf.data();
        let from = self.framer.scan.min(data.len());
        let end = data.len().min(MAX_TEXT);
        match data.get(from..end).and_then(|r| r.iter().position(|&x| x == b'\n')) {
            Some(p) => {
                let lf = from + p;
                let line = content(&data[..=lf]).to_vec();
                self.buf.consume(lf + 1);
                self.framer = Framer::default();
                Some(Ok(line))
            }
            None if data.len() < MAX_TEXT => {
                self.framer.scan = data.len();
                None
            }
            None => Some(Err(self.fail(Error::TooLong))),
        }
    }

    /// How many bytes are held, waiting for the rest of a command.
    pub fn buffered(&self) -> usize {
        self.buf.data().len()
    }

    fn fail(&mut self, e: Error) -> Error {
        self.failed = Some(e.clone());
        self.buf = Buf::default();
        self.framer = Framer::default();
        self.waiting = false;
        e
    }
}

/// Splits the byte stream a server sends into responses, for a world that
/// plays a client. Server literals never wait, so any literal too large
/// is fatal.
#[derive(Clone, Debug, Default)]
pub struct ResponseDecoder {
    buf: Buf,
    framer: Framer,
    failed: Option<Error>,
}

impl ResponseDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> ResponseDecoder {
        ResponseDecoder::default()
    }

    /// Adds bytes read from the connection. After a fatal error they are
    /// dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            self.buf.feed(bytes);
        }
    }

    /// The next response, or `None` when the decoder needs more bytes. A
    /// syntax error drops that response and the stream goes on. After a
    /// fatal error it keeps returning that error.
    pub fn next_response(&mut self) -> Option<Result<Response, Error>> {
        if let Some(e) = &self.failed {
            return Some(Err(e.clone()));
        }
        loop {
            match self.framer.step(self.buf.data(), true) {
                Step::More => return None,
                Step::Literal { .. } => {}
                Step::Done(end) => {
                    let r = Response::parse(self.buf.data().get(..end).unwrap_or(&[]));
                    self.buf.consume(end);
                    return Some(r);
                }
                Step::TooLarge { size, .. } => {
                    let e = Error::LiteralTooLarge { tag: tag_of(self.buf.data()), size, waiting: false };
                    return Some(Err(self.fail(e)));
                }
                Step::TooLong => return Some(Err(self.fail(Error::TooLong))),
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a response.
    pub fn buffered(&self) -> usize {
        self.buf.data().len()
    }

    fn fail(&mut self, e: Error) -> Error {
        self.failed = Some(e.clone());
        self.buf = Buf::default();
        self.framer = Framer::default();
        e
    }
}

/// Bytes read and not yet taken. Taking bytes moves a start index, and
/// the bytes are moved down only once as many are taken as are left, so
/// a stream of many short messages costs time in proportion to its
/// length.
#[derive(Clone, Debug, Default)]
struct Buf {
    bytes: Vec<u8>,
    start: usize,
}

impl Buf {
    fn data(&self) -> &[u8] {
        self.bytes.get(self.start..).unwrap_or(&[])
    }

    fn feed(&mut self, b: &[u8]) {
        self.bytes.extend_from_slice(b);
    }

    /// Takes the first `n` bytes of [`Buf::data`].
    fn consume(&mut self, n: usize) {
        self.start = self.start.saturating_add(n).min(self.bytes.len());
        if self.start == self.bytes.len() {
            self.bytes.clear();
            self.start = 0;
        } else if self.start >= self.bytes.len() - self.start {
            self.bytes.drain(..self.start);
            self.start = 0;
        }
    }
}

/// What a framer found in the bytes it was given.
enum Step {
    /// The message is not whole yet.
    More,
    /// A literal was announced, and the framer now waits for its bytes.
    Literal { non_sync: bool, size: usize },
    /// A whole message ends at this index.
    Done(usize),
    /// A literal too large to take, announced by the line that ends at
    /// `line_end`.
    TooLarge { size: u64, non_sync: bool, line_end: usize },
    /// The message is too long.
    TooLong,
}

/// Finds where one message ends in a buffer that starts with it. It keeps
/// its place between calls, so bytes are scanned once.
#[derive(Clone, Debug, Default)]
struct Framer {
    /// Where the current line starts.
    line_start: usize,
    /// Where to go on looking for the line's LF.
    scan: usize,
    /// Bytes of the lines read so far.
    text: usize,
    /// Bytes of the literals announced so far.
    lits: usize,
    /// Where the literal being waited for ends.
    literal_end: Option<usize>,
    /// For responses: what the first line said the response is.
    kind: Option<Kind>,
}

impl Framer {
    fn step(&mut self, b: &[u8], response: bool) -> Step {
        if let Some(end) = self.literal_end {
            if b.len() < end {
                return Step::More;
            }
            self.literal_end = None;
            self.line_start = end;
            self.scan = end;
        }
        let Some(p) = b.get(self.scan..).and_then(|r| r.iter().position(|&x| x == b'\n')) else {
            let partial = b.len().saturating_sub(self.line_start);
            if self.text.saturating_add(partial).saturating_add(1) > MAX_TEXT {
                return Step::TooLong;
            }
            self.scan = b.len();
            return Step::More;
        };
        let lf = self.scan + p;
        let line = &b[self.line_start.min(lf)..=lf];
        self.text = self.text.saturating_add(line.len());
        if self.text > MAX_TEXT || self.text.saturating_add(self.lits) > MAX_MESSAGE {
            return Step::TooLong;
        }
        let literals = !response || *self.kind.get_or_insert_with(|| classify(content(line))) == Kind::Data;
        if literals && let Some((size, non_sync)) = marker(line, !response) {
            let used = (self.text.saturating_add(self.lits)) as u64;
            if size > MAX_LITERAL as u64 || used.saturating_add(size) > MAX_MESSAGE as u64 {
                return Step::TooLarge { size, non_sync, line_end: lf + 1 };
            }
            let n = size as usize;
            self.lits += n;
            self.line_start = lf + 1;
            self.scan = lf + 1;
            self.literal_end = Some(lf.saturating_add(1).saturating_add(n));
            return Step::Literal { non_sync, size: n };
        }
        *self = Framer::default();
        Step::Done(lf + 1)
    }
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

/// A byte an argument word may hold outside square brackets. It is wider
/// than `ATOM-CHAR`, to take flags, sequence sets and list patterns.
fn word_char(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && !matches!(b, b'(' | b')' | b'{' | b'"' | b'[')
}

/// The length of the word at the start of `b`. A `[` opens a section
/// that runs to the next `]` and may hold spaces.
fn word_len(b: &[u8]) -> Result<usize, &'static str> {
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'[' {
            let close = b[i + 1..].iter().position(|&x| x == b']' || !(0x20..=0x7e).contains(&x));
            match close.map(|p| i + 1 + p) {
                Some(j) if b[j] == b']' => i = j + 1,
                _ => return Err("an atom has [ without ]"),
            }
        } else if word_char(c) {
            i += 1;
        } else {
            break;
        }
    }
    Ok(i)
}

/// Whether `s` is written as an atom.
fn atom_ok(s: &[u8]) -> bool {
    !s.is_empty() && word_len(s) == Ok(s.len())
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
/// Lists are read with a stack, not by recursion.
fn parse_values(c: &mut Cursor<'_>, allow_non_sync: bool) -> Result<Vec<Value>, Fault> {
    let mut levels: Vec<Vec<Value>> = vec![Vec::new()];
    loop {
        if levels.len() == 1 {
            if c.at_end() {
                c.i += 2;
                break;
            }
            if c.peek() != Some(b' ') {
                return Err(Fault::Syntax("expected a space or the end of the line"));
            }
            c.i += 1;
        } else {
            if c.peek() == Some(b')') {
                c.i += 1;
                let list = levels.pop().unwrap_or_default();
                if let Some(parent) = levels.last_mut() {
                    parent.push(Value::List(list));
                }
                continue;
            }
            if levels.last().is_some_and(|l| !l.is_empty()) {
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
            Some(b'{') => parse_literal(c, allow_non_sync)?,
            _ => {
                let rest = c.b.get(c.i..).unwrap_or(&[]);
                let n = word_len(rest).map_err(Fault::Syntax)?;
                if n == 0 {
                    return Err(Fault::Syntax("expected a value"));
                }
                c.i += n;
                Value::Atom(ascii(&rest[..n]))
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

fn parse_literal(c: &mut Cursor<'_>, allow_non_sync: bool) -> Result<Value, Fault> {
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
    if data.contains(&0) {
        return Err(Fault::Syntax("a literal holds NUL"));
    }
    c.i += n;
    c.lits += n;
    Ok(Value::Literal { data: data.to_vec(), non_sync })
}

/// `s` as bytes, with each byte `ok` refuses written as `fill`, cut to
/// `max` bytes, and `fill` alone if empty.
fn clean(s: &str, ok: fn(u8) -> bool, fill: u8, max: usize) -> Vec<u8> {
    let mut v: Vec<u8> = s.bytes().take(max).map(|b| if ok(b) { b } else { fill }).collect();
    if v.is_empty() {
        v.push(fill);
    }
    v
}

/// Text with NUL, CR and LF made spaces.
fn clean_text(s: &str) -> String {
    s.chars().map(|c| if matches!(c, '\0' | '\r' | '\n') { ' ' } else { c }).collect()
}

/// The longest start of `s` that fits in `max` bytes.
fn fit(s: &str, max: usize) -> &str {
    let mut n = max.min(s.len());
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    &s[..n]
}

/// Writes ` value` for each value that fits. `out` holds only text so
/// far; a CRLF will follow.
fn write_args(out: &mut Vec<u8>, args: &[Value], server: bool, data: bool) {
    let mut text = out.len() + 2;
    let mut total = text;
    let mut tmp = Vec::new();
    for (i, v) in args.iter().enumerate() {
        tmp.clear();
        tmp.push(b' ');
        let lit = match v {
            // A data response that starts with a status word would read
            // as a status line.
            Value::Atom(a) if data && i == 0 && Status::from_word(a.as_bytes()).is_some() => {
                write_string(a.as_bytes(), &mut tmp, server)
            }
            _ => write_value(v, &mut tmp, server),
        };
        let t = tmp.len() - lit;
        if text + t > MAX_TEXT || total + tmp.len() > MAX_MESSAGE {
            break;
        }
        text += t;
        total += tmp.len();
        out.extend_from_slice(&tmp);
    }
}

/// Writes one value, with a stack for lists. It returns how many literal
/// bytes it wrote.
fn write_value(v: &Value, out: &mut Vec<u8>, server: bool) -> usize {
    let mut lit = 0;
    let mut stack: Vec<(std::slice::Iter<'_, Value>, bool)> = Vec::new();
    let mut next = Some(v);
    loop {
        if let Some(v) = next.take() {
            match v {
                Value::List(items) if stack.len() < MAX_DEPTH => {
                    out.push(b'(');
                    stack.push((items.iter(), true));
                }
                Value::List(_) => out.extend_from_slice(b"NIL"),
                Value::Atom(a) if atom_ok(a.as_bytes()) => out.extend_from_slice(a.as_bytes()),
                Value::Atom(a) => lit += write_string(a.as_bytes(), out, server),
                Value::Quoted(q) => lit += write_string(q, out, server),
                Value::Literal { data, non_sync } => lit += write_literal(data, *non_sync && !server, out),
            }
        }
        let Some((iter, first)) = stack.last_mut() else { break };
        match iter.next() {
            Some(item) => {
                if !*first {
                    out.push(b' ');
                }
                *first = false;
                next = Some(item);
            }
            None => {
                out.push(b')');
                stack.pop();
            }
        }
    }
    lit
}

/// `s` without its NUL bytes, which IMAP never carries.
fn drop_nul(s: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if s.contains(&0) { s.iter().copied().filter(|&b| b != 0).collect::<Vec<u8>>().into() } else { s.into() }
}

/// Writes a string quoted if it can be, and as a literal if not. A
/// quoted string holds UTF-8 with no CR or LF. It returns how many
/// literal bytes it wrote.
fn write_string(s: &[u8], out: &mut Vec<u8>, server: bool) -> usize {
    let s = drop_nul(s);
    let s = &s[..];
    if s.len() <= MAX_QUOTED && !s.iter().any(|&b| matches!(b, b'\r' | b'\n')) && std::str::from_utf8(s).is_ok() {
        out.push(b'"');
        for &b in s {
            if b == b'"' || b == b'\\' {
                out.push(b'\\');
            }
            out.push(b);
        }
        out.push(b'"');
        0
    } else {
        write_literal(s, !server, out)
    }
}

fn write_literal(data: &[u8], non_sync: bool, out: &mut Vec<u8>) -> usize {
    let data = drop_nul(data);
    let data = &data[..data.len().min(MAX_LITERAL)];
    out.push(b'{');
    out.extend_from_slice(data.len().to_string().as_bytes());
    if non_sync {
        out.push(b'+');
    }
    out.extend_from_slice(b"}\r\n");
    out.extend_from_slice(data);
    data.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(b: &[u8]) -> Command {
        Command::parse(b).unwrap()
    }

    fn atoms(v: &[&str]) -> Vec<Value> {
        v.iter().map(|a| Value::atom(a)).collect()
    }

    fn syntax(b: &[u8]) -> bool {
        matches!(Command::parse(b), Err(Error::Syntax { .. }))
    }

    /// Every event a decoder gives for `stream`, fed whole or a byte at a
    /// time, with continuation requests always granted.
    fn events(stream: &[u8], bytewise: bool) -> Vec<Result<Event, Error>> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = if bytewise { stream.chunks(1).collect() } else { vec![stream] };
        for chunk in chunks {
            d.feed(chunk);
            while let Some(e) = d.next_event() {
                let fatal = matches!(&e, Err(e) if e.is_fatal());
                out.push(e);
                if fatal {
                    return out;
                }
            }
        }
        out
    }

    fn responses(stream: &[u8], bytewise: bool) -> Vec<Result<Response, Error>> {
        let mut d = ResponseDecoder::new();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = if bytewise { stream.chunks(1).collect() } else { vec![stream] };
        for chunk in chunks {
            d.feed(chunk);
            while let Some(r) = d.next_response() {
                let fatal = matches!(&r, Err(e) if e.is_fatal());
                out.push(r);
                if fatal {
                    return out;
                }
            }
        }
        out
    }

    // Examples from RFC 9051 and RFC 3501, section 6 and 7.

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
    fn writers() {
        assert_eq!(Response::exists(23).to_bytes(), b"* 23 EXISTS\r\n");
        assert_eq!(Response::recent(1).to_bytes(), b"* 1 RECENT\r\n");
        assert_eq!(Response::expunge(3).to_bytes(), b"* 3 EXPUNGE\r\n");
        assert_eq!(Response::greeting("ready").to_bytes(), b"* OK ready\r\n");
        let r = Response::tagged("a2", Status::Ok, "done").with_code("READ-ONLY");
        assert_eq!(r.to_bytes(), b"a2 OK [READ-ONLY] done\r\n");
        assert_eq!(Response::tagged("a3", Status::No, "").to_bytes(), b"a3 NO \r\n");
        assert_eq!(Response::continue_req("").to_bytes(), b"+ \r\n");
        assert_eq!(Response::list(&[], None, b"INBOX").to_bytes(), b"* LIST () NIL INBOX\r\n");
        assert_eq!(
            Response::list(&["\\HasNoChildren"], Some('.'), b"Sent Items").to_bytes(),
            b"* LIST (\\HasNoChildren) \".\" \"Sent Items\"\r\n"
        );
        let f = Response::fetch(1, vec![Value::atom("BODY[]"), Value::string(b"a\r\nb")]);
        assert_eq!(f.to_bytes(), b"* 1 FETCH (BODY[] {4}\r\na\r\nb)\r\n");
        let c = Command::new(
            "t1",
            "append",
            vec![Value::atom("INBOX"), Value::Literal { data: b"hi".to_vec(), non_sync: true }],
        );
        assert_eq!(c.to_bytes(), b"t1 APPEND INBOX {2+}\r\nhi\r\n");
        // An atom that is not a word goes out quoted.
        let c = Command::new("t2", "SELECT", vec![Value::atom("My Box"), Value::atom("")]);
        assert_eq!(c.to_bytes(), b"t2 SELECT \"My Box\" \"\"\r\n");
        // Bad tags and names are mended.
        assert_eq!(Command::new("a b", "", vec![]).to_bytes(), b"axb X\r\n");
        assert_eq!(Command::new("", "no op", vec![]).to_bytes(), b"x NOXOP\r\n");
        // PREAUTH and BYE are never tagged.
        assert_eq!(Response::tagged("a", Status::Bye, "x").to_bytes(), b"* BYE x\r\n");
        // Text is kept to one line.
        assert_eq!(Response::greeting("a\r\nb").to_bytes(), b"* OK a  b\r\n");
        let r = Response::untagged(Status::Ok, "x").with_code("A]B");
        assert_eq!(r.to_bytes(), b"* OK [A B] x\r\n");
        // A data response that starts with a status word is quoted.
        let r = Response::Data(atoms(&["OK", "x"]));
        assert_eq!(r.to_bytes(), b"* \"OK\" x\r\n");
        assert_eq!(Response::Data(vec![]).to_bytes(), b"*\r\n");
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
            assert_eq!(c.to_bytes(), b, "{}", String::from_utf8_lossy(b));
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
            assert_eq!(Response::parse(b).unwrap().to_bytes(), b, "{}", String::from_utf8_lossy(b));
        }
    }

    #[test]
    fn command_errors() {
        let tagged = |b: &[u8], reason: &'static str| {
            assert_eq!(Command::parse(b), Err(Error::Syntax { tag: Some("a".into()), reason }));
        };
        assert_eq!(Command::parse(b"\r\n"), Err(Error::Syntax { tag: None, reason: "a command starts with a tag" }));
        assert_eq!(Command::parse(b"a\r\n"), Err(Error::Syntax { tag: None, reason: "a space must follow the tag" }));
        tagged(b"a \r\n", "a command name must follow the tag");
        tagged(b"a NOOP \r\n", "expected a value");
        tagged(b"a NOOP\n", "expected a space or the end of the line");
        tagged(b"a NOOP\r\nb NOOP\r\n", "expected a space or the end of the line");
        tagged(b"a X (b\r\n", "expected a space or ) in a list");
        tagged(b"a X (b)c\r\n", "expected a space or the end of the line");
        tagged(b"a X ( b)\r\n", "expected a value");
        tagged(b"a X \"ab\r\n", "a quoted string holds NUL, CR or LF");
        tagged(b"a X \"ab", "a quoted string has no closing quote");
        tagged(b"a X \"a\\b\"\r\n", "only \\\" and \\\\ may be escaped");
        tagged(b"a X {}\r\n", "a literal's size must follow {");
        tagged(b"a X {3}x\r\n", "a literal's size must end with } and CRLF");
        tagged(b"a X {3}\r\nab", "a literal is cut short");
        tagged(b"a X B[1\r\n", "an atom has [ without ]");
        let mut deep = b"a X ".to_vec();
        deep.extend(std::iter::repeat_n(b'(', MAX_DEPTH + 1));
        deep.extend(std::iter::repeat_n(b')', MAX_DEPTH + 1));
        deep.extend_from_slice(b"\r\n");
        tagged(&deep, "lists nest too deeply");
        let mut ok = b"a X ".to_vec();
        ok.extend(std::iter::repeat_n(b'(', MAX_DEPTH));
        ok.extend(std::iter::repeat_n(b')', MAX_DEPTH));
        ok.extend_from_slice(b"\r\n");
        assert_eq!(cmd(&ok).to_bytes(), ok);
        let mut long = b"a X \"".to_vec();
        long.extend(std::iter::repeat_n(b'q', MAX_QUOTED + 1));
        long.extend_from_slice(b"\"\r\n");
        tagged(&long, "a quoted string is too long");
        assert_eq!(
            Command::parse(b"a X {99999999999999999999999}\r\n"),
            Err(Error::LiteralTooLarge { tag: Some("a".into()), size: u64::MAX, waiting: true })
        );
        assert_eq!(
            Command::parse(b"a X {1048577+}\r\n"),
            Err(Error::LiteralTooLarge { tag: Some("a".into()), size: 1048577, waiting: false })
        );
        let mut text = b"a X ".to_vec();
        text.extend(std::iter::repeat_n(b'z', MAX_TEXT));
        text.extend_from_slice(b"\r\n");
        assert_eq!(Command::parse(&text), Err(Error::TooLong));
        assert_eq!(Command::parse(&vec![b'a'; MAX_MESSAGE + 1]), Err(Error::TooLong));
        assert!(syntax(b"+ X\r\n"));
        assert!(syntax(b"* X\r\n"));
    }

    #[test]
    fn response_errors() {
        let bad = |b: &[u8]| {
            assert!(matches!(Response::parse(b), Err(Error::Syntax { .. })), "{}", String::from_utf8_lossy(b))
        };
        bad(b"");
        bad(b"a FOO\r\n");
        bad(b"* OK x");
        bad(b"* OK x\n");
        bad(b"* OK \0\r\n");
        bad(b"* OK \xff\r\n");
        bad(b"* OK [\xff] x\r\n");
        bad(b"* OK x\r\ny\r\n");
        bad(b"+x\r\n");
        bad(b"a BYE x\r\n");
        bad(b"a PREAUTH x\r\n");
        bad(b"* 1 FETCH (BODY[] {2+}\r\nhi)\r\n");
        bad(b"*1 EXISTS\r\n");
        let mut long = b"* OK ".to_vec();
        long.extend(std::iter::repeat_n(b'z', MAX_TEXT));
        long.extend_from_slice(b"\r\n");
        assert_eq!(Response::parse(&long), Err(Error::TooLong));
        assert_eq!(Response::parse(&vec![b'*'; MAX_MESSAGE + 1]), Err(Error::TooLong));
        assert_eq!(
            Response::parse(b"* 1 FETCH (BODY[] {2000000}\r\n"),
            Err(Error::LiteralTooLarge { tag: None, size: 2000000, waiting: false })
        );
    }

    #[test]
    fn every_truncated_prefix() {
        let commands: &[&[u8]] = &[
            b"A003 APPEND saved-messages (\\Seen) {12}\r\nHello Joe!\r\n\r\n",
            b"a LOGIN {5+}\r\nalice \"p\\\"w\\\\\"\r\n",
            b"A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])\r\n",
        ];
        for &b in commands {
            for n in 0..b.len() {
                assert!(Command::parse(&b[..n]).is_err(), "{n}");
                let ev = events(&b[..n], false);
                assert!(ev.iter().all(|e| matches!(e, Ok(Event::Continue { .. }))), "{n}: {ev:?}");
                let mut d = Decoder::new();
                d.feed(&b[..n]);
                while let Some(e) = d.next_event() {
                    assert!(matches!(e, Ok(Event::Continue { .. })));
                }
                assert_eq!(d.buffered(), n);
            }
        }
        let streams: &[&[u8]] = &[
            b"* 12 FETCH (FLAGS (\\Seen) BODY[HEADER] {13}\r\nSubject: hi\r\n)\r\n",
            b"A142 OK [READ-WRITE] SELECT completed\r\n",
            b"+ Ready\r\n",
        ];
        for &b in streams {
            for n in 0..b.len() {
                assert!(Response::parse(&b[..n]).is_err(), "{n}");
                assert!(responses(&b[..n], false).is_empty(), "{n}");
            }
        }
    }

    #[test]
    fn decoder_and_continuations() {
        let stream = b"a1 NOOP\r\na2 LOGIN {5}\r\nalice {3+}\r\npwd\r\na3 X\r\n";
        let want = vec![
            Ok(Event::Command(Command::new("a1", "NOOP", vec![]))),
            Ok(Event::Continue { tag: Some("a2".into()), size: 5 }),
            Ok(Event::Command(Command::new(
                "a2",
                "LOGIN",
                vec![
                    Value::Literal { data: b"alice".to_vec(), non_sync: false },
                    Value::Literal { data: b"pwd".to_vec(), non_sync: true },
                ],
            ))),
            Ok(Event::Command(Command::new("a3", "X", vec![]))),
        ];
        assert_eq!(events(stream, false), want);
        assert_eq!(events(stream, true), want);

        // A refused literal drops the command; what follows is read.
        let mut d = Decoder::new();
        d.feed(b"b1 APPEND INBOX {10}\r\n");
        assert!(matches!(d.next_event(), Some(Ok(Event::Continue { size: 10, .. }))));
        assert!(d.refuse_literal());
        assert!(!d.refuse_literal());
        d.feed(b"b2 NOOP\r\n");
        assert_eq!(d.next_event(), Some(Ok(Event::Command(Command::new("b2", "NOOP", vec![])))));
        assert_eq!(d.buffered(), 0);

        // A synchronizing literal too large is refused, and the stream
        // goes on.
        let mut d = Decoder::new();
        d.feed(b"c1 APPEND INBOX {2000000}\r\nc2 NOOP\r\n");
        let e = d.next_event().unwrap().unwrap_err();
        assert_eq!(e, Error::LiteralTooLarge { tag: Some("c1".into()), size: 2000000, waiting: true });
        assert!(!e.is_fatal());
        assert_eq!(e.tag(), Some("c1"));
        assert_eq!(d.next_event(), Some(Ok(Event::Command(Command::new("c2", "NOOP", vec![])))));

        // A non-synchronizing one breaks the stream.
        let mut d = Decoder::new();
        d.feed(b"c1 APPEND INBOX {2000000+}\r\nc2 NOOP\r\n");
        let e = d.next_event().unwrap().unwrap_err();
        assert!(e.is_fatal());
        d.feed(b"c3 NOOP\r\n");
        assert_eq!(d.next_event(), Some(Err(e.clone())));
        assert_eq!(d.next_line(), Some(Err(e)));
        assert_eq!(d.buffered(), 0);

        // Literals that add up past MAX_MESSAGE.
        let mut d = Decoder::new();
        let mut s = Vec::new();
        for _ in 0..4 {
            s.extend_from_slice(b"d X {1048576+}\r\n");
            s.extend(std::iter::repeat_n(b'.', MAX_LITERAL));
            s.extend_from_slice(b" ");
        }
        s.extend_from_slice(b"\r\n");
        d.feed(&s);
        assert!(matches!(d.next_event(), Some(Err(Error::LiteralTooLarge { waiting: false, .. }))));

        // A syntax error is not fatal.
        let mut d = Decoder::new();
        d.feed(b"e1 X (\r\ne2 NOOP\r\n");
        let e = d.next_event().unwrap().unwrap_err();
        assert_eq!(e.tag(), Some("e1"));
        assert!(!e.is_fatal());
        assert!(d.next_event().unwrap().is_ok());

        // A line that never ends is fatal once it passes MAX_TEXT.
        let mut d = Decoder::new();
        d.feed(&vec![b'a'; MAX_TEXT - 1]);
        assert_eq!(d.next_event(), None);
        d.feed(b"a");
        assert_eq!(d.next_event(), Some(Err(Error::TooLong)));
    }

    #[test]
    fn raw_lines() {
        let mut d = Decoder::new();
        d.feed(b"a AUTHENTICATE PLAIN\r\n");
        assert!(matches!(d.next_event(), Some(Ok(Event::Command(_)))));
        d.feed(b"AGFsaWNlAHNlY3JldA==\r\nDONE\nb NOOP\r\n");
        assert_eq!(d.next_line(), Some(Ok(b"AGFsaWNlAHNlY3JldA==".to_vec())));
        assert_eq!(d.next_line(), Some(Ok(b"DONE".to_vec())));
        assert!(matches!(d.next_event(), Some(Ok(Event::Command(_)))));
        assert_eq!(d.next_line(), None);
        // Not while a command is half read.
        d.feed(b"c X {3}\r\n");
        assert!(matches!(d.next_event(), Some(Ok(Event::Continue { .. }))));
        assert_eq!(d.next_line(), None);
        let mut d = Decoder::new();
        d.feed(&vec![b'a'; MAX_TEXT]);
        assert_eq!(d.next_line(), Some(Err(Error::TooLong)));
    }

    #[test]
    fn response_decoder() {
        let stream = b"* OK hi {3}\r\n* 1 FETCH (BODY[] {3}\r\nabc)\r\n+ go\r\nt OK done\r\n";
        let want = vec![
            Ok(Response::greeting("hi {3}")),
            Ok(Response::fetch(
                1,
                vec![Value::atom("BODY[]"), Value::Literal { data: b"abc".to_vec(), non_sync: false }],
            )),
            Ok(Response::continue_req("go")),
            Ok(Response::tagged("t", Status::Ok, "done")),
        ];
        assert_eq!(responses(stream, false), want);
        assert_eq!(responses(stream, true), want);
        let r = responses(b"* 1 FETCH (BODY[] {2000000}\r\n", false);
        assert_eq!(r, vec![Err(Error::LiteralTooLarge { tag: None, size: 2000000, waiting: false })]);
        let mut d = ResponseDecoder::new();
        d.feed(b"* 1 FETCH (BODY[] {3+}\r\nabc)\r\n");
        assert!(matches!(d.next_response(), Some(Err(Error::Syntax { .. }))));
        assert!(matches!(d.next_response(), Some(Err(Error::Syntax { .. }))));
        assert_eq!(d.next_response(), None);
        assert_eq!(d.buffered(), 0);
        let mut d = ResponseDecoder::new();
        d.feed(&vec![b'*'; MAX_TEXT + 1]);
        assert_eq!(d.next_response(), Some(Err(Error::TooLong)));
        d.feed(b"* OK\r\n");
        assert_eq!(d.next_response(), Some(Err(Error::TooLong)));
    }

    #[test]
    fn writers_cap_what_they_write() {
        // A literal past MAX_LITERAL is cut.
        let big = Value::Literal { data: vec![b'x'; MAX_LITERAL + 10], non_sync: true };
        let b = Command::new("a", "APPEND", vec![big]).to_bytes();
        let c = cmd(&b);
        assert_eq!(c.args[0].as_bytes().map(<[u8]>::len), Some(MAX_LITERAL));
        // Literals past MAX_MESSAGE are left out.
        let lit = Value::Literal { data: vec![b'y'; MAX_LITERAL], non_sync: false };
        let r = Response::Data(vec![lit; 6]);
        let b = r.to_bytes();
        assert!(b.len() <= MAX_MESSAGE);
        let Response::Data(v) = Response::parse(&b).unwrap() else { panic!() };
        assert_eq!(v.len(), 3);
        assert_eq!(responses(&b, false).len(), 1);
        // Text past MAX_TEXT is left out.
        let c = Command::new("a", "X", vec![Value::atom(&"z".repeat(1000)); 100]);
        let b = c.to_bytes();
        assert!(b.len() <= MAX_TEXT);
        assert_eq!(cmd(&b).args.len(), 65);
        let r = Response::greeting(&"é".repeat(MAX_TEXT)).with_code(&"c".repeat(MAX_TEXT));
        assert!(r.to_bytes().len() <= MAX_TEXT);
        assert!(Response::parse(&r.to_bytes()).is_ok());
        let r = Response::continue_req(&"é".repeat(MAX_TEXT));
        assert!(Response::parse(&r.to_bytes()).is_ok());
        let c = Command::new(&"t".repeat(MAX_TEXT * 2), &"n".repeat(MAX_TEXT), vec![Value::nil()]);
        assert!(Command::parse(&c.to_bytes()).is_ok());
        // Deep lists become NIL past MAX_DEPTH.
        let mut v = Value::nil();
        for _ in 0..MAX_DEPTH + 5 {
            v = Value::List(vec![v]);
        }
        let b = Command::new("a", "X", vec![v]).to_bytes();
        let mut depth = 0;
        let mut item = &cmd(&b).args[0];
        while let Value::List(l) = item {
            depth += 1;
            item = &l[0];
        }
        assert_eq!(depth, MAX_DEPTH);
        assert!(item.is_nil());
        // A long quoted string goes out as a literal.
        let b = Command::new("a", "X", vec![Value::string(&vec![b'q'; MAX_QUOTED + 1])]).to_bytes();
        assert!(matches!(cmd(&b).args[0], Value::Literal { non_sync: true, .. }));
    }

    // Problems found against the RFC 9051 grammar (section 9).

    #[test]
    fn literals_never_hold_nul() {
        // literal = "{" number64 ["+"] "}" CRLF *CHAR8, and CHAR8 is
        // %x01-ff: NUL is not allowed anywhere outside literal8.
        assert_eq!(
            Command::parse(b"a X {3}\r\na\0b\r\n"),
            Err(Error::Syntax { tag: Some("a".into()), reason: "a literal holds NUL" })
        );
        assert!(matches!(Response::parse(b"* 1 FETCH (BODY[] {1}\r\n\0)\r\n"), Err(Error::Syntax { .. })));
        // The stream goes on after it.
        let ev = events(b"a X {1+}\r\n\0\r\nb NOOP\r\n", true);
        assert!(matches!(ev[0], Err(Error::Syntax { .. })));
        assert_eq!(ev[1], Ok(Event::Command(Command::new("b", "NOOP", vec![]))));
        // Writers leave NUL out.
        let c = Command::new(
            "a",
            "X",
            vec![Value::string(b"a\0b"), Value::Literal { data: b"\0c\0".to_vec(), non_sync: true }],
        );
        assert_eq!(c.to_bytes(), b"a X \"ab\" {1+}\r\nc\r\n");
        let r = Response::fetch(1, vec![Value::atom("BODY[]"), Value::string(b"x\r\n\0")]);
        assert_eq!(r.to_bytes(), b"* 1 FETCH (BODY[] {3}\r\nx\r\n)\r\n");
    }

    #[test]
    fn status_word_is_followed_by_a_space() {
        // resp-cond-state = ("OK" / "NO" / "BAD") SP resp-text, and
        // resp-text = ["[" resp-text-code "]" SP] [text].
        assert_eq!(Response::tagged("a3", Status::No, "").to_bytes(), b"a3 NO \r\n");
        assert_eq!(Response::bye("").to_bytes(), b"* BYE \r\n");
        let r = Response::untagged(Status::No, "").with_code("ALERT");
        assert_eq!(r.to_bytes(), b"* NO [ALERT] \r\n");
        assert_eq!(Response::parse(&r.to_bytes()), Ok(r));
        let r = Response::tagged("a", Status::Ok, "");
        assert_eq!(Response::parse(&r.to_bytes()), Ok(r));
    }

    #[test]
    fn quoted_strings_are_utf8() {
        // QUOTED-CHAR is 7-bit TEXT-CHAR or a whole UTF-8 character, so
        // other 8-bit bytes must go as a literal.
        let c = Command::new("a", "X", vec![Value::string(b"\xff"), Value::string("é".as_bytes())]);
        assert_eq!(c.to_bytes(), b"a X {1+}\r\n\xff \"\xc3\xa9\"\r\n");
        let r = Response::Data(vec![Value::atom("X"), Value::string(b"a\x80")]);
        assert_eq!(r.to_bytes(), b"* X {2}\r\na\x80\r\n");
    }

    #[test]
    fn list_writes_a_valid_mailbox_and_delimiter() {
        // mailbox = "INBOX" / astring: list wildcards and \ are not
        // ASTRING-CHARs, so such names go quoted.
        assert_eq!(Response::list(&[], Some('/'), b"a%b").to_bytes(), b"* LIST () \"/\" \"a%b\"\r\n");
        assert_eq!(Response::list(&[], Some('/'), b"a\\b").to_bytes(), b"* LIST () \"/\" \"a\\\\b\"\r\n");
        assert_eq!(Response::list(&[], Some('/'), b"x*").to_bytes(), b"* LIST () \"/\" \"x*\"\r\n");
        assert_eq!(Response::list(&[], Some('/'), b"[Gmail]/All").to_bytes(), b"* LIST () \"/\" [Gmail]/All\r\n");
        // The delimiter is DQUOTE QUOTED-CHAR DQUOTE or NIL, never a
        // literal.
        assert_eq!(Response::list(&[], Some('\n'), b"INBOX").to_bytes(), b"* LIST () NIL INBOX\r\n");
        assert_eq!(Response::list(&[], Some('\0'), b"INBOX").to_bytes(), b"* LIST () NIL INBOX\r\n");
    }

    // Problems found in the hardening review.

    #[test]
    fn quoted_strings_must_be_utf8_to_read() {
        // QUOTED-CHAR holds only 7-bit text or whole UTF-8 characters.
        // Taking other bytes broke the round trip: they were written back
        // as a literal.
        assert_eq!(
            Command::parse(b"a X \"\xff\"\r\n"),
            Err(Error::Syntax { tag: Some("a".into()), reason: "a quoted string is not UTF-8" })
        );
        assert!(matches!(Response::parse(b"* X \"a\xc3\"\r\n"), Err(Error::Syntax { .. })));
        let c = cmd("a X \"é\"\r\n".as_bytes());
        assert_eq!(c.args[0].as_str(), Some("é"));
        assert_eq!(cmd(&c.to_bytes()), c);
    }

    #[test]
    fn many_messages_in_one_feed() {
        // Taking each message from the front of the buffer used to move
        // the rest down, which made one large feed cost quadratic time.
        let n = 200_000;
        let stream = b"a NOOP\r\n".repeat(n);
        let mut d = Decoder::new();
        d.feed(&stream);
        let mut got = 0;
        while let Some(e) = d.next_event() {
            assert_eq!(e, Ok(Event::Command(Command::new("a", "NOOP", vec![]))));
            got += 1;
        }
        assert_eq!(got, n);
        assert_eq!(d.buffered(), 0);
        let mut d = ResponseDecoder::new();
        d.feed(&b"* 1 EXISTS\r\n".repeat(n));
        let mut got = 0;
        while let Some(r) = d.next_response() {
            assert_eq!(r, Ok(Response::exists(1)));
            got += 1;
        }
        assert_eq!(got, n);
        let mut d = Decoder::new();
        d.feed(&b"x\r\n".repeat(n));
        let mut got = 0;
        while let Some(l) = d.next_line() {
            assert_eq!(l, Ok(b"x".to_vec()));
            got += 1;
        }
        assert_eq!(got, n);
        // Bytes left after a partial take stay in order.
        let mut d = Decoder::new();
        d.feed(b"a NOOP\r\nb NO");
        assert!(d.next_event().is_some());
        d.feed(b"OP\r\n");
        assert_eq!(d.next_event(), Some(Ok(Event::Command(Command::new("b", "NOOP", vec![])))));
    }

    #[test]
    fn raw_lines_a_byte_at_a_time() {
        // next_line goes on looking where it stopped, and still finds
        // the end of a line fed one byte at a time.
        let mut d = Decoder::new();
        let mut lines = Vec::new();
        for &b in b"abc\r\nDONE\nx NOOP\r\n" {
            d.feed(&[b]);
            if let Some(l) = d.next_line() {
                lines.push(l.unwrap());
            }
        }
        assert_eq!(lines, vec![b"abc".to_vec(), b"DONE".to_vec(), b"x NOOP".to_vec()]);
        let mut d = Decoder::new();
        for _ in 0..MAX_TEXT - 1 {
            d.feed(b"a");
            assert_eq!(d.next_line(), None);
        }
        d.feed(b"a");
        assert_eq!(d.next_line(), Some(Err(Error::TooLong)));
    }

    #[test]
    fn list_quotes_a_mailbox_named_nil() {
        // An atom NIL reads as the empty value.
        assert_eq!(Response::list(&[], Some('/'), b"NIL").to_bytes(), b"* LIST () \"/\" \"NIL\"\r\n");
        assert_eq!(Response::list(&[], Some('/'), b"nil").to_bytes(), b"* LIST () \"/\" \"nil\"\r\n");
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n
        }
    }

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
    ];

    const ARGS: &[&[u8]] = &[
        b"INBOX",
        b"\"a b\"",
        b"\"\"",
        b"(\\Seen \\Deleted)",
        b"()",
        b"BODY[HEADER.FIELDS (FROM)]",
        b"{3}\r\nabc",
        b"{2+}\r\nhi",
        b"{0}\r\n",
        b"NIL",
        b"1:*",
        b"(a (b (c)))",
        b"\"q\\\"\"",
        b"[ALERT]",
        b"x",
        b"OK",
        b"{99999999}\r\n",
        b"\"\xff\"",
        b"\"\xc3\xa9\"",
        b"NIL[x]",
    ];

    /// Lines that are mostly well formed: a tag or `*` or `+`, a name,
    /// and arguments.
    fn random_lines(rng: &mut Lcg) -> Vec<u8> {
        let heads: &[&[u8]] = &[b"a1 ", b"* ", b"+ ", b"t2 ", b"*"];
        let names: &[&[u8]] = &[b"LOGIN", b"OK", b"NO", b"BYE", b"5", b"FETCH", b"CAPABILITY", b"PREAUTH"];
        let mut b = Vec::new();
        for _ in 0..1 + rng.below(4) {
            b.extend_from_slice(heads[rng.below(heads.len())]);
            b.extend_from_slice(names[rng.below(names.len())]);
            for _ in 0..rng.below(5) {
                b.push(b' ');
                b.extend_from_slice(ARGS[rng.below(ARGS.len())]);
            }
            if rng.below(30) == 0 {
                b.push(rng.next() as u8);
            }
            b.extend_from_slice(b"\r\n");
        }
        b
    }

    fn random_stream(rng: &mut Lcg) -> Vec<u8> {
        if rng.below(2) == 0 {
            return random_lines(rng);
        }
        let mut b = Vec::new();
        for _ in 0..rng.below(40) {
            if rng.below(8) == 0 {
                b.push(rng.next() as u8);
            } else {
                b.extend_from_slice(PIECES[rng.below(PIECES.len())]);
            }
        }
        b
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg(0x1ee7_1ee7);
        let mut commands = 0;
        let mut resps = 0;
        for _ in 0..20_000 {
            let b = random_stream(&mut rng);
            let whole = events(&b, false);
            assert_eq!(whole, events(&b, true));
            for e in whole.iter().flatten() {
                if let Event::Command(c) = e {
                    commands += 1;
                    let bytes = c.to_bytes();
                    assert_eq!(&cmd(&bytes), c);
                    assert_eq!(events(&bytes, false).last(), Some(&Ok(e.clone())));
                }
            }
            let whole = responses(&b, false);
            assert_eq!(whole, responses(&b, true));
            for r in whole.iter().flatten() {
                resps += 1;
                let bytes = r.to_bytes();
                assert_eq!(&Response::parse(&bytes).unwrap(), r);
                assert_eq!(responses(&bytes, false), vec![Ok(r.clone())]);
            }
            let _ = Command::parse(&b);
            let _ = Response::parse(&b);
            let mut d = Decoder::new();
            d.feed(&b);
            let _ = d.next_line();
            let _ = d.next_event();
            d.refuse_literal();
            while d.next_event().is_some_and(|e| !matches!(e, Err(e) if e.is_fatal())) {}
        }
        assert!(commands > 100, "{commands}");
        assert!(resps > 100, "{resps}");
    }

    #[test]
    fn random_values_round_trip() {
        let mut rng = Lcg(42);
        let words = ["INBOX", "a b", "", "\\Seen", "x[y]", "OK", "é", "{3}", "a\r\nb", "NIL", "q\"\\", "n\0", "\0"];
        for _ in 0..3000 {
            let mut args = Vec::new();
            for _ in 0..rng.below(6) {
                let w = words[rng.below(words.len())];
                let mut v = match rng.below(4) {
                    0 => Value::atom(w),
                    1 => Value::string(w.as_bytes()),
                    2 => Value::Literal { data: w.as_bytes().to_vec(), non_sync: rng.below(2) == 0 },
                    _ => Value::List(vec![Value::atom(w), Value::string(w.as_bytes())]),
                };
                for _ in 0..rng.below(3) {
                    v = Value::List(vec![v]);
                }
                args.push(v);
            }
            if rng.below(5) == 0 {
                args.push(Value::string(b"a\xff\0"));
            }
            let c = Command::new(words[rng.below(words.len())], "x", args.clone());
            let b = c.to_bytes();
            assert!(Command::parse(&b).is_ok(), "{}", String::from_utf8_lossy(&b));
            let r = Response::Data(args);
            let b = r.to_bytes();
            assert_eq!(responses(&b, true).len(), 1, "{}", String::from_utf8_lossy(&b));
            assert!(Response::parse(&b).is_ok(), "{}", String::from_utf8_lossy(&b));
            let text = words[rng.below(words.len())];
            let s = Response::Status {
                tag: Some(text.into()),
                status: Status::No,
                code: Some(text.into()),
                text: text.into(),
            };
            assert!(Response::parse(&s.to_bytes()).is_ok());
            assert!(Response::parse(&Response::continue_req(text).to_bytes()).is_ok());
        }
    }
}
