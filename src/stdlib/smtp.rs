//! SMTP: reading and writing commands, replies and DATA, with no I/O.
//!
//! SMTP transfers mail over TCP, usually on port 25. This module implements
//! RFC 5321 command and reply framing, multiline replies and DATA
//! transparency (dot-stuffing). [`Request`] reads common commands, including
//! STARTTLS and AUTH. Envelope paths are preserved without the surrounding
//! angle brackets; mailbox validity and extension negotiation belong to
//! world code. Arguments may contain UTF-8 for negotiated SMTPUTF8 use.
//! Command lines use the base 512-byte limit; extension-specific increases
//! and BDAT binary chunk framing are not implemented.
//!
//! Feed a server's connection bytes to [`CommandDecoder`]. After accepting
//! DATA and sending a 354 reply, call [`CommandDecoder::start_data`] and
//! read [`CommandDecoder::next_data`] until the terminating dot arrives.
//! Buffered bytes after it remain available as commands. Bad command lines
//! are skipped; malformed replies and DATA stop their decoder. Session
//! state, authentication, TLS and message storage belong to the caller.
//! Mail headers can be read separately with [`imf`](crate::stdlib::imf).
//! New stacks use [`Server`] or [`Replies`] with [`codec::Stream`]. Their
//! [`Wire`] implementations require exact CRLF framing and write transactionally.
//! Legacy parsers, decoders, and `to_bytes` methods keep their original behavior.
//!
//! ```
//! use fictionet::stdlib::smtp::{CommandDecoder, Request, Reply};
//!
//! let mut decoder = CommandDecoder::new();
//! let bytes = b"DATA\r\nSubject: hello\r\n\r\n..a leading dot\r\n.\r\nQUIT\r\n";
//! assert_eq!(decoder.feed(bytes), bytes.len());
//! let command = decoder.next_command().unwrap().unwrap();
//! assert_eq!(Request::from_command(&command).unwrap(), Request::Data);
//! decoder.start_data().unwrap(); // after the server accepts DATA
//! assert_eq!(decoder.next_data().unwrap().unwrap(),
//!            b"Subject: hello\r\n\r\n.a leading dot\r\n");
//! assert_eq!(decoder.next_command().unwrap().unwrap().verb, "QUIT");
//! assert_eq!(Reply::new(250, "Queued").to_bytes().unwrap(), b"250 Queued\r\n");
//! ```

extern crate alloc;

use self::alloc::{string::String, vec::Vec};
use super::codec::{self, Decode, Wire};

/// SMTP relay port.
pub const PORT: u16 = 25;
/// Message submission port.
pub const SUBMISSION_PORT: u16 = 587;
/// Implicit TLS message submission port.
pub const TLS_PORT: u16 = 465;
/// Maximum command or reply line size, including CRLF (RFC 5321, section 4.5.3.1).
pub const MAX_LINE: usize = 512;
/// Maximum DATA line size, including CRLF but excluding the extra stuffed dot.
pub const MAX_DATA_LINE: usize = 1000;
/// Local limit on the unstuffed message, including every line's CRLF.
pub const MAX_DATA: usize = 8 << 20;
/// Local limit on lines in a multiline reply.
pub const MAX_REPLY_LINES: usize = 1024;
/// Maximum unread wire bytes held by a decoder, separate from a message
/// or multiline reply being assembled.
pub const MAX_BUFFERED: usize = 16 << 10;

/// Why SMTP input or a value to be written is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A line exceeds its size limit.
    LineTooLong,
    /// A line ended with a bare LF rather than CRLF.
    LineEnding,
    /// Invalid UTF-8, NUL, or a forbidden control character.
    Text,
    /// A command verb must be 1 to 16 ASCII letters.
    Verb,
    /// Arguments do not match the command, path or parameter syntax.
    Argument,
    /// A reply code or its following separator is invalid.
    ReplyCode,
    /// A multiline reply changed its code before the final line.
    ReplyMismatch,
    /// A reply exceeded [`MAX_REPLY_LINES`] or had no lines when written.
    ReplyLines,
    /// A message exceeded [`MAX_DATA`].
    TooMuchData,
    /// DATA was started while already active or in the middle of a line.
    State,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LineTooLong => "SMTP line exceeds its limit",
            Self::LineEnding => "SMTP lines must end with CRLF",
            Self::Text => "SMTP text contains invalid characters",
            Self::Verb => "SMTP command verb must be 1 to 16 ASCII letters",
            Self::Argument => "SMTP command arguments are invalid",
            Self::ReplyCode => "SMTP reply code or separator is invalid",
            Self::ReplyMismatch => "SMTP multiline reply changed its code",
            Self::ReplyLines => "SMTP reply line count is outside its limit",
            Self::TooMuchData => "SMTP DATA exceeds the local size limit",
            Self::State => "SMTP decoder cannot enter DATA in its current state",
        })
    }
}
impl std::error::Error for Error {}

fn text(b: &[u8]) -> Result<&str, Error> {
    let s = std::str::from_utf8(b).map_err(|_| Error::Text)?;
    if s.chars().any(|c| c.is_control() && c != '\t') {
        return Err(Error::Text);
    }
    Ok(s)
}

/// A command verb and its uninterpreted argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// Case-insensitive ASCII verb; readers normalize it to upper case.
    pub verb: String,
    /// Everything after the first space; an empty argument differs from none.
    pub arg: Option<String>,
}
impl Command {
    /// Builds a command; its writer checks syntax and length.
    pub fn new(verb: &str, arg: Option<&str>) -> Self {
        Self {
            verb: verb.to_string(),
            arg: arg.map(str::to_string),
        }
    }

    /// Reads one command line without CRLF. Unknown verbs are preserved.
    pub fn parse(line: &[u8]) -> Result<Self, Error> {
        if line.len() > MAX_LINE - 2 {
            return Err(Error::LineTooLong);
        }
        let line = text(line)?;
        let (verb, arg) = line
            .split_once(' ')
            .map_or((line, None), |(v, a)| (v, Some(a)));
        if verb.is_empty() || verb.len() > 16 || !verb.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(Error::Verb);
        }
        Ok(Self {
            verb: verb.to_ascii_uppercase(),
            arg: arg.map(str::to_string),
        })
    }

    /// Writes a command and CRLF, normalizing only the verb. Refuses bad
    /// characters or length rather than truncating or changing arguments.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.verb.is_empty()
            || self.verb.len() > 16
            || !self.verb.bytes().all(|b| b.is_ascii_alphabetic())
        {
            return Err(Error::Verb);
        }
        if self.verb.len() > MAX_LINE - 2
            || self.arg.as_ref().is_some_and(|a| a.len() > MAX_LINE - 2)
        {
            return Err(Error::LineTooLong);
        }
        let mut out = self.verb.to_ascii_uppercase().into_bytes();
        if let Some(arg) = &self.arg {
            out.push(b' ');
            out.extend_from_slice(arg.as_bytes());
        }
        Self::parse(&out)?;
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }
}

/// An ESMTP parameter such as `SIZE=123` or `SMTPUTF8`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    /// An ASCII letter or digit followed by letters, digits or hyphens.
    /// Case is preserved; comparisons belong to the caller.
    pub keyword: String,
    /// Nonempty printable ASCII excluding `=`, when an equals sign was sent.
    pub value: Option<String>,
}
impl Parameter {
    fn parse(s: &str) -> Result<Self, Error> {
        let (keyword, value) = s.split_once('=').map_or((s, None), |(k, v)| (k, Some(v)));
        if !keyword
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            || !keyword
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.is_some_and(|v| {
                v.is_empty() || !v.bytes().all(|b| b.is_ascii_graphic() && b != b'=')
            })
        {
            return Err(Error::Argument);
        }
        Ok(Self {
            keyword: keyword.to_string(),
            value: value.map(str::to_string),
        })
    }
}

/// Common SMTP commands with their arguments separated. This does not
/// check command sequencing, mailbox grammar, or negotiated extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// The client's name or address literal.
    Helo(String),
    /// Extended greeting, asking for the server's extensions.
    Ehlo(String),
    /// Reverse path (empty for a bounce) and ESMTP parameters.
    Mail {
        /// Path without `<` and `>`, preserving quoted strings and source routes.
        path: String,
        /// ESMTP parameters in wire order.
        parameters: Vec<Parameter>,
    },
    /// Forward path and ESMTP parameters.
    Rcpt {
        /// Nonempty path without `<` and `>`.
        path: String,
        /// ESMTP parameters in wire order.
        parameters: Vec<Parameter>,
    },
    /// Begin a message after the server replies 354.
    Data,
    /// Reset the current mail transaction.
    Rset,
    /// No operation, optionally with uninterpreted text.
    Noop(Option<String>),
    /// End the session.
    Quit,
    /// Verify a mailbox or user.
    Vrfy(String),
    /// Expand a mailing list.
    Expn(String),
    /// Request help, optionally about a command.
    Help(Option<String>),
    /// Start TLS (RFC 3207). Hand buffered bytes to the TLS layer with
    /// [`CommandDecoder::take_buffered`] once the switch is accepted.
    StartTls,
    /// Start SASL authentication (RFC 4954). Credentials remain opaque.
    Auth {
        /// SASL mechanism name; case is preserved.
        mechanism: String,
        /// Optional initial response, including `=` for an empty response.
        initial_response: Option<String>,
    },
    /// An extension verb this module does not interpret.
    Other(Command),
}
impl Request {
    /// Reads a command's arguments. Paths are split with awareness of
    /// quoted strings and backslash escapes; mailbox semantics stay opaque.
    pub fn from_command(command: &Command) -> Result<Self, Error> {
        command.to_bytes()?;
        let arg = command.arg.as_deref();
        let required = || {
            arg.filter(|s| !s.is_empty())
                .ok_or(Error::Argument)
                .map(str::to_string)
        };
        let no_arg = |request| {
            if arg.is_none() {
                Ok(request)
            } else {
                Err(Error::Argument)
            }
        };
        match command.verb.to_ascii_uppercase().as_str() {
            "HELO" | "EHLO" => {
                let name = required()?;
                if name.bytes().any(|b| b.is_ascii_whitespace()) {
                    return Err(Error::Argument);
                }
                Ok(if command.verb.eq_ignore_ascii_case("HELO") {
                    Self::Helo(name)
                } else {
                    Self::Ehlo(name)
                })
            }
            "MAIL" => {
                let (path, parameters) = envelope(arg, "FROM:", true)?;
                Ok(Self::Mail { path, parameters })
            }
            "RCPT" => {
                let (path, parameters) = envelope(arg, "TO:", false)?;
                Ok(Self::Rcpt { path, parameters })
            }
            "DATA" => no_arg(Self::Data),
            "RSET" => no_arg(Self::Rset),
            "QUIT" => no_arg(Self::Quit),
            "STARTTLS" => no_arg(Self::StartTls),
            "NOOP" => Ok(Self::Noop(command.arg.clone())),
            "HELP" => Ok(Self::Help(command.arg.clone())),
            "VRFY" => Ok(Self::Vrfy(required()?)),
            "EXPN" => Ok(Self::Expn(required()?)),
            "AUTH" => {
                let value = required()?;
                let (mechanism, response) = value
                    .split_once(' ')
                    .map_or((value.as_str(), None), |(m, r)| (m, Some(r)));
                if mechanism.is_empty()
                    || mechanism.len() > 20
                    || !mechanism
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    || response
                        .is_some_and(|r| r.is_empty() || !r.bytes().all(|b| b.is_ascii_graphic()))
                {
                    return Err(Error::Argument);
                }
                Ok(Self::Auth {
                    mechanism: mechanism.to_string(),
                    initial_response: response.map(str::to_string),
                })
            }
            _ => {
                let mut c = command.clone();
                c.verb.make_ascii_uppercase();
                Ok(Self::Other(c))
            }
        }
    }

    /// Writes a request and CRLF. Invalid arguments and `Other` values
    /// that would parse as a known request are refused.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let command = match self {
            Self::Helo(s) => Command::new("HELO", Some(s)),
            Self::Ehlo(s) => Command::new("EHLO", Some(s)),
            Self::Mail { path, parameters } | Self::Rcpt { path, parameters } => {
                if path.len() > MAX_LINE || parameters.len() > MAX_LINE {
                    return Err(Error::LineTooLong);
                }
                let mail = matches!(self, Self::Mail { .. });
                let mut arg = format!("{}<{path}>", if mail { "FROM:" } else { "TO:" });
                for parameter in parameters {
                    // Check lengths before building attacker-controlled strings.
                    if parameter.keyword.len() > MAX_LINE
                        || parameter.value.as_ref().is_some_and(|v| v.len() > MAX_LINE)
                    {
                        return Err(Error::LineTooLong);
                    }
                    arg.push(' ');
                    arg.push_str(&parameter.keyword);
                    if let Some(value) = &parameter.value {
                        arg.push('=');
                        arg.push_str(value);
                    }
                    if arg.len() > MAX_LINE {
                        return Err(Error::LineTooLong);
                    }
                }
                Command::new(if mail { "MAIL" } else { "RCPT" }, Some(&arg))
            }
            Self::Data => Command::new("DATA", None),
            Self::Rset => Command::new("RSET", None),
            Self::Quit => Command::new("QUIT", None),
            Self::StartTls => Command::new("STARTTLS", None),
            Self::Noop(arg) => Command::new("NOOP", arg.as_deref()),
            Self::Help(arg) => Command::new("HELP", arg.as_deref()),
            Self::Vrfy(arg) => Command::new("VRFY", Some(arg)),
            Self::Expn(arg) => Command::new("EXPN", Some(arg)),
            Self::Auth {
                mechanism,
                initial_response,
            } => {
                if mechanism.len() > MAX_LINE
                    || initial_response
                        .as_ref()
                        .is_some_and(|r| r.len() > MAX_LINE)
                {
                    return Err(Error::LineTooLong);
                }
                let mut arg = mechanism.clone();
                if let Some(response) = initial_response {
                    arg.push(' ');
                    arg.push_str(response);
                }
                Command::new("AUTH", Some(&arg))
            }
            Self::Other(command) => {
                if !matches!(Self::from_command(command)?, Self::Other(_)) {
                    return Err(Error::Argument);
                }
                return command.to_bytes();
            }
        };
        if Self::from_command(&command)? != *self {
            return Err(Error::Argument);
        }
        command.to_bytes()
    }
}

fn envelope(
    arg: Option<&str>,
    prefix: &str,
    empty: bool,
) -> Result<(String, Vec<Parameter>), Error> {
    let arg = arg.ok_or(Error::Argument)?;
    if !arg
        .get(..prefix.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
    {
        return Err(Error::Argument);
    }
    let tail = &arg[prefix.len()..];
    if !tail.starts_with('<') {
        return Err(Error::Argument);
    }
    let mut quoted = false;
    let mut escaped = false;
    let mut end = None;
    for (i, byte) in tail.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b'>' if !quoted => {
                end = Some(i);
                break;
            }
            b'<' | b' ' | b'\t' if !quoted => return Err(Error::Argument),
            _ => {}
        }
    }
    let end = end.ok_or(Error::Argument)?;
    if end + 1 > 256 || (!empty && end == 1) {
        return Err(Error::Argument);
    }
    let rest = &tail[end + 1..];
    let parameters = if rest.is_empty() {
        Vec::new()
    } else {
        let rest = rest.strip_prefix(' ').ok_or(Error::Argument)?;
        rest.split(' ')
            .map(Parameter::parse)
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok((tail[1..end].to_string(), parameters))
}

/// A server reply. All lines share one numeric code; the writer supplies
/// the hyphens and final space. Reply text may contain UTF-8 and tabs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Three digits: first 2..=5, second 0..=5, third 0..=9.
    pub code: u16,
    /// One or more lines, without code, separator or CRLF.
    pub lines: Vec<String>,
}
impl Reply {
    /// Builds a single-line reply. Its writer validates it.
    pub fn new(code: u16, text: &str) -> Self {
        Self {
            code,
            lines: vec![text.to_string()],
        }
    }

    /// Reads one complete reply at the start of `b`, returning its consumed
    /// length. `Ok(None)` means a line or continuation is still incomplete.
    pub fn parse(b: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let mut code = None;
        let mut lines = Vec::new();
        let mut at = 0;
        loop {
            let tail = &b[at..];
            let Some(end) = tail.iter().take(MAX_LINE).position(|&x| x == b'\n') else {
                return if tail.len() >= MAX_LINE {
                    Err(Error::LineTooLong)
                } else {
                    Ok(None)
                };
            };
            if end == 0 || tail[end - 1] != b'\r' {
                return Err(Error::LineEnding);
            }
            let (number, more, line) = reply_line(&tail[..end - 1])?;
            if code.is_some_and(|c| c != number) {
                return Err(Error::ReplyMismatch);
            }
            code = Some(number);
            lines.push(line.to_string());
            at += end + 1;
            if !more {
                return Ok(Some((
                    Self {
                        code: number,
                        lines,
                    },
                    at,
                )));
            }
            if lines.len() == MAX_REPLY_LINES {
                return Err(Error::ReplyLines);
            }
        }
    }

    /// Writes the reply, refusing invalid codes, characters and lengths.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if !valid_code(self.code) {
            return Err(Error::ReplyCode);
        }
        if self.lines.is_empty() || self.lines.len() > MAX_REPLY_LINES {
            return Err(Error::ReplyLines);
        }
        let mut out = Vec::new();
        for (i, line) in self.lines.iter().enumerate() {
            if line.len() > MAX_LINE - 6 {
                return Err(Error::LineTooLong);
            }
            text(line.as_bytes())?;
            out.extend_from_slice(
                format!(
                    "{:03}{}",
                    self.code,
                    if i + 1 == self.lines.len() { ' ' } else { '-' }
                )
                .as_bytes(),
            );
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        Ok(out)
    }
}

fn valid_code(code: u16) -> bool {
    (200..=559).contains(&code) && code / 10 % 10 <= 5
}

fn reply_line(line: &[u8]) -> Result<(u16, bool, &str), Error> {
    if line.len() < 3 || !line[..3].iter().all(u8::is_ascii_digit) {
        return Err(Error::ReplyCode);
    }
    let code = u16::from(line[0] - b'0') * 100
        + u16::from(line[1] - b'0') * 10
        + u16::from(line[2] - b'0');
    if !valid_code(code) {
        return Err(Error::ReplyCode);
    }
    match line.get(3) {
        None => Ok((code, false, "")),
        Some(b' ' | b'-') => Ok((code, line[3] == b'-', text(&line[4..])?)),
        _ => Err(Error::ReplyCode),
    }
}

/// Writes a DATA message with dot-stuffing and the terminating dot line.
/// An empty message is allowed. Every nonempty message must already end
/// in CRLF; bare CR/LF, NUL and lines over 1000 bytes are refused. Other
/// bytes, including 8-bit content, are preserved; negotiation is the caller's job.
pub fn write_data(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() > MAX_DATA {
        return Err(Error::TooMuchData);
    }
    let mut out = Vec::with_capacity(data.len() + 3);
    let mut at = 0;
    while at < data.len() {
        let tail = &data[at..];
        let end = tail
            .iter()
            .take(MAX_DATA_LINE)
            .position(|&b| b == b'\n')
            .ok_or(if tail.len() >= MAX_DATA_LINE {
                Error::LineTooLong
            } else {
                Error::LineEnding
            })?;
        if end == 0 || tail[end - 1] != b'\r' {
            return Err(Error::LineEnding);
        }
        let line = &tail[..end - 1];
        check_data_line(line)?;
        if line.starts_with(b".") {
            out.push(b'.');
        }
        out.extend_from_slice(&tail[..end + 1]);
        at += end + 1;
    }
    out.extend_from_slice(b".\r\n");
    Ok(out)
}

fn check_data_line(line: &[u8]) -> Result<(), Error> {
    if line.len() > MAX_DATA_LINE - 2 {
        return Err(Error::LineTooLong);
    }
    if line.iter().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
        return Err(Error::Text);
    }
    Ok(())
}

// Scan every input byte once. A long line reports one error, then is
// discarded through LF without retaining its contents.
#[derive(Debug, Default)]
struct Lines {
    buf: Vec<u8>,
    start: usize,
    line: Vec<u8>,
    skipping: bool,
}
impl Lines {
    fn buffered(&self) -> usize {
        self.buf.len() - self.start + self.line.len()
    }

    fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let n = bytes.len().min(MAX_BUFFERED - self.buffered());
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    fn next(&mut self, limit: usize) -> Option<Result<Vec<u8>, Error>> {
        while self.start < self.buf.len() {
            let byte = self.buf[self.start];
            self.start += 1;
            if self.skipping {
                if byte == b'\n' {
                    self.skipping = false;
                }
                continue;
            }
            if byte == b'\n' {
                if self.line.last() != Some(&b'\r') {
                    self.line.clear();
                    return Some(Err(Error::LineEnding));
                }
                self.line.pop();
                return Some(Ok(std::mem::take(&mut self.line)));
            }
            self.line.push(byte);
            if self.line.len() >= limit {
                self.line.clear();
                self.skipping = true;
                return Some(Err(Error::LineTooLong));
            }
        }
        None
    }
}

/// A server-side command and DATA decoder. Command errors affect one line;
/// DATA errors are sticky and release all buffered input and message data.
#[derive(Debug, Default)]
pub struct CommandDecoder {
    lines: Lines,
    data: Option<Vec<u8>>,
    failed: Option<Error>,
}
impl CommandDecoder {
    /// An empty decoder in command mode.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes as many wire bytes as fit. Drain commands or DATA and feed
    /// the remainder. After a DATA error, takes and drops every byte.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            bytes.len()
        } else {
            self.lines.feed(bytes)
        }
    }

    /// The next command. Returns `None` in DATA mode or when more bytes
    /// are needed. On a malformed command line, returns one error and
    /// advances to the next line (discarding an overlong line's remainder).
    pub fn next_command(&mut self) -> Option<Result<Command, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        if self.data.is_some() {
            return None;
        }
        self.lines
            .next(MAX_LINE)
            .map(|line| line.and_then(|line| Command::parse(&line)))
    }

    /// Enters DATA mode at a command boundary, retaining buffered bytes.
    /// Call only after accepting DATA, not simply after seeing its verb.
    pub fn start_data(&mut self) -> Result<(), Error> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.data.is_some() || !self.lines.line.is_empty() || self.lines.skipping {
            return Err(Error::State);
        }
        self.data = Some(Vec::new());
        Ok(())
    }

    /// Returns the next whole unstuffed message, then returns to command
    /// mode. While incomplete, keeps up to [`MAX_DATA`] message bytes in
    /// addition to [`MAX_BUFFERED`] unread wire bytes. A single leading dot
    /// is removed from each nonterminating line, as RFC 5321 requires.
    pub fn next_data(&mut self) -> Option<Result<Vec<u8>, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        self.data.as_ref()?;
        while let Some(line) = self.lines.next(MAX_DATA_LINE + 1) {
            let result = line.and_then(|line| {
                if line == b"." {
                    return Ok(true);
                }
                let line = line.strip_prefix(b".").unwrap_or(&line);
                check_data_line(line)?;
                let data = self.data.as_mut().unwrap();
                if line.len() + 2 > MAX_DATA - data.len() {
                    return Err(Error::TooMuchData);
                }
                data.extend_from_slice(line);
                data.extend_from_slice(b"\r\n");
                Ok(false)
            });
            match result {
                Ok(true) => return Some(Ok(self.data.take().unwrap())),
                Ok(false) => {}
                Err(e) => {
                    self.failed = Some(e);
                    self.lines = Lines::default();
                    self.data = None;
                    return Some(Err(e));
                }
            }
        }
        None
    }

    /// Whether a DATA message is being read.
    pub fn in_data(&self) -> bool {
        self.data.is_some()
    }

    /// Unread wire bytes, including a partial line, excluding assembled DATA.
    pub fn buffered(&self) -> usize {
        self.lines.buffered()
    }

    /// Message bytes assembled so far.
    pub fn data_buffered(&self) -> usize {
        self.data.as_ref().map_or(0, Vec::len)
    }

    /// Takes unread bytes at a command boundary, for example when handing
    /// the connection to TLS. Fails during DATA or a partially read line.
    pub fn take_buffered(&mut self) -> Result<Vec<u8>, Error> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.data.is_some() || !self.lines.line.is_empty() || self.lines.skipping {
            return Err(Error::State);
        }
        let lines = std::mem::take(&mut self.lines);
        Ok(lines.buf[lines.start..].to_vec())
    }
}

/// A client-side reply decoder. Multiline replies keep their parsed lines
/// separately from the bounded input buffer. Any error is sticky.
#[derive(Debug, Default)]
pub struct ReplyDecoder {
    lines: Lines,
    reply: Option<Reply>,
    failed: Option<Error>,
}
impl ReplyDecoder {
    /// An empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the prefix that fits in [`MAX_BUFFERED`]; drain replies and
    /// feed the rest. After an error, takes and drops all bytes.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            bytes.len()
        } else {
            self.lines.feed(bytes)
        }
    }

    /// A complete reply, `None` if more bytes are needed, or a sticky error.
    pub fn next_reply(&mut self) -> Option<Result<Reply, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        while let Some(line) = self.lines.next(MAX_LINE) {
            let result = line.and_then(|line| {
                let (code, more, text) = reply_line(&line)?;
                let reply = self.reply.get_or_insert_with(|| Reply {
                    code,
                    lines: Vec::new(),
                });
                if reply.code != code {
                    return Err(Error::ReplyMismatch);
                }
                reply.lines.push(text.to_string());
                if more && reply.lines.len() == MAX_REPLY_LINES {
                    return Err(Error::ReplyLines);
                }
                Ok(more)
            });
            match result {
                Ok(false) => return Some(Ok(self.reply.take().unwrap())),
                Ok(true) => {}
                Err(e) => {
                    self.failed = Some(e);
                    self.lines = Lines::default();
                    self.reply = None;
                    return Some(Err(e));
                }
            }
        }
        None
    }

    /// Unread wire bytes, excluding the already parsed reply lines.
    pub fn buffered(&self) -> usize {
        self.lines.buffered()
    }
}

/// Maximum text bytes retained while assembling a reply.
pub const MAX_REPLY_TEXT: usize = MAX_REPLY_LINES * (MAX_LINE - 6);

/// Why a shared SMTP decoder cannot continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A line exceeded its limit or ended before CRLF.
    Line(codec::LineError),
    /// An assembly exceeded its named limit.
    Limit(Error),
    /// Storage for a bounded DATA assembly could not be allocated.
    Allocation,
    /// EOF interrupted DATA or a multiline reply.
    Incomplete,
    /// The caller must select command mode after the DATA item.
    State,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Line(e) => e.fmt(f),
            Self::Limit(e) => e.fmt(f),
            Self::Allocation => f.write_str("SMTP assembly allocation failed"),
            Self::Incomplete => f.write_str("incomplete SMTP assembly"),
            Self::State => f.write_str("select SMTP command mode after DATA"),
        }
    }
}
impl core::error::Error for DecodeError {}

/// Why bytes are not exactly one SMTP wire value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A complete command or reply is malformed.
    Invalid(Error),
    /// Line framing or assembly failed.
    Framing(DecodeError),
    /// No complete value was present.
    Incomplete,
    /// Bytes follow the value.
    Trailing,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(e) => e.fmt(f),
            Self::Framing(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete SMTP value"),
            Self::Trailing => f.write_str("bytes after SMTP value"),
        }
    }
}
impl core::error::Error for ParseError {}

/// The value cannot be written within the limits without changing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteError;

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SMTP value cannot be written unchanged")
    }
}
impl core::error::Error for WriteError {}

impl Wire for Command {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads exactly one command, including its required CRLF.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut lines = codec::Lines::new(MAX_LINE - 2, codec::Ending::Crlf);
        match smtp_line(&mut lines, bytes, true).map_err(ParseError::Framing)? {
            codec::Step::Item(line, used) if used == bytes.len() => {
                Command::parse(&line.map_err(ParseError::Invalid)?).map_err(ParseError::Invalid)
            }
            codec::Step::Item(_, _) => Err(ParseError::Trailing),
            _ => Err(ParseError::Incomplete),
        }
    }

    /// Appends CRLF. Refuses normalization and leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let bytes = self.to_bytes().map_err(|_| WriteError)?;
        if <Self as Wire>::parse(&bytes).as_ref() != Ok(self) {
            return Err(WriteError);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Reply {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads one complete reply and refuses trailing bytes.
    fn parse(mut bytes: &[u8]) -> Result<Self, ParseError> {
        let mut replies = Replies::new();
        loop {
            match replies.decode(bytes, true).map_err(ParseError::Framing)? {
                codec::Step::Item(reply, used) => {
                    if used != bytes.len() {
                        return Err(ParseError::Trailing);
                    }
                    return reply.map_err(ParseError::Invalid);
                }
                codec::Step::Skip(used) => {
                    bytes = bytes.get(used..).ok_or(ParseError::Incomplete)?
                }
                _ => return Err(ParseError::Incomplete),
            }
        }
    }

    /// Appends a bounded reply with CRLF. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let bytes = self.to_bytes().map_err(|_| WriteError)?;
        if <Self as Wire>::parse(&bytes).as_ref() != Ok(self) {
            return Err(WriteError);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

fn smtp_line(
    lines: &mut codec::Lines,
    input: &[u8],
    eof: bool,
) -> Result<codec::Step<Result<Vec<u8>, Error>>, DecodeError> {
    let step = match lines.decode(input, eof) {
        Ok(step) => step,
        Err(never) => match never {},
    };
    Ok(match step {
        codec::Step::Item(Ok(line), used) => codec::Step::Item(Ok(line), used),
        codec::Step::Item(Err(codec::LineError::BareLf), used) => {
            codec::Step::Item(Err(Error::LineEnding), used)
        }
        codec::Step::Item(Err(e), _) => return Err(DecodeError::Line(e)),
        codec::Step::Skip(used) => codec::Step::Skip(used),
        codec::Step::Need => codec::Step::Need,
        codec::Step::End => codec::Step::End,
    })
}

/// One command or one complete, unstuffed DATA message from [`Server`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// A command, with its verb normalized to upper case.
    Command(Command),
    /// DATA bytes, including each content line's CRLF, without the terminator.
    Message(Vec<u8>),
}

#[derive(PartialEq, Eq)]
enum Mode {
    Command,
    Data,
    DataDone,
    End,
}

/// Reads SMTP commands and DATA over [`codec::Lines`].
///
/// CRLF is required. Command lines use [`MAX_LINE`]. DATA lines use
/// [`MAX_DATA_LINE`], plus one transparency dot on the wire. Input capacity
/// is always `MAX_DATA_LINE + 1`, so mode changes never need a larger buffer.
/// DATA assembly holds at most [`MAX_DATA`] bytes. Scanning is linear.
///
/// Complete malformed commands are error items. Bad DATA content rejects
/// the message at its dot terminator. Line overflow, unterminated lines,
/// assembly overflow, and EOF before the dot terminate the stream.
/// The legacy [`CommandDecoder`] retains its original behavior.
///
/// Call [`start_data`](Self::start_data) only after accepting DATA. After
/// the message item, call [`start_commands`](Self::start_commands). For an
/// accepted STARTTLS, call [`handoff`](Self::handoff), then use
/// [`codec::Stream::into_parts`] to obtain unread TLS bytes.
///
/// ```
/// use fictionet::stdlib::{codec::Stream, smtp::{Server, Input}};
/// let mut stream = Stream::new(Server::new());
/// assert_eq!(stream.push(b"DATA\r\n..x\r\n.\r\nQUIT\r\n"), 20);
/// assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(_))))));
/// stream.decoder().start_data().unwrap();
/// assert_eq!(stream.next(), Some(Ok(Ok(Input::Message(b".x\r\n".to_vec())))));
/// stream.decoder().start_commands().unwrap();
/// assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(_))))));
/// ```
pub struct Server {
    lines: codec::Lines,
    mode: Mode,
    partial: bool,
    data: Vec<u8>,
    data_size: usize,
    rejected: Option<Error>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// Creates an empty decoder in command mode.
    pub fn new() -> Self {
        Self {
            lines: codec::Lines::new(MAX_LINE - 2, codec::Ending::Crlf),
            mode: Mode::Command,
            partial: false,
            data: Vec::new(),
            data_size: 0,
            rejected: None,
        }
    }

    /// Starts DATA at a command boundary after the world accepts it.
    pub fn start_data(&mut self) -> Result<(), Error> {
        if self.mode != Mode::Command || self.partial {
            return Err(Error::State);
        }
        self.mode = Mode::Data;
        self.lines = codec::Lines::new(MAX_DATA_LINE - 1, codec::Ending::Crlf);
        Ok(())
    }

    /// Resumes commands after the complete DATA item, including a rejected one.
    pub fn start_commands(&mut self) -> Result<(), Error> {
        if self.mode != Mode::DataDone {
            return Err(Error::State);
        }
        self.mode = Mode::Command;
        self.lines = codec::Lines::new(MAX_LINE - 2, codec::Ending::Crlf);
        Ok(())
    }

    /// Ends SMTP decoding at a command boundary for an accepted protocol switch.
    pub fn handoff(&mut self) -> Result<(), Error> {
        if self.mode != Mode::Command || self.partial {
            return Err(Error::State);
        }
        self.mode = Mode::End;
        Ok(())
    }
}

impl Decode for Server {
    type Item = Result<Input, Error>;
    type Error = DecodeError;
    const NAME: &'static str = "SMTP server";

    fn capacity(&self) -> usize {
        MAX_DATA_LINE + 1
    }

    fn held(&self) -> usize {
        self.data.len()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<codec::Step<Self::Item>, DecodeError> {
        if self.mode == Mode::End {
            return Ok(codec::Step::End);
        }
        if self.mode == Mode::DataDone {
            return Err(DecodeError::State);
        }
        let (line, used) = match smtp_line(&mut self.lines, input, eof)? {
            codec::Step::Item(line, used) => (line, used),
            codec::Step::Need => {
                self.partial = !input.is_empty();
                return if eof && self.mode == Mode::Data {
                    Err(DecodeError::Incomplete)
                } else {
                    Ok(codec::Step::Need)
                };
            }
            codec::Step::Skip(used) => return Ok(codec::Step::Skip(used)),
            codec::Step::End => return Ok(codec::Step::End),
        };
        self.partial = false;
        if self.mode == Mode::Command {
            return Ok(codec::Step::Item(
                line.and_then(|b| Command::parse(&b)).map(Input::Command),
                used,
            ));
        }
        if line.as_deref() == Ok(b".".as_slice()) {
            self.mode = Mode::DataDone;
            self.data_size = 0;
            let data = core::mem::take(&mut self.data);
            return Ok(codec::Step::Item(
                self.rejected
                    .take()
                    .map_or_else(|| Ok(Input::Message(data)), Err),
                used,
            ));
        }
        self.data_size = self
            .data_size
            .checked_add(used)
            .and_then(|n| {
                n.checked_sub(usize::from(
                    line.as_ref().is_ok_and(|b| b.starts_with(b".")),
                ))
            })
            .filter(|&n| n <= MAX_DATA)
            .ok_or(DecodeError::Limit(Error::TooMuchData))?;
        let result = line.and_then(|line| {
            let content = line.strip_prefix(b".").unwrap_or(&line);
            check_data_line(content)?;
            Ok(line)
        });
        match result {
            Ok(line) if self.rejected.is_none() => {
                if self.data_size > self.data.capacity() {
                    let target = self
                        .data_size
                        .max(self.data.capacity().saturating_mul(2))
                        .min(MAX_DATA);
                    self.data
                        .try_reserve_exact(target.saturating_sub(self.data.len()))
                        .map_err(|_| DecodeError::Allocation)?;
                }
                self.data
                    .extend_from_slice(line.strip_prefix(b".").unwrap_or(&line));
                self.data.extend_from_slice(b"\r\n");
            }
            Err(Error::LineTooLong) => return Err(DecodeError::Limit(Error::LineTooLong)),
            Err(e) => {
                self.rejected.get_or_insert(e);
                self.data.clear();
            }
            _ => {}
        }
        Ok(codec::Step::Skip(used))
    }
}

/// Reads SMTP replies over CRLF lines bounded by [`MAX_LINE`].
///
/// Hyphen continuations are assembled under [`MAX_REPLY_LINES`] and
/// [`MAX_REPLY_TEXT`]. A malformed complete line yields an error item
/// and discards the pending reply. The next line starts a new reply.
/// Oversized lines and assemblies, or EOF in a continuation, end the stream.
/// The legacy [`ReplyDecoder`] keeps its repeating errors.
pub struct Replies {
    lines: codec::Lines,
    pending: Option<Reply>,
    text_size: usize,
}

impl Default for Replies {
    fn default() -> Self {
        Self::new()
    }
}

impl Replies {
    /// Creates a decoder with no pending reply.
    pub fn new() -> Self {
        Self {
            lines: codec::Lines::new(MAX_LINE - 2, codec::Ending::Crlf),
            pending: None,
            text_size: 0,
        }
    }
}

impl Decode for Replies {
    type Item = Result<Reply, Error>;
    type Error = DecodeError;
    const NAME: &'static str = "SMTP replies";

    fn capacity(&self) -> usize {
        MAX_LINE
    }

    fn held(&self) -> usize {
        self.text_size
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<codec::Step<Self::Item>, DecodeError> {
        let (line, used) = match smtp_line(&mut self.lines, input, eof)? {
            codec::Step::Item(line, used) => (line, used),
            codec::Step::Need if eof && self.pending.is_some() => {
                return Err(DecodeError::Incomplete);
            }
            codec::Step::Need => return Ok(codec::Step::Need),
            codec::Step::Skip(used) => return Ok(codec::Step::Skip(used)),
            codec::Step::End => return Ok(codec::Step::End),
        };
        let result = line.and_then(|line| {
            let (code, more, text) = reply_line(&line)?;
            let reply = self.pending.get_or_insert_with(|| Reply {
                code,
                lines: Vec::new(),
            });
            if reply.code != code {
                return Err(Error::ReplyMismatch);
            }
            if reply.lines.len() >= MAX_REPLY_LINES {
                return Err(Error::ReplyLines);
            }
            reply.lines.push(text.to_string());
            self.text_size = self.text_size.saturating_add(text.len());
            if more && reply.lines.len() >= MAX_REPLY_LINES {
                return Err(Error::ReplyLines);
            }
            Ok(more)
        });
        match result {
            Ok(true) => Ok(codec::Step::Skip(used)),
            Ok(false) => {
                self.text_size = 0;
                Ok(codec::Step::Item(
                    self.pending.take().ok_or(Error::ReplyCode),
                    used,
                ))
            }
            Err(Error::ReplyLines) => Err(DecodeError::Limit(Error::ReplyLines)),
            Err(e) => {
                self.pending = None;
                self.text_size = 0;
                Ok(codec::Step::Item(Err(e), used))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_and_request_round_trips() {
        for line in [
            "HELO example.test",
            "ehlo [127.0.0.1]",
            "MAIL FROM:<> SIZE=0",
            "mail from:<alice@example.test> BODY=8BITMIME SMTPUTF8",
            "RCPT TO:<Postmaster>",
            "RCPT TO:<\"a > b\"@example.test> NOTIFY=SUCCESS,FAILURE",
            "MAIL FROM:<\"a\\\"b\"@example.test>",
            "DATA",
            "RSET",
            "QUIT",
            "NOOP",
            "NOOP ",
            "HELP MAIL",
            "VRFY a name",
            "EXPN list",
            "STARTTLS",
            "AUTH PLAIN =",
            "AUTH LOGIN",
            "XTEST arg",
        ] {
            let command = Command::parse(line.as_bytes()).unwrap();
            let bytes = command.to_bytes().unwrap();
            assert_eq!(
                Command::parse(&bytes[..bytes.len() - 2]),
                Ok(command.clone())
            );
            let request = Request::from_command(&command).unwrap();
            let bytes = request.to_bytes().unwrap();
            let back = Command::parse(&bytes[..bytes.len() - 2]).unwrap();
            assert_eq!(Request::from_command(&back), Ok(request));
        }
        let command = Command::parse(b"MAIL FROM:<> SIZE=0").unwrap();
        assert_eq!(
            Request::from_command(&command),
            Ok(Request::Mail {
                path: String::new(),
                parameters: vec![Parameter {
                    keyword: "SIZE".to_string(),
                    value: Some("0".to_string())
                }]
            })
        );
    }

    #[test]
    fn bad_arguments_and_injection_are_refused() {
        for line in [
            "HELO",
            "EHLO two names",
            "MAIL TO:<a@b>",
            "MAIL FROM:a@b",
            "RCPT TO:<>",
            "MAIL FROM:<a b>",
            "MAIL FROM:<a<b>",
            "MAIL FROM:<\"unclosed>",
            "MAIL FROM:<a>SIZE=1",
            "MAIL FROM:<a> SIZE=",
            "MAIL FROM:<a> SIZE=1=2",
            "MAIL FROM:<a> -BAD",
            "MAIL FROM:<a> ",
            "MAIL FROM:<a>  SIZE=1",
            "DATA arg",
            "QUIT ",
            "RSET arg",
            "STARTTLS arg",
            "AUTH",
            "AUTH PLAIN  x",
        ] {
            let c = Command::parse(line.as_bytes()).unwrap();
            assert_eq!(Request::from_command(&c), Err(Error::Argument), "{line}");
        }
        for line in [&b"NOOP\r\nQUIT"[..], b"NOOP\0", b"\xff", b"NOOP\x7f"] {
            assert_eq!(Command::parse(line), Err(Error::Text));
        }
        assert!(Command::new("NOOP QUIT", None).to_bytes().is_err());
        assert!(Command::new("NOOP", Some("x\r\nQUIT")).to_bytes().is_err());
        assert_eq!(
            Request::Other(Command::new("DATA", None)).to_bytes(),
            Err(Error::Argument)
        );
        assert!(
            Request::Mail {
                path: "a> SIZE=1".to_string(),
                parameters: vec![]
            }
            .to_bytes()
            .is_err()
        );
        assert!(
            Request::Mail {
                path: "a".to_string(),
                parameters: vec![Parameter {
                    keyword: "SIZE=1".to_string(),
                    value: None
                }]
            }
            .to_bytes()
            .is_err()
        );
    }

    fn commands(bytes: &[u8], size: usize, drain_each: bool) -> Vec<Result<Command, Error>> {
        let mut decoder = CommandDecoder::new();
        let mut out = Vec::new();
        for mut chunk in bytes.chunks(size) {
            while !chunk.is_empty() {
                let n = decoder.feed(chunk);
                chunk = &chunk[n..];
                assert!(decoder.buffered() <= MAX_BUFFERED);
                if drain_each || !chunk.is_empty() {
                    let before = out.len();
                    out.extend(std::iter::from_fn(|| decoder.next_command()));
                    assert!(n > 0 || out.len() > before || decoder.buffered() < MAX_BUFFERED);
                }
            }
        }
        out.extend(std::iter::from_fn(|| decoder.next_command()));
        out
    }

    #[test]
    fn command_line_limits_recovery_and_schedules() {
        let mut stream = b"NOOP ".to_vec();
        stream.extend(vec![b'a'; MAX_LINE - 7]);
        stream.extend_from_slice(b"\r\n");
        let maximum = Command::parse(&stream[..MAX_LINE - 2]).unwrap();
        assert_eq!(maximum.to_bytes().unwrap().len(), MAX_LINE);
        stream.extend(vec![b'a'; MAX_BUFFERED * 2]);
        stream.extend_from_slice(b"\r\nNOOP\nQUIT\r\n");
        let expected = vec![
            Ok(maximum),
            Err(Error::LineTooLong),
            Err(Error::LineEnding),
            Ok(Command::new("QUIT", None)),
        ];
        for size in [1, 7, MAX_LINE, stream.len()] {
            for drain in [false, true] {
                assert_eq!(commands(&stream, size, drain), expected);
            }
        }
        assert!(
            Command::new("NOOP", Some(&"a".repeat(MAX_LINE - 6)))
                .to_bytes()
                .is_err()
        );
    }

    fn replies(bytes: &[u8], size: usize) -> Vec<Result<Reply, Error>> {
        let mut d = ReplyDecoder::new();
        let mut out = Vec::new();
        for mut chunk in bytes.chunks(size) {
            while !chunk.is_empty() {
                let n = d.feed(chunk);
                chunk = &chunk[n..];
                assert!(d.buffered() <= MAX_BUFFERED);
                let before = out.len();
                while let Some(reply) = d.next_reply() {
                    let failed = reply.is_err();
                    out.push(reply);
                    if failed {
                        return out;
                    }
                }
                assert!(n > 0 || out.len() > before);
            }
        }
        out
    }

    #[test]
    fn multiline_replies_require_codes_on_every_line() {
        let bytes = b"250-server.test\r\n250-PIPELINING\r\n250 SIZE 123\r\n221\r\n";
        let first = Reply {
            code: 250,
            lines: vec!["server.test".into(), "PIPELINING".into(), "SIZE 123".into()],
        };
        assert_eq!(
            Reply::parse(bytes),
            Ok(Some((first.clone(), bytes.len() - 5)))
        );
        for size in [1, 7, bytes.len()] {
            assert_eq!(
                replies(bytes, size),
                [Ok(first.clone()), Ok(Reply::new(221, ""))]
            );
        }
        for bad in [
            &b"250-hi\r\n550 done\r\n"[..],
            b"250-hi\r\n PIPELINING\r\n250 done\r\n",
            b"199 hi\r\n",
            b"260 hi\r\n",
            b"250xhi\r\n",
            b"250 hi\n",
            b"250 hi\0\r\n",
        ] {
            let error = Reply::parse(bad).unwrap_err();
            for size in [1, bad.len()] {
                assert_eq!(replies(bad, size), [Err(error)]);
            }
        }
    }

    #[test]
    fn reply_prefixes_limits_and_sticky_errors() {
        let reply = Reply {
            code: 250,
            lines: vec!["x".repeat(MAX_LINE - 6); MAX_REPLY_LINES],
        };
        let bytes = reply.to_bytes().unwrap();
        assert_eq!(Reply::parse(&bytes), Ok(Some((reply.clone(), bytes.len()))));
        assert_eq!(replies(&bytes, 7), [Ok(reply)]);
        let short = b"250-one\r\n250 two\r\n";
        for cut in 0..short.len() {
            assert_eq!(Reply::parse(&short[..cut]), Ok(None));
        }
        let endless = b"250-\r\n".repeat(MAX_REPLY_LINES);
        assert_eq!(Reply::parse(&endless), Err(Error::ReplyLines));
        assert_eq!(replies(&endless, 1), [Err(Error::ReplyLines)]);
        assert_eq!(
            Reply::new(250, &"x".repeat(MAX_LINE - 5)).to_bytes(),
            Err(Error::LineTooLong)
        );
        assert_eq!(
            Reply {
                code: 250,
                lines: vec![]
            }
            .to_bytes(),
            Err(Error::ReplyLines)
        );
        assert_eq!(Reply::new(999, "bad").to_bytes(), Err(Error::ReplyCode));
        assert_eq!(
            Reply::new(250, "ok\r\n550 bad").to_bytes(),
            Err(Error::Text)
        );
        let mut d = ReplyDecoder::new();
        assert_eq!(d.feed(b"250 bad\n"), 8);
        assert_eq!(d.next_reply(), Some(Err(Error::LineEnding)));
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.feed(short), short.len());
        assert_eq!(d.next_reply(), Some(Err(Error::LineEnding)));
    }

    fn data(bytes: &[u8], size: usize) -> Result<Vec<u8>, Error> {
        let mut d = CommandDecoder::new();
        d.start_data().unwrap();
        for mut chunk in bytes.chunks(size) {
            while !chunk.is_empty() {
                let n = d.feed(chunk);
                chunk = &chunk[n..];
                assert!(d.buffered() <= MAX_BUFFERED && d.data_buffered() <= MAX_DATA);
                if let Some(result) = d.next_data() {
                    return result;
                }
                assert!(n > 0 || d.buffered() < MAX_BUFFERED);
            }
        }
        panic!("incomplete DATA")
    }

    #[test]
    fn data_transparency_and_empty_message() {
        let message = b"Subject: hi\r\n\r\n.\r\n..dots\r\n\xff\r\n";
        let wire = write_data(message).unwrap();
        assert_eq!(wire, b"Subject: hi\r\n\r\n..\r\n...dots\r\n\xff\r\n.\r\n");
        for size in [1, 7, wire.len()] {
            assert_eq!(data(&wire, size), Ok(message.to_vec()));
        }
        assert_eq!(write_data(b""), Ok(b".\r\n".to_vec()));
        assert_eq!(data(b".\r\n", 1), Ok(vec![]));
        // RFC 5321 removes one dot even when the sender did not double it.
        assert_eq!(data(b".x\r\n.\r\n", 1), Ok(b"x\r\n".to_vec()));
    }

    #[test]
    fn data_switch_preserves_pipeline_and_tls_tail() {
        let stream = b"DATA\r\n..x\r\n.\r\nQUIT\r\nSTARTTLS\r\n\x16\x03\x03\0\x05";
        let mut d = CommandDecoder::new();
        assert_eq!(d.feed(stream), stream.len());
        assert_eq!(d.next_command(), Some(Ok(Command::new("DATA", None))));
        d.start_data().unwrap();
        assert!(d.in_data());
        assert_eq!(d.start_data(), Err(Error::State));
        assert_eq!(d.next_command(), None);
        assert_eq!(d.next_data(), Some(Ok(b".x\r\n".to_vec())));
        assert!(!d.in_data());
        assert_eq!(d.next_command(), Some(Ok(Command::new("QUIT", None))));
        assert_eq!(d.next_command(), Some(Ok(Command::new("STARTTLS", None))));
        assert_eq!(d.take_buffered(), Ok(b"\x16\x03\x03\0\x05".to_vec()));
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.feed(b"NO"), 2);
        assert_eq!(d.next_command(), None);
        assert_eq!(d.start_data(), Err(Error::State));
        assert_eq!(d.take_buffered(), Err(Error::State));
    }

    #[test]
    fn data_line_limits_count_the_unstuffed_length() {
        for dot in [false, true] {
            let mut message = vec![b'x'; MAX_DATA_LINE - 2];
            if dot {
                message[0] = b'.';
            }
            message.extend_from_slice(b"\r\n");
            let wire = write_data(&message).unwrap();
            assert_eq!(wire.len(), MAX_DATA_LINE + 3 + usize::from(dot));
            assert_eq!(data(&wire, 1), Ok(message.clone()));
            message.insert(1, b'x');
            assert_eq!(write_data(&message), Err(Error::LineTooLong));
            let mut wire = message.clone();
            if dot {
                wire.insert(0, b'.');
            }
            wire.extend_from_slice(b".\r\n");
            assert_eq!(data(&wire, 1), Err(Error::LineTooLong));
        }
        for bad in [&b"bare\n"[..], b"bare\r", b"nul\0\r\n", b"cr\rinside\r\n"] {
            assert!(write_data(bad).is_err());
        }
    }

    #[test]
    fn data_errors_are_sticky_and_release_buffers() {
        let mut d = CommandDecoder::new();
        d.start_data().unwrap();
        let bytes = b"ok\r\nbad\nQUIT\r\n";
        assert_eq!(d.feed(bytes), bytes.len());
        assert_eq!(d.next_data(), Some(Err(Error::LineEnding)));
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.data_buffered(), 0);
        assert_eq!(d.feed(b".\r\n"), 3);
        assert_eq!(d.next_data(), Some(Err(Error::LineEnding)));
        assert_eq!(d.next_command(), Some(Err(Error::LineEnding)));
        assert_eq!(d.start_data(), Err(Error::LineEnding));
    }

    #[test]
    fn data_total_size_limit() {
        let mut d = CommandDecoder::new();
        d.start_data().unwrap();
        let line = [vec![b'x'; 998], b"\r\n".to_vec()].concat();
        for _ in 0..MAX_DATA / line.len() {
            assert_eq!(d.feed(&line), line.len());
            assert_eq!(d.next_data(), None);
        }
        let remaining = MAX_DATA % line.len();
        let last = [vec![b'x'; remaining - 2], b"\r\n".to_vec()].concat();
        assert_eq!(d.feed(&last), remaining);
        assert_eq!(d.next_data(), None);
        assert_eq!(d.data_buffered(), MAX_DATA);
        assert_eq!(d.feed(b"\r\n"), 2);
        assert_eq!(d.next_data(), Some(Err(Error::TooMuchData)));
        assert_eq!(d.data_buffered(), 0);
        assert_eq!(write_data(&vec![0; MAX_DATA + 1]), Err(Error::TooMuchData));
    }
}
