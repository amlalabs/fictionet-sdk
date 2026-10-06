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
//! Run connection bytes through [`Stream<Server>`](super::codec::Stream).
//! After accepting DATA and sending a 354 reply, call [`Server::start_data`].
//! The next item is the complete unstuffed message. Its terminating dot
//! returns the reader to commands. Use [`Stream<Replies>`](super::codec::Stream)
//! on the client. Bad commands are error items; overlong lines are skipped.
//! Partial lines at EOF, DATA overflow, and malformed multiline replies end
//! the stream. Call [`Server::handoff`] after accepting STARTTLS, then take
//! the unread TLS bytes from the stream. Session state, authentication, TLS,
//! and storage belong to the caller. Read headers separately with
//! [`imf`](crate::stdlib::imf).
//!
//! ```
//! use fictionet::stdlib::{codec::{Stream, Wire}, smtp::{Server, Input, Request, Reply}};
//!
//! let mut stream = Stream::new(Server::new());
//! let bytes = b"DATA\r\nSubject: hello\r\n\r\n..a leading dot\r\n.\r\nQUIT\r\n";
//! assert_eq!(stream.push(bytes), bytes.len());
//! let Some(Ok(Ok(Input::Command(command)))) = stream.next() else { panic!() };
//! assert_eq!(Request::from_command(&command).unwrap(), Request::Data);
//! stream.decoder().start_data().unwrap();
//! assert_eq!(stream.next(), Some(Ok(Ok(Input::Message(
//!     b"Subject: hello\r\n\r\n.a leading dot\r\n".to_vec())))));
//! assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(c)))) if c.verb == "QUIT"));
//! assert_eq!(Reply::new(250, "Queued").to_bytes().unwrap(), b"250 Queued\r\n");
//! ```

extern crate alloc;
extern crate self as fictionet;

use self::alloc::{string::String, vec::Vec};
use fictionet::stdlib::codec::{self, Decode, Wire};

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
/// Why SMTP input is invalid.
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
    /// A reply exceeded [`MAX_REPLY_LINES`].
    ReplyLines,
    /// A message exceeded [`MAX_DATA`].
    TooMuchData,
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

    fn parse_line(line: &[u8]) -> Result<Self, Error> {
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

    fn validate(&self) -> Result<(), Error> {
        if self.verb.is_empty()
            || self.verb.len() > 16
            || !self.verb.bytes().all(|b| b.is_ascii_alphabetic())
        {
            return Err(Error::Verb);
        }
        let size = self
            .verb
            .len()
            .checked_add(self.arg.as_ref().map_or(0, |a| a.len().saturating_add(1)));
        if size.is_none_or(|n| n > MAX_LINE - 2) {
            return Err(Error::LineTooLong);
        }
        if let Some(arg) = &self.arg {
            text(arg.as_bytes())?;
        }
        Ok(())
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
    /// Start TLS (RFC 3207). Call [`Server::handoff`] once accepted, then
    /// pass the stream's unread bytes to TLS.
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
        command.validate()?;
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

    /// Builds the command for this request. Refuses invalid arguments,
    /// oversized fields, and `Other` values that change when parsed.
    pub fn to_command(&self) -> Result<Command, WriteError> {
        match self {
            Self::Helo(s) | Self::Ehlo(s) | Self::Vrfy(s) | Self::Expn(s) if s.len() > MAX_LINE => {
                return Err(WriteError::Unwritable);
            }
            Self::Noop(Some(s)) | Self::Help(Some(s)) if s.len() > MAX_LINE => {
                return Err(WriteError::Unwritable);
            }
            Self::Other(c) => c.validate().map_err(|_| WriteError::Unwritable)?,
            _ => {}
        }
        let command = match self {
            Self::Helo(s) => Command::new("HELO", Some(s)),
            Self::Ehlo(s) => Command::new("EHLO", Some(s)),
            Self::Mail { path, parameters } | Self::Rcpt { path, parameters } => {
                if path.len() > MAX_LINE || parameters.len() > MAX_LINE {
                    return Err(WriteError::Unwritable);
                }
                let mail = matches!(self, Self::Mail { .. });
                let mut arg = format!("{}<{path}>", if mail { "FROM:" } else { "TO:" });
                for parameter in parameters {
                    // Check lengths before building attacker-controlled strings.
                    if parameter.keyword.len() > MAX_LINE
                        || parameter.value.as_ref().is_some_and(|v| v.len() > MAX_LINE)
                    {
                        return Err(WriteError::Unwritable);
                    }
                    arg.push(' ');
                    arg.push_str(&parameter.keyword);
                    if let Some(value) = &parameter.value {
                        arg.push('=');
                        arg.push_str(value);
                    }
                    if arg.len() > MAX_LINE {
                        return Err(WriteError::Unwritable);
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
                    return Err(WriteError::Unwritable);
                }
                let mut arg = mechanism.clone();
                if let Some(response) = initial_response {
                    arg.push(' ');
                    arg.push_str(response);
                }
                Command::new("AUTH", Some(&arg))
            }
            Self::Other(command) => {
                if !matches!(
                    Self::from_command(command).map_err(|_| WriteError::Unwritable)?,
                    Self::Other(_)
                ) {
                    return Err(WriteError::Unwritable);
                }
                command.clone()
            }
        };
        if Self::from_command(&command).map_err(|_| WriteError::Unwritable)? != *self {
            return Err(WriteError::Unwritable);
        }
        Ok(command)
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

fn check_data_line(line: &[u8]) -> Result<(), Error> {
    if line.len() > MAX_DATA_LINE - 2 {
        return Err(Error::LineTooLong);
    }
    if line.iter().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
        return Err(Error::Text);
    }
    Ok(())
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
    /// A malformed line interrupted a multiline reply.
    Reply(Error),
    /// A mode change was requested outside a command boundary.
    State,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Line(e) => e.fmt(f),
            Self::Limit(e) => e.fmt(f),
            Self::Allocation => f.write_str("SMTP assembly allocation failed"),
            Self::Incomplete => f.write_str("incomplete SMTP assembly"),
            Self::Reply(e) => e.fmt(f),
            Self::State => f.write_str("SMTP mode change requires a command boundary"),
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

/// Why an SMTP, POP3, or IMAP value cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The value cannot fit its wire grammar and limits without changing.
    Unwritable,
}

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("mail value cannot be written unchanged")
    }
}
impl core::error::Error for WriteError {}

impl Wire for Command {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads exactly one command with CRLF. Refuses trailing bytes,
    /// invalid text or verbs, and lines over [`MAX_LINE`]. Unknown verbs
    /// are preserved. Verbs are normalized to uppercase.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut lines = codec::Lines::new(MAX_LINE - 2, codec::Ending::Crlf);
        match smtp_line(&mut lines, bytes, true, false).map_err(ParseError::Framing)? {
            codec::Step::Item(line, used) if used == bytes.len() => {
                Command::parse_line(&line.map_err(ParseError::Invalid)?)
                    .map_err(ParseError::Invalid)
            }
            codec::Step::Item(_, _) => Err(ParseError::Trailing),
            _ => Err(ParseError::Incomplete),
        }
    }

    /// Appends the command and CRLF. Refuses invalid verbs, non-uppercase
    /// verbs, forbidden text, and lines longer than [`MAX_LINE`].
    /// Errors leave `out` unchanged. Arguments are never changed.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        self.validate().map_err(|_| WriteError::Unwritable)?;
        if self.verb.bytes().any(|b| b.is_ascii_lowercase()) {
            return Err(WriteError::Unwritable);
        }
        let size = self.verb.len() + self.arg.as_ref().map_or(0, |a| a.len() + 1) + 2;
        out.try_reserve(size).map_err(|_| WriteError::Unwritable)?;
        out.extend_from_slice(self.verb.as_bytes());
        if let Some(arg) = &self.arg {
            out.push(b' ');
            out.extend_from_slice(arg.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        Ok(())
    }
}

impl Wire for Reply {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads one complete reply. Refuses trailing bytes, missing CRLF,
    /// invalid codes or text, mismatched continuation codes, and limits
    /// above [`MAX_LINE`], [`MAX_REPLY_LINES`], or [`MAX_REPLY_TEXT`].
    fn parse(mut bytes: &[u8]) -> Result<Self, ParseError> {
        let mut replies = Replies::new();
        loop {
            match replies.decode(bytes, true).map_err(|e| match e {
                DecodeError::Reply(e) => ParseError::Invalid(e),
                e => ParseError::Framing(e),
            })? {
                codec::Step::Item(reply, used) => {
                    let reply = reply.map_err(ParseError::Invalid)?;
                    if used != bytes.len() {
                        return Err(ParseError::Trailing);
                    }
                    return Ok(reply);
                }
                codec::Step::Skip(used) => {
                    bytes = bytes.get(used..).ok_or(ParseError::Incomplete)?
                }
                _ => return Err(ParseError::Incomplete),
            }
        }
    }

    /// Appends the reply with CRLF. Refuses invalid codes, empty or
    /// oversized line lists, forbidden text, and lines over [`MAX_LINE`].
    /// Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        if !valid_code(self.code) || self.lines.is_empty() || self.lines.len() > MAX_REPLY_LINES {
            return Err(WriteError::Unwritable);
        }
        let mut size = 0usize;
        for line in &self.lines {
            if line.len() > MAX_LINE - 6 || text(line.as_bytes()).is_err() {
                return Err(WriteError::Unwritable);
            }
            size = size
                .checked_add(line.len() + 6)
                .ok_or(WriteError::Unwritable)?;
        }
        out.try_reserve(size).map_err(|_| WriteError::Unwritable)?;
        let code = self.code.to_string();
        for (i, line) in self.lines.iter().enumerate() {
            out.extend_from_slice(code.as_bytes());
            out.push(if i + 1 == self.lines.len() {
                b' '
            } else {
                b'-'
            });
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        Ok(())
    }
}

impl Wire for Request {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads one command and interprets its arguments. Refuses invalid
    /// command framing, paths, parameters, and arguments for known verbs.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::from_command(&Command::parse(bytes)?).map_err(ParseError::Invalid)
    }

    /// Appends one request. Refuses invalid arguments and values that
    /// would parse differently. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        self.to_command()?.write(out)
    }
}

/// An unstuffed SMTP message whose wire form ends in a dot line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    /// Message bytes, including each content line's CRLF.
    pub bytes: Vec<u8>,
}

impl Wire for Data {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads one dot-terminated message and removes transparency dots.
    /// Refuses trailing bytes, missing CRLF, NUL, lines over
    /// [`MAX_DATA_LINE`], and messages over [`MAX_DATA`].
    fn parse(mut bytes: &[u8]) -> Result<Self, ParseError> {
        let mut server = Server::new();
        server.start_data().map_err(ParseError::Framing)?;
        loop {
            match server.decode(bytes, true).map_err(ParseError::Framing)? {
                codec::Step::Item(item, used) => {
                    let Input::Message(message) = item.map_err(ParseError::Invalid)? else {
                        return Err(ParseError::Incomplete);
                    };
                    if used != bytes.len() {
                        return Err(ParseError::Trailing);
                    }
                    return Ok(Self { bytes: message });
                }
                codec::Step::Skip(used) => {
                    bytes = bytes.get(used..).ok_or(ParseError::Incomplete)?
                }
                _ => return Err(ParseError::Incomplete),
            }
        }
    }

    /// Appends dot-stuffed lines and the terminating dot. Refuses NUL,
    /// bare CR or LF, unterminated content, and line or message overflow.
    /// Empty messages and 8-bit content are allowed. Errors leave `out`
    /// unchanged; extension negotiation belongs to the caller.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        if self.bytes.len() > MAX_DATA || (!self.bytes.is_empty() && !self.bytes.ends_with(b"\r\n"))
        {
            return Err(WriteError::Unwritable);
        }
        let mut size = self
            .bytes
            .len()
            .checked_add(3)
            .ok_or(WriteError::Unwritable)?;
        for line in self.bytes.split_inclusive(|b| *b == b'\n') {
            let content = line.strip_suffix(b"\r\n").ok_or(WriteError::Unwritable)?;
            check_data_line(content).map_err(|_| WriteError::Unwritable)?;
            size = size
                .checked_add(usize::from(content.starts_with(b".")))
                .ok_or(WriteError::Unwritable)?;
        }
        out.try_reserve(size).map_err(|_| WriteError::Unwritable)?;
        for line in self.bytes.split_inclusive(|b| *b == b'\n') {
            if line.starts_with(b".") {
                out.push(b'.');
            }
            out.extend_from_slice(line);
        }
        out.extend_from_slice(b".\r\n");
        Ok(())
    }
}

fn smtp_line(
    lines: &mut codec::Lines,
    input: &[u8],
    eof: bool,
    recover_long: bool,
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
        codec::Step::Item(Err(codec::LineError::TooLong { .. }), used) if recover_long => {
            codec::Step::Item(Err(Error::LineTooLong), used)
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
    End,
}

/// Reads SMTP commands and DATA over [`codec::Lines`].
///
/// CRLF is required. Command lines use [`MAX_LINE`]. DATA lines use
/// [`MAX_DATA_LINE`], plus one transparency dot on the wire. Input capacity
/// is always `MAX_DATA_LINE + 1`, so mode changes never need a larger buffer.
/// DATA assembly holds at most [`MAX_DATA`] bytes. Scanning is linear.
///
/// Malformed or overlong commands are error items; the rest of an overlong
/// line is skipped through LF. Bad DATA content rejects the message at its
/// dot terminator. DATA line overflow, unterminated lines, assembly overflow,
/// and EOF before the dot terminate the stream. An overlong command cut off
/// at EOF is skipped after its error item, then ends cleanly.
///
/// Call [`start_data`](Self::start_data) between items after accepting DATA.
/// The terminator returns to command mode, including for rejected messages.
/// Mode changes are refused while a command line is partial or being skipped.
/// For an accepted STARTTLS, call [`handoff`](Self::handoff), then use
/// [`codec::Stream::into_parts`] to obtain unread TLS bytes.
///
/// ```
/// use fictionet::stdlib::{codec::Stream, smtp::{Server, Input}};
/// let mut stream = Stream::new(Server::new());
/// assert_eq!(stream.push(b"DATA\r\n..x\r\n.\r\nQUIT\r\n"), 20);
/// assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(_))))));
/// stream.decoder().start_data().unwrap();
/// assert_eq!(stream.next(), Some(Ok(Ok(Input::Message(b".x\r\n".to_vec())))));
/// assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(_))))));
/// ```
pub struct Server {
    lines: codec::Lines,
    mode: Mode,
    partial: bool,
    skipping: bool,
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
            skipping: false,
            data: Vec::new(),
            data_size: 0,
            rejected: None,
        }
    }

    /// Starts DATA at a command boundary after the world accepts it.
    /// Refuses other modes, partial lines, and lines still being skipped
    /// with [`DecodeError::State`], without changing the mode.
    pub fn start_data(&mut self) -> Result<(), DecodeError> {
        if self.mode != Mode::Command || self.partial || self.skipping {
            return Err(DecodeError::State);
        }
        self.mode = Mode::Data;
        self.lines = codec::Lines::new(MAX_DATA_LINE - 1, codec::Ending::Crlf);
        Ok(())
    }

    /// Ends SMTP decoding at a command boundary for an accepted protocol switch.
    /// Refuses other modes, partial lines, and lines still being skipped
    /// with [`DecodeError::State`], without changing the mode.
    pub fn handoff(&mut self) -> Result<(), DecodeError> {
        if self.mode != Mode::Command || self.partial || self.skipping {
            return Err(DecodeError::State);
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
        let (line, used) = match smtp_line(&mut self.lines, input, eof, true)? {
            codec::Step::Item(line, used) => (line, used),
            codec::Step::Need => {
                self.partial = !input.is_empty();
                return if eof && self.mode == Mode::Data {
                    Err(DecodeError::Incomplete)
                } else {
                    Ok(codec::Step::Need)
                };
            }
            codec::Step::Skip(used) => {
                self.skipping = input.get(used.saturating_sub(1)) != Some(&b'\n');
                return Ok(codec::Step::Skip(used));
            }
            codec::Step::End => return Ok(codec::Step::End),
        };
        self.partial = false;
        if self.mode == Mode::Command {
            self.skipping = matches!(line, Err(Error::LineTooLong))
                && input.get(used.saturating_sub(1)) != Some(&b'\n');
            return Ok(codec::Step::Item(
                line.and_then(|b| Command::parse_line(&b))
                    .map(Input::Command),
                used,
            ));
        }
        if line.as_deref() == Ok(b".".as_slice()) {
            self.mode = Mode::Command;
            self.lines = codec::Lines::new(MAX_LINE - 2, codec::Ending::Crlf);
            self.data_size = 0;
            let data = core::mem::take(&mut self.data);
            return Ok(codec::Step::Item(
                self.rejected
                    .take()
                    .map_or_else(|| Ok(Input::Message(data)), Err),
                used,
            ));
        }
        if matches!(line, Err(Error::LineTooLong)) {
            return Err(DecodeError::Limit(Error::LineTooLong));
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
/// [`MAX_REPLY_TEXT`]. A malformed line outside an assembly yields an error
/// item. A malformed line within a multiline reply ends the stream so its
/// remaining lines cannot be mistaken for another reply. Oversized lines and
/// assemblies, or EOF in a continuation, also end the stream.
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
        let (line, used) = match smtp_line(&mut self.lines, input, eof, false)? {
            codec::Step::Item(line, used) => (line, used),
            codec::Step::Need if eof && self.pending.is_some() => {
                return Err(DecodeError::Incomplete);
            }
            codec::Step::Need => return Ok(codec::Step::Need),
            codec::Step::Skip(used) => return Ok(codec::Step::Skip(used)),
            codec::Step::End => return Ok(codec::Step::End),
        };
        let pending = self.pending.is_some();
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
            self.text_size = self
                .text_size
                .checked_add(text.len())
                .filter(|&size| size <= MAX_REPLY_TEXT)
                .ok_or(Error::ReplyLines)?;
            reply.lines.push(text.to_string());
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
            Err(e) if pending => Err(DecodeError::Reply(e)),
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
    use codec::{
        Fail, Stream, contract,
        test_support::{Lcg, decode_all, mutate},
    };

    fn data_server() -> Server {
        let mut server = Server::new();
        server.start_data().unwrap();
        server
    }

    fn refused(value: &impl Wire<WriteError = WriteError>) {
        let mut out = b"prefix".to_vec();
        assert_eq!(value.write(&mut out), Err(WriteError::Unwritable));
        assert_eq!(out, b"prefix");
    }

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
            let command = Command::parse(format!("{line}\r\n").as_bytes()).unwrap();
            let bytes = command.to_bytes().unwrap();
            assert_eq!(
                Command::parse(&bytes),
                Ok(command.clone())
            );
            let request = Request::from_command(&command).unwrap();
            let bytes = request.to_bytes().unwrap();
            let back = Command::parse(&bytes).unwrap();
            assert_eq!(Request::from_command(&back), Ok(request));
        }
        let command = Command::parse(b"MAIL FROM:<> SIZE=0\r\n").unwrap();
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
            let c = Command::parse(format!("{line}\r\n").as_bytes()).unwrap();
            assert_eq!(Request::from_command(&c), Err(Error::Argument), "{line}");
        }
        for line in [&b"NOOP\r\nQUIT"[..], b"NOOP\0", b"\xff", b"NOOP\x7f"] {
            assert!(Command::parse(&[line, b"\r\n"].concat()).is_err());
        }
        assert!(Command::new("NOOP QUIT", None).to_bytes().is_err());
        assert!(Command::new("NOOP", Some("x\r\nQUIT")).to_bytes().is_err());
        assert_eq!(
            Request::Other(Command::new("DATA", None)).to_bytes(),
            Err(WriteError::Unwritable)
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


    #[test]
    fn command_line_limits_and_recovery() {
        let maximum = Command::new("NOOP", Some(&"a".repeat(MAX_LINE - 7)));
        let mut wire = maximum.to_bytes().unwrap();
        assert_eq!(wire.len(), MAX_LINE);
        wire.extend(vec![b'a'; MAX_LINE * 64]);
        wire.extend_from_slice(b"\r\nNOOP\nQUIT\r\n");
        let expected = vec![
            Ok(Input::Command(maximum)),
            Err(Error::LineTooLong),
            Err(Error::LineEnding),
            Ok(Input::Command(Command::new("QUIT", None))),
        ];
        assert_eq!(decode_all(Server::new, &wire), (expected, None));
        contract::check_decode_with_alloc_limit(Server::new, &wire, 2 * (MAX_DATA_LINE + 1));
        refused(&Command::new("NOOP", Some(&"a".repeat(MAX_LINE - 6))));
    }

    #[test]
    fn multiline_replies_require_codes_on_every_line() {
        let bytes = b"250-server.test\r\n250-PIPELINING\r\n250 SIZE 123\r\n221\r\n";
        let first = Reply {
            code: 250,
            lines: vec!["server.test".into(), "PIPELINING".into(), "SIZE 123".into()],
        };
        assert_eq!(Reply::parse(&bytes[..bytes.len() - 5]), Ok(first.clone()));
        assert_eq!(
            decode_all(Replies::new, bytes),
            (vec![Ok(first), Ok(Reply::new(221, ""))], None)
        );
        contract::check_decode_with_alloc_limit(Replies::new, bytes, 2 * MAX_LINE);
        for bad in [
            b"250-hi\r\n550 done\r\n".as_slice(),
            b"250-hi\r\n PIPELINING\r\n250 done\r\n",
            b"199 hi\r\n",
            b"260 hi\r\n",
            b"250xhi\r\n",
            b"250 hi\n",
            b"250 hi\0\r\n",
        ] {
            assert!(Reply::parse(bad).is_err());
            let (items, failure) = decode_all(Replies::new, bad);
            assert!(failure.is_some() || items.iter().any(Result::is_err));
            contract::check_decode_with_alloc_limit(Replies::new, bad, 2 * MAX_LINE);
        }
    }

    #[test]
    fn reply_prefixes_limits_and_terminal_errors() {
        let reply = Reply {
            code: 250,
            lines: vec!["x".repeat(MAX_LINE - 6); MAX_REPLY_LINES],
        };
        let bytes = reply.to_bytes().unwrap();
        assert_eq!(Reply::parse(&bytes), Ok(reply.clone()));
        assert_eq!(decode_all(Replies::new, &bytes), (vec![Ok(reply)], None));
        let short = b"250-one\r\n250 two\r\n";
        for cut in 0..short.len() {
            assert!(Reply::parse(&short[..cut]).is_err());
        }
        contract::check_decode_with_alloc_limit(Replies::new, short, 2 * MAX_LINE);
        let endless = b"250-\r\n".repeat(MAX_REPLY_LINES);
        assert_eq!(
            decode_all(Replies::new, &endless).1,
            Some(Fail::Protocol(DecodeError::Limit(Error::ReplyLines)))
        );
        for reply in [
            Reply::new(250, &"x".repeat(MAX_LINE - 5)),
            Reply {
                code: 250,
                lines: vec![],
            },
            Reply::new(999, "bad"),
            Reply::new(250, "ok\r\n550 bad"),
        ] {
            refused(&reply);
        }
        let mut stream = Stream::new(Replies::new());
        let bad = b"250-first\r\n550 bad\r\n";
        assert_eq!(stream.push(bad), bad.len());
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(DecodeError::Reply(
                Error::ReplyMismatch
            ))))
        );
        assert_eq!(stream.next(), None);
        assert!(stream.failed().is_some());
    }

    #[test]
    fn data_transparency_and_empty_message() {
        let message = Data {
            bytes: b"Subject: hi\r\n\r\n.\r\n..dots\r\n\xff\r\n".to_vec(),
        };
        let wire = message.to_bytes().unwrap();
        assert_eq!(wire, b"Subject: hi\r\n\r\n..\r\n...dots\r\n\xff\r\n.\r\n");
        assert_eq!(Data::parse(&wire), Ok(message));
        contract::check_wire::<Data>(&wire);
        contract::check_decode_with_alloc_limit(data_server, &wire, 2 * (MAX_DATA_LINE + 1));
        assert_eq!(Data { bytes: vec![] }.to_bytes().unwrap(), b".\r\n");
        assert_eq!(Data::parse(b".\r\n").unwrap().bytes, b"");
        assert_eq!(Data::parse(b".x\r\n.\r\n").unwrap().bytes, b"x\r\n");
    }

    #[test]
    fn data_switch_preserves_pipeline_and_tls_tail() {
        let bytes = b"DATA\r\n..x\r\n.\r\nQUIT\r\nSTARTTLS\r\n\x16\x03\x03\0\x05";
        let mut stream = Stream::new(Server::new());
        assert_eq!(stream.push(bytes), bytes.len());
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(Input::Command(Command::new("DATA", None)))))
        );
        stream.decoder().start_data().unwrap();
        assert_eq!(stream.decoder().start_data(), Err(DecodeError::State));
        assert_eq!(stream.decoder().handoff(), Err(DecodeError::State));
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(Input::Message(b".x\r\n".to_vec()))))
        );
        for verb in ["QUIT", "STARTTLS"] {
            assert_eq!(
                stream.next(),
                Some(Ok(Ok(Input::Command(Command::new(verb, None)))))
            );
        }
        stream.decoder().handoff().unwrap();
        assert_eq!(stream.next(), None);
        assert_eq!(stream.into_parts().0.unread(), b"\x16\x03\x03\0\x05");
        let mut stream = Stream::new(Server::new());
        assert_eq!(stream.push(b"NO"), 2);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().start_data(), Err(DecodeError::State));
        assert_eq!(stream.decoder().handoff(), Err(DecodeError::State));
    }

    #[test]
    fn data_line_limits_count_the_unstuffed_length() {
        for dot in [false, true] {
            let mut message = Data {
                bytes: vec![b'x'; MAX_DATA_LINE - 2],
            };
            if dot {
                message.bytes[0] = b'.';
            }
            message.bytes.extend_from_slice(b"\r\n");
            let wire = message.to_bytes().unwrap();
            assert_eq!(wire.len(), MAX_DATA_LINE + 3 + usize::from(dot));
            assert_eq!(Data::parse(&wire), Ok(message.clone()));
            contract::check_decode_with_alloc_limit(data_server, &wire, 2 * (MAX_DATA_LINE + 1));
            message.bytes.insert(1, b'x');
            refused(&message);
            let mut wire = message.bytes;
            if dot {
                wire.insert(0, b'.');
            }
            wire.extend_from_slice(b".\r\n");
            assert_eq!(
                decode_all(data_server, &wire).1,
                Some(Fail::Protocol(DecodeError::Limit(Error::LineTooLong)))
            );
        }
        for bad in [
            b"bare\n".as_slice(),
            b"bare\r",
            b"nul\0\r\n",
            b"cr\rinside\r\n",
        ] {
            refused(&Data {
                bytes: bad.to_vec(),
            });
        }
    }

    #[test]
    fn data_errors_reject_the_message_and_return_to_commands() {
        let bytes = b"ok\r\nbad\nQUIT\r\n.\r\nNOOP\r\n";
        assert_eq!(
            decode_all(data_server, bytes),
            (
                vec![
                    Err(Error::LineEnding),
                    Ok(Input::Command(Command::new("NOOP", None)))
                ],
                None
            )
        );
        contract::check_decode_with_alloc_limit(data_server, bytes, 2 * (MAX_DATA_LINE + 1));
    }

    #[test]
    fn data_total_size_limit() {
        let mut stream = Stream::new(data_server());
        let line = [vec![b'x'; 998], b"\r\n".to_vec()].concat();
        for _ in 0..MAX_DATA / line.len() {
            assert_eq!(stream.push(&line), line.len());
            assert_eq!(stream.next(), None);
        }
        let remaining = MAX_DATA % line.len();
        let last = [vec![b'x'; remaining - 2], b"\r\n".to_vec()].concat();
        assert_eq!(stream.push(&last), remaining);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.held(), MAX_DATA);
        assert_eq!(stream.push(b"\r\n"), 2);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(DecodeError::Limit(Error::TooMuchData))))
        );
        assert_eq!(stream.next(), None);
        refused(&Data {
            bytes: vec![0; MAX_DATA + 1],
        });
    }

    #[test]
    fn mutated_streams_and_values_obey_contracts() {
        let seeds: &[&[u8]] = &[
            b"EHLO example.test\r\nDATA\r\n",
            b"250-one\r\n250 done\r\n",
            b"..dot\r\n.\r\n",
        ];
        let mut rng = Lcg::new(25);
        for _ in 0..128 {
            let mut bytes = seeds[rng.index(seeds.len())].to_vec();
            mutate(&mut rng, &mut bytes);
            contract::check_decode_with_alloc_limit(Server::new, &bytes, 2 * (MAX_DATA_LINE + 1));
            contract::check_decode_with_alloc_limit(Replies::new, &bytes, 2 * MAX_LINE);
            contract::check_decode_with_alloc_limit(data_server, &bytes, 2 * (MAX_DATA_LINE + 1));
            contract::check_wire::<Command>(&bytes);
            contract::check_wire::<Request>(&bytes);
            contract::check_wire::<Reply>(&bytes);
            contract::check_wire::<Data>(&bytes);
            contract::check_wire_value(&Command::new(&rng.text(20), Some(&rng.text(520))));
            contract::check_wire_value(&Data {
                bytes: rng.bytes(100),
            });
        }
    }
}
