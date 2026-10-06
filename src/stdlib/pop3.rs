//! POP3: reading and writing commands and replies, with no I/O.
//!
//! POP3 is how a mail client downloads mail from its server. The client
//! connects over TCP, usually to port 110, and sends commands one per
//! line, such as `USER alice` or `RETR 1`. The server answers each with a
//! status line that starts `+OK` or `-ERR`. Some answers carry a body
//! after the status line: a message, a list of messages, or a list of
//! capabilities. The body is sent a line at a time and ends with a line
//! holding a single dot. A body line that starts with a dot gets a second
//! dot in front of it, so it is never read as the end. This module follows
//! RFC 1939 (POP3), RFC 2449 (`CAPA` and response codes such as
//! `[IN-USE]`), RFC 2595 (`STLS`) and RFC 3206 (the `SYS` and `AUTH`
//! response codes).
//!
//! Run a server's connection bytes through
//! [`Stream<Commands>`](fictionet::stdlib::codec::Stream), interpret each [`Request`],
//! and write a [`Reply`]. Clients use [`Stream<Replies>`](fictionet::stdlib::codec::Stream)
//! and queue whether each reply has a body with [`Replies::expect`]. CRLF is
//! required. Bad or overlong commands are error items. Overlong command
//! remainders are skipped through LF, including at EOF. Short partial lines
//! at EOF end the stream. Bad status lines end the stream when a body was
//! expected; other bad status lines are error items. Bodies are bounded by
//! [`MAX_BODY`] and their wire lines by [`MAX_DATA_LINE`]. Mailboxes,
//! authentication, and message storage belong to world code.
//!
//! During AUTH (RFC 5034), select one raw line between items with
//! [`Commands::expect_line`] or [`Replies::expect_line`]. A challenge (`+`
//! alone or `+ ` and data) leaves AUTH's reply expectation queued. A final
//! status line consumes it.
//!
//! ```
//! use fictionet::stdlib::{codec::{Stream, Wire}, pop3::{Commands, Input, Request, Reply, Replies, Output}};
//!
//! let mut commands = Stream::new(Commands::new());
//! assert_eq!(commands.push(b"USER alice\r\n"), 12);
//! let Some(Ok(Ok(Input::Command(command)))) = commands.next() else { panic!() };
//! assert_eq!(Request::from_command(&command).unwrap(), Request::User("alice".into()));
//! let mut out = Vec::new();
//! Reply::ok("alice is welcome").write(&mut out).unwrap();
//! let mut replies = Stream::new(Replies::new());
//! replies.decoder().expect(false).unwrap();
//! assert_eq!(replies.push(&out), out.len());
//! assert_eq!(replies.next(), Some(Ok(Ok(Output::Reply(Reply::ok("alice is welcome"))))));
//! ```

extern crate alloc;

use self::alloc::{collections::VecDeque, string::String, vec::Vec};
use fictionet::stdlib::codec::{self, Decode, Wire};
use std::num::NonZeroU32;

/// The TCP port POP3 servers listen on.
pub const PORT: u16 = 110;
/// The longest command line, counting its CRLF (RFC 2449, section 4).
/// RFC 1939 also held each argument to 40 bytes. RFC 2449 lifts that
/// limit, so an argument is held only by the length of the line.
pub const MAX_COMMAND_LINE: usize = 255;
/// The shortest command keyword. A keyword is printable ASCII other than
/// space (RFC 2449, section 3).
pub const MIN_KEYWORD: usize = 3;
/// The longest command keyword.
pub const MAX_KEYWORD: usize = 4;
/// The longest status line, the first line of a reply, counting its CRLF
/// (RFC 2449, section 4).
pub const MAX_REPLY_LINE: usize = 512;
/// The longest line of a reply's body, as sent, counting its CRLF. RFC 1939
/// sets no limit. RFC 5322 allows mail lines of 1000 bytes, and this is
/// well above that.
pub const MAX_DATA_LINE: usize = 4096;
/// The most bytes a reply's body may hold, after the dots added in front
/// of lines are taken off, counting the CRLF of every line.
pub const MAX_BODY: usize = 8 << 20;
/// The longest response code, the text between the brackets: what fits in
/// a `+OK` status line with no text. RFC 2449 sets no limit of its own, so
/// a code is held only by the length of its line. A `-ERR` line has room
/// for one byte less.
pub const MAX_CODE: usize = MAX_REPLY_LINE - 8;
/// The longest raw line [`Commands::expect_line`] and [`Replies::expect_line`]
/// select, excluding CRLF. The base64
/// lines of an `AUTH` exchange have no limit of their own (RFC 5034,
/// section 4), and this is well above what common mechanisms send.
pub const MAX_AUTH_LINE: usize = 16 << 10;
/// The longest unique-id a `UIDL` listing may give (RFC 1939, section 7).
pub const MAX_UID: usize = 70;

/// Response codes from RFC 2449 and RFC 3206. A server puts one in
/// brackets after the status, as in `-ERR [IN-USE] Mailbox locked`.
pub mod code {
    /// The user may not log in again so soon (RFC 2449).
    pub const LOGIN_DELAY: &str = "LOGIN-DELAY";
    /// The mailbox is locked by another session (RFC 2449).
    pub const IN_USE: &str = "IN-USE";
    /// A passing problem on the server. Trying later may work (RFC 3206).
    pub const SYS_TEMP: &str = "SYS/TEMP";
    /// A lasting problem on the server (RFC 3206).
    pub const SYS_PERM: &str = "SYS/PERM";
    /// The credentials were wrong (RFC 3206).
    pub const AUTH: &str = "AUTH";
}

/// One command line, split into its keyword and the text after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// The keyword, such as `RETR`, in upper case. Keywords are three or
    /// four printable ASCII characters other than space.
    pub keyword: String,
    /// Everything after the space that follows the keyword, or `None` if
    /// nothing follows it.
    pub argument: Option<String>,
}

/// Why a line is not a command. A server answers with `-ERR` and reads the
/// next line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    /// The line exceeded [`MAX_COMMAND_LINE`], or [`MAX_AUTH_LINE`] in raw mode.
    LineTooLong,
    /// The line was not UTF-8, or held a control character.
    BadCharacter,
    /// The keyword was not three or four printable ASCII characters.
    BadKeyword,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CommandError::LineTooLong => "command line too long",
            CommandError::BadCharacter => "bad character in command line",
            CommandError::BadKeyword => "bad command keyword",
        })
    }
}

impl std::error::Error for CommandError {}

impl Command {
    fn parse_line(line: &[u8]) -> Result<Command, CommandError> {
        if line.len() > MAX_COMMAND_LINE - 2 {
            return Err(CommandError::LineTooLong);
        }
        let s = std::str::from_utf8(line).map_err(|_| CommandError::BadCharacter)?;
        if s.chars().any(char::is_control) {
            return Err(CommandError::BadCharacter);
        }
        let (keyword, argument) = match s.split_once(' ') {
            Some((k, a)) => (k, Some(a)),
            None => (s, None),
        };
        if !(MIN_KEYWORD..=MAX_KEYWORD).contains(&keyword.len())
            || !keyword.bytes().all(|c| c.is_ascii_graphic())
        {
            return Err(CommandError::BadKeyword);
        }
        Ok(Command {
            keyword: keyword.to_ascii_uppercase(),
            argument: argument.filter(|a| !a.is_empty()).map(String::from),
        })
    }
}

/// A command this module knows, with its arguments read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// `USER name`: the mailbox to log in to.
    User(String),
    /// `PASS string`: the password, after `USER`. It is the whole rest of
    /// the line, spaces included (RFC 1939, section 7).
    Pass(String),
    /// `APOP name digest`: log in with the MD5 digest of the greeting's
    /// timestamp and a shared secret, in place of `USER` and `PASS`.
    Apop {
        /// The mailbox.
        name: String,
        /// The 16-byte digest, sent as 32 hex digits.
        digest: [u8; 16],
    },
    /// `STAT`: how many messages there are, and their size.
    Stat,
    /// `LIST [msg]`: the size of one message, or of every message.
    List(Option<NonZeroU32>),
    /// `RETR msg`: one whole message.
    Retr(NonZeroU32),
    /// `DELE msg`: mark a message to be deleted at `QUIT`.
    Dele(NonZeroU32),
    /// `NOOP`: do nothing.
    Noop,
    /// `RSET`: unmark every message marked for deletion.
    Rset,
    /// `QUIT`: delete marked messages and close.
    Quit,
    /// `TOP msg n`: a message's headers and the first `lines` lines of its
    /// body.
    Top {
        /// The message.
        msg: NonZeroU32,
        /// How many lines of the body to send.
        lines: u32,
    },
    /// `UIDL [msg]`: the unique-id of one message, or of every message.
    Uidl(Option<NonZeroU32>),
    /// `CAPA`: the server's capabilities (RFC 2449).
    Capa,
    /// `STLS`: start TLS on this connection (RFC 2595). Bytes a decoder
    /// still holds after this command came in the clear, so a server
    /// starts a new [`Commands`] stream once TLS is up.
    Stls,
    /// An unknown keyword, such as `AUTH`. The writer refuses keywords
    /// that would parse as a known request.
    Other(Command),
}

/// Why a known command's arguments are wrong. A server answers with
/// `-ERR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgumentError {
    /// An argument the command needs is not there.
    Missing,
    /// There are more arguments than the command takes.
    Extra,
    /// Arguments were not split by single spaces.
    Spacing,
    /// A number was not decimal digits, did not fit, or was a message
    /// number of 0.
    BadNumber,
    /// An `APOP` digest was not 32 hex digits.
    BadDigest,
}

impl std::fmt::Display for ArgumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ArgumentError::Missing => "missing argument",
            ArgumentError::Extra => "too many arguments",
            ArgumentError::Spacing => "arguments must be split by single spaces",
            ArgumentError::BadNumber => "bad number",
            ArgumentError::BadDigest => "digest must be 32 hex digits",
        })
    }
}

impl std::error::Error for ArgumentError {}

impl Request {
    /// Reads a command's arguments. A keyword this module does not know
    /// gives [`Request::Other`].
    pub fn from_command(c: &Command) -> Result<Request, ArgumentError> {
        let keyword = c.keyword.to_ascii_uppercase();
        let arg = c.argument.as_deref().filter(|a| !a.is_empty());
        let args = || split_args(arg);
        let none = || match arg {
            None => Ok(()),
            Some(_) => Err(ArgumentError::Extra),
        };
        Ok(match keyword.as_str() {
            "USER" => {
                let [name] = exact(args()?)?;
                Request::User(name.to_string())
            }
            "PASS" => Request::Pass(arg.ok_or(ArgumentError::Missing)?.to_string()),
            "APOP" => {
                let [name, digest] = exact(args()?)?;
                Request::Apop {
                    name: name.to_string(),
                    digest: parse_digest(digest)?,
                }
            }
            "STAT" => none().map(|()| Request::Stat)?,
            "LIST" => Request::List(optional(args()?)?.map(message).transpose()?),
            "RETR" => {
                let [m] = exact(args()?)?;
                Request::Retr(message(m)?)
            }
            "DELE" => {
                let [m] = exact(args()?)?;
                Request::Dele(message(m)?)
            }
            "NOOP" => none().map(|()| Request::Noop)?,
            "RSET" => none().map(|()| Request::Rset)?,
            "QUIT" => none().map(|()| Request::Quit)?,
            "TOP" => {
                let [m, n] = exact(args()?)?;
                let lines = decimal(n)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or(ArgumentError::BadNumber)?;
                Request::Top {
                    msg: message(m)?,
                    lines,
                }
            }
            "UIDL" => Request::Uidl(optional(args()?)?.map(message).transpose()?),
            "CAPA" => none().map(|()| Request::Capa)?,
            "STLS" => none().map(|()| Request::Stls)?,
            _ => Request::Other(c.clone()),
        })
    }

    /// Builds a command without changing credentials or arguments.
    /// Refuses fields that exceed the command limit or parse differently.
    pub fn to_command(&self) -> Result<Command, WriteError> {
        let short = |s: &str| {
            if s.len() > MAX_COMMAND_LINE {
                Err(WriteError::Unwritable)
            } else {
                Ok(s.to_string())
            }
        };
        let with = |keyword: &str, argument: Option<String>| Command {
            keyword: keyword.to_string(),
            argument,
        };
        let command = match self {
            Self::User(name) => with("USER", Some(short(name)?)),
            Self::Pass(password) => with("PASS", Some(short(password)?)),
            Self::Apop { name, digest } => {
                let name = short(name)?;
                let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                with("APOP", Some(format!("{name} {hex}")))
            }
            Self::Stat => with("STAT", None),
            Self::List(m) => with("LIST", m.map(|m| m.to_string())),
            Self::Retr(m) => with("RETR", Some(m.to_string())),
            Self::Dele(m) => with("DELE", Some(m.to_string())),
            Self::Noop => with("NOOP", None),
            Self::Rset => with("RSET", None),
            Self::Quit => with("QUIT", None),
            Self::Top { msg, lines } => with("TOP", Some(format!("{msg} {lines}"))),
            Self::Uidl(m) => with("UIDL", m.map(|m| m.to_string())),
            Self::Capa => with("CAPA", None),
            Self::Stls => with("STLS", None),
            Self::Other(c) => {
                c.validate()?;
                c.clone()
            }
        };
        command.validate()?;
        if Self::from_command(&command).as_ref() != Ok(self) {
            return Err(WriteError::Unwritable);
        }
        Ok(command)
    }

    /// Whether a `+OK` answer to this request carries a body: `LIST` and
    /// `UIDL` with no argument, `RETR`, `TOP` and `CAPA`. A `-ERR` answer
    /// never does. Pass this to [`Replies::expect`].
    pub fn multi_line(&self) -> bool {
        matches!(
            self,
            Request::List(None)
                | Request::Uidl(None)
                | Request::Retr(_)
                | Request::Top { .. }
                | Request::Capa
        )
    }
}

/// One reply: the status line and, for some commands, a body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Whether the status was `+OK` rather than `-ERR`.
    pub ok: bool,
    /// The response code, without its brackets, such as `SYS/TEMP`
    /// (RFC 2449, section 8).
    pub code: Option<String>,
    /// UTF-8 text after the status and response code, without NUL or CR/LF.
    pub text: String,
    /// The body, for a reply that has one, with the extra dots taken off.
    /// Every line in it ends with CRLF.
    pub body: Option<Vec<u8>>,
}

/// Why a status line is not a reply. A pending body makes this fatal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// The status line did not start with `+OK` or `-ERR` followed by a
    /// space or the end of the line, or its text was not UTF-8 without
    /// NUL, CR, or LF.
    BadStatus,
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReplyError::BadStatus => "status is not +OK or -ERR",
        })
    }
}

impl std::error::Error for ReplyError {}

/// Why one item from [`Replies`] was rejected at a known boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyItemError {
    /// A malformed status line, or [`ReplyError::BadStatus`] for a raw AUTH
    /// challenge ending in bare LF.
    Reply(ReplyError),
    /// A body line used bare LF or contained an embedded CR. The whole
    /// reply is rejected at its dot terminator.
    BadBodyLine,
}

impl core::fmt::Display for ReplyItemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Reply(e) => e.fmt(f),
            Self::BadBodyLine => f.write_str("body line requires CRLF without embedded CR"),
        }
    }
}

impl core::error::Error for ReplyItemError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Reply(e) => Some(e),
            Self::BadBodyLine => None,
        }
    }
}

impl Reply {
    /// A `+OK` reply with this text.
    pub fn ok(text: &str) -> Reply {
        Reply {
            ok: true,
            code: None,
            text: text.to_string(),
            body: None,
        }
    }

    /// A `-ERR` reply with this text.
    pub fn err(text: &str) -> Reply {
        Reply {
            ok: false,
            code: None,
            text: text.to_string(),
            body: None,
        }
    }

    /// The reply with a response code, such as [`code::IN_USE`].
    pub fn with_code(mut self, code: &str) -> Reply {
        self.code = Some(code.to_string());
        self
    }

    /// The reply with a body. The writer requires CRLF on every line.
    pub fn with_body(mut self, body: Vec<u8>) -> Reply {
        self.body = Some(body);
        self
    }

    /// The answer to `STAT`: how many messages, and their size in bytes.
    pub fn stat(count: u32, octets: u64) -> Reply {
        Reply::ok(&format!("{count} {octets}"))
    }

    fn parse_line(line: &[u8]) -> Result<Reply, ReplyError> {
        let (ok, rest) = if let Some(r) = line.strip_prefix(b"+OK") {
            (true, r)
        } else if let Some(r) = line.strip_prefix(b"-ERR") {
            (false, r)
        } else {
            return Err(ReplyError::BadStatus);
        };
        let rest = match rest {
            [] => rest,
            [b' ', t @ ..] => t,
            _ => return Err(ReplyError::BadStatus),
        };
        let rest = core::str::from_utf8(rest).map_err(|_| ReplyError::BadStatus)?;
        if rest.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
            return Err(ReplyError::BadStatus);
        }
        let (code, text) = match split_code(rest.as_bytes()) {
            Some((code, text)) => (
                Some(
                    core::str::from_utf8(code)
                        .map_err(|_| ReplyError::BadStatus)?
                        .to_string(),
                ),
                core::str::from_utf8(text)
                    .map_err(|_| ReplyError::BadStatus)?
                    .to_string(),
            ),
            None => (None, rest.to_string()),
        };
        Ok(Reply {
            ok,
            code,
            text,
            body: None,
        })
    }

    /// Whether the reply's response code is `code` or a more detailed form
    /// of it. Codes are compared without regard to case, and levels after
    /// `code` are ignored, as RFC 2449, section 8 asks of clients. So a
    /// reply with `[sys/temp/disk]` has the code [`code::SYS_TEMP`] and the
    /// code `SYS`. An empty `code` matches nothing.
    pub fn has_code(&self, code: &str) -> bool {
        let Some(own) = self.code.as_deref() else {
            return false;
        };
        let (own, want) = (own.as_bytes(), code.as_bytes());
        !want.is_empty()
            && own
                .get(..want.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(want))
            && matches!(own.get(want.len()), None | Some(b'/'))
    }

    /// The body's lines, without their line ends, one at a time. A reply
    /// with no body has none.
    pub fn lines(&self) -> impl Iterator<Item = &[u8]> {
        self.body.as_deref().into_iter().flat_map(body_lines)
    }

    /// The timestamp a server's greeting offers for `APOP`, such as
    /// `<1896.697170952@dbc.mit.edu>`, brackets included. It is the first
    /// `<` and the next `>`, with only printable ASCII other than space
    /// between them (RFC 2449, section 3).
    pub fn timestamp(&self) -> Option<&str> {
        let start = self.text.find('<')?;
        let end = start.checked_add(self.text.get(start..)?.find('>')?)?;
        let stamp = self.text.get(start..=end)?;
        stamp.bytes().all(|c| c.is_ascii_graphic()).then_some(stamp)
    }

    /// The count and size an answer to `STAT` gives. Text after the size's
    /// digits is allowed and ignored (RFC 1939, section 5).
    pub fn drop_listing(&self) -> Option<(u32, u64)> {
        let mut parts = self.text.splitn(2, ' ');
        let count = u32::try_from(decimal(parts.next()?)?).ok()?;
        Some((count, leading_decimal(parts.next()?)?))
    }
}

/// Reads a scan listing, `msg octets`: one line of the answer to `LIST`,
/// or the text of the answer to `LIST msg`. Text after the size's digits
/// is allowed and ignored (RFC 1939, section 5).
fn parse_scan_listing(line: &[u8]) -> Option<(NonZeroU32, u64)> {
    let s = std::str::from_utf8(line).ok()?;
    let (msg, rest) = s.split_once(' ')?;
    Some((message(msg).ok()?, leading_decimal(rest)?))
}

/// Reads a unique-id listing, `msg uid`: one line of the answer to
/// `UIDL`, or the text of the answer to `UIDL msg`. The unique-id is 1 to
/// [`MAX_UID`] printable ASCII characters other than space.
fn parse_unique_id_listing(line: &[u8]) -> Option<(NonZeroU32, String)> {
    let s = std::str::from_utf8(line).ok()?;
    let (msg, uid) = s.split_once(' ')?;
    if uid.is_empty() || uid.len() > MAX_UID || !uid.bytes().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    Some((message(msg).ok()?, uid.to_string()))
}

/// A command's arguments: how many there are, and the first few. No
/// command takes more than two, so the rest are only counted.
struct Args<'a> {
    first: [&'a str; 3],
    count: usize,
}

/// Splits an argument at single spaces, without keeping more than three
/// pieces, however many spaces it holds.
fn split_args(arg: Option<&str>) -> Result<Args<'_>, ArgumentError> {
    let mut out = Args {
        first: [""; 3],
        count: 0,
    };
    for piece in arg.into_iter().flat_map(|a| a.split(' ')) {
        if piece.is_empty() {
            return Err(ArgumentError::Spacing);
        }
        if let Some(slot) = out.first.get_mut(out.count) {
            *slot = piece;
        }
        out.count = out.count.saturating_add(1);
    }
    Ok(out)
}

/// Exactly `N` arguments.
fn exact<const N: usize>(args: Args<'_>) -> Result<[&str; N], ArgumentError> {
    match args.count.cmp(&N) {
        std::cmp::Ordering::Less => Err(ArgumentError::Missing),
        std::cmp::Ordering::Greater => Err(ArgumentError::Extra),
        std::cmp::Ordering::Equal => args
            .first
            .get(..N)
            .and_then(|a| a.try_into().ok())
            .ok_or(ArgumentError::Missing),
    }
}

/// No arguments or one.
fn optional(args: Args<'_>) -> Result<Option<&str>, ArgumentError> {
    match args.count {
        0 => Ok(None),
        1 => Ok(Some(args.first[0])),
        _ => Err(ArgumentError::Extra),
    }
}

/// A message number: decimal, 1 or more.
fn message(s: &str) -> Result<NonZeroU32, ArgumentError> {
    decimal(s)
        .and_then(|n| u32::try_from(n).ok())
        .and_then(NonZeroU32::new)
        .ok_or(ArgumentError::BadNumber)
}

/// Decimal digits only, no sign, fitting in a `u64`. Leading zeros are
/// allowed, however many there are.
fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    s.bytes().try_fold(0u64, |n, c| {
        let d = c.checked_sub(b'0').filter(|&d| d < 10)?;
        n.checked_mul(10)?.checked_add(u64::from(d))
    })
}

/// The decimal digits `s` starts with, one or more, read as by `decimal`.
/// What follows them is ignored.
fn leading_decimal(s: &str) -> Option<u64> {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    decimal(s.get(..digits)?)
}

fn parse_digest(s: &str) -> Result<[u8; 16], ArgumentError> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return Err(ArgumentError::BadDigest);
    }
    let mut out = [0u8; 16];
    for (o, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        let hi = hex(pair[0]).ok_or(ArgumentError::BadDigest)?;
        let lo = hex(pair[1]).ok_or(ArgumentError::BadDigest)?;
        *o = hi << 4 | lo;
    }
    Ok(out)
}

fn hex(c: u8) -> Option<u8> {
    char::from(c)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Splits a response code off the start of status text: the code without
/// its brackets, and the text after it with one space taken off. It gives
/// `None` if the text does not start with a code. The status line holds
/// the code to [`MAX_CODE`] bytes.
fn split_code(rest: &[u8]) -> Option<(&[u8], &[u8])> {
    let after = rest.strip_prefix(b"[")?;
    let end = after.iter().position(|&c| c == b']')?;
    let (inner, tail) = (after.get(..end)?, after.get(end + 1..)?);
    if !inner
        .split(|&c| c == b'/')
        .all(|l| !l.is_empty() && l.iter().all(|&c| rchar(c)))
    {
        return None;
    }
    Some((inner, tail.strip_prefix(b" ").unwrap_or(tail)))
}

/// Whether a byte may be in one level of a response code (RFC 2449,
/// section 9): printable ASCII other than `/` and `]`.
fn rchar(c: u8) -> bool {
    (0x21..=0x7f).contains(&c) && c != b'/' && c != b']'
}

/// A body's lines: split at LF, with the CR before each LF dropped. A last
/// line with no LF counts as a line, and loses a CR at its end too.
/// This only inspects content for [`Reply::lines`]; it does not write it.
fn body_lines(body: &[u8]) -> impl Iterator<Item = &[u8]> {
    let body = (!body.is_empty()).then(|| body.strip_suffix(b"\n").unwrap_or(body));
    body.into_iter()
        .flat_map(|b| b.split(|&c| c == b'\n'))
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

/// Maximum queued reply expectations in [`Replies`]. This is a local limit.
pub const MAX_EXPECTATIONS: usize = 1024;
/// Maximum retained reply bytes and expectation entries in [`Replies`].
pub const MAX_REPLY_HELD: usize = MAX_BODY + MAX_REPLY_LINE + MAX_EXPECTATIONS;

/// Why a shared POP3 decoder cannot continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A line exceeded its limit or ended before CRLF.
    Line(codec::LineError),
    /// The body exceeded [`MAX_BODY`].
    BodyTooLong,
    /// Storage for a bounded body could not be allocated.
    Allocation,
    /// EOF interrupted a multiline response.
    Incomplete,
    /// Input arrived without a queued reply expectation.
    MissingExpectation,
    /// The expectation queue reached [`MAX_EXPECTATIONS`].
    ExpectationsFull,
    /// A malformed status line made a multiline reply's boundary uncertain.
    Reply(ReplyError),
    /// A raw line was requested while a line or body was in progress.
    State,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Line(e) => e.fmt(f),
            Self::BodyTooLong => f.write_str("POP3 body exceeds its limit"),
            Self::Allocation => f.write_str("POP3 body allocation failed"),
            Self::Incomplete => f.write_str("incomplete POP3 body"),
            Self::MissingExpectation => f.write_str("POP3 reply needs an expectation"),
            Self::ExpectationsFull => f.write_str("POP3 expectation queue is full"),
            Self::Reply(e) => e.fmt(f),
            Self::State => f.write_str("POP3 raw line requires a line boundary"),
        }
    }
}
impl core::error::Error for DecodeError {}

/// Why bytes are not exactly one POP3 wire value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A complete command is malformed.
    Command(CommandError),
    /// A complete reply is malformed.
    Reply(ReplyItemError),
    /// A known command has invalid arguments.
    Argument(ArgumentError),
    /// A scan or unique-id listing is invalid or oversized.
    Listing,
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
            Self::Command(e) => e.fmt(f),
            Self::Reply(e) => e.fmt(f),
            Self::Argument(e) => e.fmt(f),
            Self::Listing => f.write_str("invalid POP3 listing"),
            Self::Framing(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete POP3 value"),
            Self::Trailing => f.write_str("bytes after POP3 value"),
        }
    }
}
impl core::error::Error for ParseError {}

/// Why a POP3 value cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The value cannot fit its wire grammar and limits without changing.
    Unwritable,
}

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("POP3 value cannot be written without changing it")
    }
}
impl core::error::Error for WriteError {}

impl Command {
    fn validate(&self) -> Result<(), WriteError> {
        let size = self.keyword.len().checked_add(
            self.argument
                .as_ref()
                .map_or(0, |a| a.len().saturating_add(1)),
        );
        if size.is_none_or(|n| n > MAX_COMMAND_LINE - 2)
            || !(MIN_KEYWORD..=MAX_KEYWORD).contains(&self.keyword.len())
            || !self
                .keyword
                .bytes()
                .all(|b| b.is_ascii_graphic() && !b.is_ascii_lowercase())
            || self
                .argument
                .as_ref()
                .is_some_and(|a| a.is_empty() || a.chars().any(char::is_control))
        {
            return Err(WriteError::Unwritable);
        }
        Ok(())
    }
}

impl Wire for Command {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads exactly one command with CRLF. Refuses trailing bytes,
    /// controls, invalid UTF-8, invalid keywords, and oversized lines.
    /// Keywords become uppercase; empty arguments become `None`.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut lines = codec::Lines::new(MAX_COMMAND_LINE - 2, codec::Ending::Crlf);
        match pop_line(&mut lines, bytes, true, false).map_err(ParseError::Framing)? {
            codec::Step::Item(line, used) if used == bytes.len() => {
                let line = line.map_err(|_| ParseError::Command(CommandError::BadCharacter))?;
                Command::parse_line(&line).map_err(ParseError::Command)
            }
            codec::Step::Item(_, _) => Err(ParseError::Trailing),
            _ => Err(ParseError::Incomplete),
        }
    }

    /// Appends one command with CRLF. Refuses invalid or lowercase
    /// keywords, empty arguments, control characters, and oversized lines.
    /// Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        self.validate()?;
        let size = self
            .keyword
            .len()
            .checked_add(self.argument.as_ref().map_or(0, String::len))
            .and_then(|n| n.checked_add(usize::from(self.argument.is_some())))
            .and_then(|n| n.checked_add(2))
            .ok_or(WriteError::Unwritable)?;
        out.try_reserve(size).map_err(|_| WriteError::Unwritable)?;
        out.extend_from_slice(self.keyword.as_bytes());
        if let Some(arg) = &self.argument {
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

    /// Reads exactly one status line, or a status and a dot-terminated body.
    /// Refuses trailing bytes, invalid status text, missing CRLF, embedded
    /// CR in bodies, and line or body overflow. Bracketed text is a code
    /// only when it fits RFC 2449's grammar. Text may follow `]` directly
    /// or after one space; other bracketed text stays plain text.
    ///
    /// The supplied slice defines the whole value. Bytes after its status
    /// line must form its body. Stream callers must use [`Replies::expect`]
    /// because a stream has no such enclosing boundary.
    fn parse(mut bytes: &[u8]) -> Result<Self, ParseError> {
        let body = bytes
            .iter()
            .take(MAX_REPLY_LINE)
            .position(|&b| b == b'\n')
            .is_some_and(|n| n.saturating_add(1) < bytes.len());
        let mut replies = Replies::new();
        replies.expect(body).map_err(ParseError::Framing)?;
        loop {
            match replies.decode(bytes, true).map_err(|e| match e {
                DecodeError::Reply(e) => ParseError::Reply(ReplyItemError::Reply(e)),
                e => ParseError::Framing(e),
            })? {
                codec::Step::Item(reply, used) => {
                    let Output::Reply(reply) = reply.map_err(ParseError::Reply)? else {
                        return Err(ParseError::Incomplete);
                    };
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

    /// Appends the status and dot-stuffed body. Refuses invalid codes,
    /// ambiguous text, NUL or CR/LF in status text, and bodies on `-ERR`.
    /// Body lines must already end in CRLF without embedded CR. Line and
    /// body limits apply. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let status = if self.ok {
            b"+OK".as_slice()
        } else {
            b"-ERR".as_slice()
        };
        if self.text.len() > MAX_REPLY_LINE - 2
            || self.text.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n'))
            || (!self.ok && self.body.is_some())
            || self.body.as_ref().is_some_and(|b| b.len() > MAX_BODY)
        {
            return Err(WriteError::Unwritable);
        }
        let mut size = status.len();
        let mut space = !self.text.is_empty();
        if let Some(code) = &self.code {
            if code.len() > MAX_CODE
                || !code
                    .split('/')
                    .all(|s| !s.is_empty() && s.bytes().all(rchar))
            {
                return Err(WriteError::Unwritable);
            }
            size = size
                .checked_add(code.len() + 3)
                .ok_or(WriteError::Unwritable)?;
            let room = (MAX_REPLY_LINE - 2)
                .checked_sub(size)
                .ok_or(WriteError::Unwritable)?;
            if self.text.len() == room && !self.text.starts_with(' ') {
                space = false;
            }
        } else if split_code(self.text.as_bytes()).is_some() {
            return Err(WriteError::Unwritable);
        }
        size = size
            .checked_add(self.text.len() + usize::from(space) + 2)
            .filter(|&n| n <= MAX_REPLY_LINE)
            .ok_or(WriteError::Unwritable)?;
        if let Some(body) = &self.body {
            if !body.is_empty() && !body.ends_with(b"\r\n") {
                return Err(WriteError::Unwritable);
            }
            for line in body.split_inclusive(|b| *b == b'\n') {
                let content = line.strip_suffix(b"\r\n").ok_or(WriteError::Unwritable)?;
                let stuffed = usize::from(content.starts_with(b"."));
                if content.contains(&b'\r') || line.len().saturating_add(stuffed) > MAX_DATA_LINE {
                    return Err(WriteError::Unwritable);
                }
                size = size
                    .checked_add(line.len() + stuffed)
                    .ok_or(WriteError::Unwritable)?;
            }
            size = size.checked_add(3).ok_or(WriteError::Unwritable)?;
        }
        out.try_reserve(size).map_err(|_| WriteError::Unwritable)?;
        out.extend_from_slice(status);
        if let Some(code) = &self.code {
            out.extend_from_slice(b" [");
            out.extend_from_slice(code.as_bytes());
            out.push(b']');
        }
        if space {
            out.push(b' ');
        }
        out.extend_from_slice(self.text.as_bytes());
        out.extend_from_slice(b"\r\n");
        if let Some(body) = &self.body {
            for line in body.split_inclusive(|b| *b == b'\n') {
                if line.starts_with(b".") {
                    out.push(b'.');
                }
                out.extend_from_slice(line);
            }
            out.extend_from_slice(b".\r\n");
        }
        Ok(())
    }
}

impl Wire for Request {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads a command and its arguments. Refuses invalid command framing,
    /// spacing, counts, message numbers, and APOP digests.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::from_command(&Command::parse(bytes)?).map_err(ParseError::Argument)
    }

    /// Appends one request. Refuses invalid or oversized credentials and
    /// `Other` values that change when parsed. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        self.to_command()?.write(out)
    }
}

/// One LIST entry, without a line ending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanListing {
    /// The nonzero message number.
    pub message: NonZeroU32,
    /// Message size in octets.
    pub octets: u64,
}

impl Wire for ScanListing {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads `msg octets`. Refuses missing or overflowing numbers, a zero
    /// message number, CR/LF, and lines over [`MAX_DATA_LINE`] minus CRLF.
    /// Text after the size's digits is ignored, as RFC 1939 permits.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() > MAX_DATA_LINE - 2 || bytes.iter().any(|b| matches!(b, b'\r' | b'\n')) {
            return Err(ParseError::Listing);
        }
        let (message, octets) = parse_scan_listing(bytes).ok_or(ParseError::Listing)?;
        Ok(Self { message, octets })
    }

    /// Appends decimal numbers separated by a space. Refuses allocation
    /// failure and leaves `out` unchanged. Every value fits the line limit.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let line = format!("{} {}", self.message, self.octets);
        out.try_reserve(line.len())
            .map_err(|_| WriteError::Unwritable)?;
        out.extend_from_slice(line.as_bytes());
        Ok(())
    }
}

/// One UIDL entry, without a line ending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniqueIdListing {
    /// The nonzero message number.
    pub message: NonZeroU32,
    /// One to [`MAX_UID`] printable ASCII bytes other than space.
    pub id: String,
}

impl Wire for UniqueIdListing {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads `msg uid`. Refuses zero or overflowing message numbers,
    /// empty or oversized IDs, spaces in IDs, and non-printable ASCII.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() > MAX_DATA_LINE - 2 {
            return Err(ParseError::Listing);
        }
        let (message, id) = parse_unique_id_listing(bytes).ok_or(ParseError::Listing)?;
        Ok(Self { message, id })
    }

    /// Appends a message number and ID. Refuses empty or oversized IDs,
    /// spaces, and non-printable ASCII. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        if self.id.is_empty()
            || self.id.len() > MAX_UID
            || !self.id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(WriteError::Unwritable);
        }
        let message = self.message.to_string();
        let size = message
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(self.id.len()))
            .ok_or(WriteError::Unwritable)?;
        out.try_reserve(size).map_err(|_| WriteError::Unwritable)?;
        out.extend_from_slice(message.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.id.as_bytes());
        Ok(())
    }
}

fn pop_line(
    lines: &mut codec::Lines,
    input: &[u8],
    eof: bool,
    recover_long: bool,
) -> Result<codec::Step<Result<Vec<u8>, codec::LineError>>, DecodeError> {
    let step = match lines.decode(input, eof) {
        Ok(step) => step,
        Err(never) => match never {},
    };
    match step {
        codec::Step::Item(Err(e @ codec::LineError::Unterminated), _) => Err(DecodeError::Line(e)),
        codec::Step::Item(Err(e @ codec::LineError::TooLong { .. }), _) if !recover_long => {
            Err(DecodeError::Line(e))
        }
        step => Ok(step),
    }
}

/// One client command or raw AUTH answer from [`Commands`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// A parsed command.
    Command(Command),
    /// A raw line without CRLF, selected by [`Commands::expect_line`].
    Line(Vec<u8>),
}

/// One server reply or raw AUTH challenge from [`Replies`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// A complete reply, including its body when expected.
    Reply(Reply),
    /// An AUTH challenge without CRLF, selected by [`Replies::expect_line`].
    Line(Vec<u8>),
}

/// Reads POP3 commands over CRLF lines bounded by [`MAX_COMMAND_LINE`].
///
/// This retains RFC 2449's command limit, which extends RFC 1939.
/// Syntax errors, bare LF, and overlong lines are error items; the decoder
/// skips the rest of an overlong line through LF, then reads the next line.
/// Every line error except [`codec::LineError::TooLong`] maps to
/// [`CommandError::BadCharacter`]: a missing CR is invalid command framing,
/// while unterminated lines end the stream through [`DecodeError::Line`]
/// before this item mapping.
/// An overlong line cut off at EOF is skipped after its error item, then
/// ends cleanly. No input is retained.
/// Call [`expect_line`](Self::expect_line) between items for one raw AUTH
/// answer, bounded by [`MAX_AUTH_LINE`] bytes excluding CRLF. Input capacity
/// is always `MAX_AUTH_LINE + 2`, so mode changes fit the same buffer.
pub struct Commands {
    lines: codec::Lines,
    raw_line: bool,
    partial: bool,
    skipping: bool,
}

impl Default for Commands {
    fn default() -> Self {
        Self::new()
    }
}

impl Commands {
    /// Creates a decoder with no pending command.
    pub fn new() -> Self {
        Self {
            lines: codec::Lines::new(MAX_COMMAND_LINE - 2, codec::Ending::Crlf),
            raw_line: false,
            partial: false,
            skipping: false,
        }
    }

    /// Selects one raw AUTH answer or cancellation line, without parsing it.
    /// Call between items. Refuses a partial line, a line still being skipped,
    /// or an already selected raw line, without changing the mode.
    pub fn expect_line(&mut self) -> Result<(), DecodeError> {
        if self.partial || self.skipping || self.raw_line {
            return Err(DecodeError::State);
        }
        self.raw_line = true;
        self.lines = codec::Lines::new(MAX_AUTH_LINE, codec::Ending::Crlf);
        Ok(())
    }
}

impl Decode for Commands {
    type Item = Result<Input, CommandError>;
    type Error = DecodeError;
    const NAME: &'static str = "POP3 commands";

    fn capacity(&self) -> usize {
        MAX_AUTH_LINE + 2
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<codec::Step<Self::Item>, DecodeError> {
        Ok(match pop_line(&mut self.lines, input, eof, true)? {
            codec::Step::Item(line, used) => {
                self.partial = false;
                self.skipping = matches!(line, Err(codec::LineError::TooLong { .. }))
                    && input.get(used.saturating_sub(1)) != Some(&b'\n');
                let raw = core::mem::take(&mut self.raw_line);
                if !self.skipping {
                    self.lines = codec::Lines::new(MAX_COMMAND_LINE - 2, codec::Ending::Crlf);
                }
                codec::Step::Item(
                    line.map_err(|e| match e {
                        codec::LineError::TooLong { .. } => CommandError::LineTooLong,
                        _ => CommandError::BadCharacter,
                    })
                    .and_then(|b| {
                        if raw {
                            Ok(Input::Line(b))
                        } else {
                            Command::parse_line(&b).map(Input::Command)
                        }
                    }),
                    used,
                )
            }
            codec::Step::Skip(used) => {
                self.skipping = input.get(used.saturating_sub(1)) != Some(&b'\n');
                if !self.skipping {
                    self.lines = codec::Lines::new(MAX_COMMAND_LINE - 2, codec::Ending::Crlf);
                }
                codec::Step::Skip(used)
            }
            codec::Step::Need => {
                self.partial = !input.is_empty();
                codec::Step::Need
            }
            codec::Step::End => codec::Step::End,
        })
    }
}

/// Reads POP3 replies using the world's bounded expectation queue.
///
/// Call [`expect`](Self::expect) for each reply, including `expect(false)`
/// for the greeting. A `-ERR` consumes an expectation without reading a body.
/// An empty queue never implies a reply mode. Queue changes happen between
/// items. The active response keeps the expectation consumed at its status.
/// During AUTH, call [`expect_line`](Self::expect_line) between items,
/// before each line that may be a challenge. The next line is read in one of
/// two ways, then the decoder returns to status mode. A challenge (`+`
/// alone, or `+ ` and data, RFC 5034 section 4) is [`Output::Line`] and
/// consumes no expectation; the queued one remains for AUTH's final reply.
/// Any other line is that final `+OK` or `-ERR`, read as a status line: it
/// consumes the expectation and gives [`Output::Reply`], or the error item
/// or stream error a bad status line gives. A server may refuse AUTH with
/// no challenge at all, so the client cannot know which comes. Challenges
/// use [`MAX_AUTH_LINE`] excluding CRLF; a status line still uses
/// [`MAX_REPLY_LINE`]. Input capacity is always `MAX_AUTH_LINE + 2`.
///
/// CRLF is required. Status lines use RFC 1939's [`MAX_REPLY_LINE`]. Body
/// lines use the local [`MAX_DATA_LINE`], including stuffing and CRLF;
/// RFC 1939 supplies no body-line maximum. Dot-stuffing is removed and
/// [`MAX_BODY`] bounds the assembled body. Scanning is linear.
/// A malformed status line is an error item for a single-line expectation,
/// and ends the stream for a multiline expectation. A bad body line rejects
/// its whole reply at the terminator with [`ReplyItemError::BadBodyLine`].
/// This covers bare LF and embedded CR. A bare LF after an AUTH challenge
/// yields [`ReplyItemError::Reply`] wrapping [`ReplyError::BadStatus`] and
/// leaves the queued expectation for the final reply. Line overflow,
/// unterminated lines, and incomplete bodies end the stream. Retained state
/// is bounded by [`MAX_REPLY_HELD`].
///
/// ```
/// use fictionet::stdlib::{codec::Stream, pop3::{Replies, Output}};
/// let mut replies = Stream::new(Replies::new());
/// replies.decoder().expect(true).unwrap();
/// let bytes = b"+OK message\r\n..x\r\n.\r\n";
/// assert_eq!(replies.push(bytes), bytes.len());
/// let Output::Reply(reply) = replies.next().unwrap().unwrap().unwrap() else { panic!() };
/// assert_eq!(reply.body, Some(b".x\r\n".to_vec()));
/// ```
pub struct Replies {
    lines: codec::Lines,
    expected: VecDeque<bool>,
    raw_line: bool,
    partial: bool,
    pending: Option<Reply>,
    body_size: usize,
    rejected: bool,
}

impl Default for Replies {
    fn default() -> Self {
        Self::new()
    }
}

impl Replies {
    /// Creates a decoder with an empty expectation queue.
    pub fn new() -> Self {
        Self {
            lines: codec::Lines::new(MAX_REPLY_LINE - 2, codec::Ending::Crlf),
            expected: VecDeque::new(),
            raw_line: false,
            partial: false,
            pending: None,
            body_size: 0,
            rejected: false,
        }
    }

    /// Queues whether a successful reply has a body. Refuses a full queue
    /// without changing it. Call between items as each command is sent.
    pub fn expect(&mut self, multi_line: bool) -> Result<(), DecodeError> {
        if self.expected.len() >= MAX_EXPECTATIONS {
            return Err(DecodeError::ExpectationsFull);
        }
        self.expected.push_back(multi_line);
        Ok(())
    }

    /// Selects one raw AUTH challenge line without consuming a reply expectation.
    /// Call between items, before a line that may be a challenge. If the line
    /// is AUTH's final `+OK` or `-ERR` instead, it is read as a reply and
    /// consumes the expectation. Refuses an active body, a partial line, or
    /// an already selected raw line without changing state.
    pub fn expect_line(&mut self) -> Result<(), DecodeError> {
        if self.pending.is_some() || self.partial || self.raw_line {
            return Err(DecodeError::State);
        }
        self.raw_line = true;
        self.lines = codec::Lines::new(MAX_AUTH_LINE, codec::Ending::Crlf);
        Ok(())
    }

    /// Number of queued expectations, excluding the active body.
    pub fn expected(&self) -> usize {
        self.expected.len()
    }
}

impl Decode for Replies {
    type Item = Result<Output, ReplyItemError>;
    type Error = DecodeError;
    const NAME: &'static str = "POP3 replies";

    fn capacity(&self) -> usize {
        MAX_AUTH_LINE + 2
    }

    fn held(&self) -> usize {
        self.expected
            .len()
            .saturating_add(self.pending.as_ref().map_or(0, |r| {
                r.text
                    .len()
                    .saturating_add(r.code.as_ref().map_or(0, String::len))
                    .saturating_add(r.body.as_ref().map_or(0, Vec::len))
            }))
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<codec::Step<Self::Item>, DecodeError> {
        if !self.raw_line && self.pending.is_none() && self.expected.is_empty() && !input.is_empty()
        {
            return Err(DecodeError::MissingExpectation);
        }
        let (line, used) = match pop_line(&mut self.lines, input, eof, false)? {
            codec::Step::Item(line, used) => (line, used),
            codec::Step::Need if eof && self.pending.is_some() => {
                return Err(DecodeError::Incomplete);
            }
            codec::Step::Need => {
                self.partial = !input.is_empty();
                return Ok(codec::Step::Need);
            }
            codec::Step::Skip(used) => return Ok(codec::Step::Skip(used)),
            codec::Step::End => return Ok(codec::Step::End),
        };
        self.partial = false;
        if core::mem::take(&mut self.raw_line) {
            self.lines = codec::Lines::new(MAX_REPLY_LINE - 2, codec::Ending::Crlf);
            // The line as sent, without its LF or CRLF. A challenge is `+`
            // alone or `+ ` and data (RFC 5034, section 4). Anything else is
            // the final status line and takes AUTH's expectation.
            let sent = input.get(..used).unwrap_or_default();
            let sent = sent.strip_suffix(b"\n").unwrap_or(sent);
            let sent = sent.strip_suffix(b"\r").unwrap_or(sent);
            if sent == b"+" || sent.starts_with(b"+ ") {
                return Ok(codec::Step::Item(
                    line.map(Output::Line)
                        .map_err(|_| ReplyItemError::Reply(ReplyError::BadStatus)),
                    used,
                ));
            }
            // A status line is held to its own limit, as in status mode.
            if sent.len() > MAX_REPLY_LINE - 2 {
                return Err(DecodeError::Line(codec::LineError::TooLong {
                    max: MAX_REPLY_LINE - 2,
                }));
            }
        }
        if self.pending.is_none() {
            let multi = self
                .expected
                .pop_front()
                .ok_or(DecodeError::MissingExpectation)?;
            let reply = line.map_err(|_| ReplyError::BadStatus).and_then(|b| {
                if b.iter().any(|b| matches!(b, 0 | b'\r')) || core::str::from_utf8(&b).is_err() {
                    return Err(ReplyError::BadStatus);
                }
                Reply::parse_line(&b)
            });
            match reply {
                Ok(mut reply) if reply.ok && multi => {
                    reply.body = Some(Vec::new());
                    self.pending = Some(reply);
                    self.lines = codec::Lines::new(MAX_DATA_LINE - 2, codec::Ending::Crlf);
                    return Ok(codec::Step::Skip(used));
                }
                Err(e) if multi => return Err(DecodeError::Reply(e)),
                reply => {
                    return Ok(codec::Step::Item(
                        reply.map(Output::Reply).map_err(ReplyItemError::Reply),
                        used,
                    ));
                }
            }
        }
        if line.as_deref() == Ok(b".".as_slice()) {
            let reply = self
                .pending
                .take()
                .ok_or(ReplyItemError::Reply(ReplyError::BadStatus));
            self.lines = codec::Lines::new(MAX_REPLY_LINE - 2, codec::Ending::Crlf);
            self.body_size = 0;
            return Ok(codec::Step::Item(
                if core::mem::take(&mut self.rejected) {
                    Err(ReplyItemError::BadBodyLine)
                } else {
                    reply.map(Output::Reply)
                },
                used,
            ));
        }
        self.body_size = self
            .body_size
            .checked_add(used)
            .and_then(|n| {
                n.checked_sub(usize::from(
                    line.as_ref().is_ok_and(|b| b.starts_with(b".")),
                ))
            })
            .filter(|&n| n <= MAX_BODY)
            .ok_or(DecodeError::BodyTooLong)?;
        match line {
            Ok(line) if !line.contains(&b'\r') && !self.rejected => {
                if let Some(body) = self.pending.as_mut().and_then(|r| r.body.as_mut()) {
                    if self.body_size > body.capacity() {
                        let target = self
                            .body_size
                            .max(body.capacity().saturating_mul(2))
                            .min(MAX_BODY);
                        body.try_reserve_exact(target.saturating_sub(body.len()))
                            .map_err(|_| DecodeError::Allocation)?;
                    }
                    body.extend_from_slice(line.strip_prefix(b".").unwrap_or(&line));
                    body.extend_from_slice(b"\r\n");
                }
            }
            _ => {
                self.rejected = true;
                if let Some(body) = self.pending.as_mut().and_then(|r| r.body.as_mut()) {
                    body.clear();
                }
            }
        }
        Ok(codec::Step::Skip(used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{
        Fail, Stream, contract,
        Lcg, test_support::{decode_all, mutate},
    };

    fn scan(bytes: &[u8]) -> Option<(NonZeroU32, u64)> {
        ScanListing::parse(bytes)
            .ok()
            .map(|v| (v.message, v.octets))
    }
    fn n(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).unwrap()
    }
    fn command(line: &[u8]) -> Result<Command, ParseError> {
        Command::parse(&[line, b"\r\n"].concat())
    }
    fn status(line: &[u8]) -> Result<Reply, ParseError> {
        Reply::parse(&[line, b"\r\n"].concat())
    }
    fn request(line: &[u8]) -> Result<Request, ArgumentError> {
        Request::from_command(&command(line).unwrap())
    }
    fn refused(value: &impl Wire<WriteError = WriteError>) {
        let mut out = b"prefix".to_vec();
        assert_eq!(value.write(&mut out), Err(WriteError::Unwritable));
        assert_eq!(out, b"prefix");
    }
    fn reply_reader(multi: bool) -> Replies {
        let mut replies = Replies::new();
        replies.expect(multi).unwrap();
        replies
    }
    #[test]
    fn argument_errors() {
        assert_eq!(request(b"USER"), Err(ArgumentError::Missing));
        assert_eq!(request(b"PASS"), Err(ArgumentError::Missing));
        assert_eq!(request(b"USER a b"), Err(ArgumentError::Extra));
        assert_eq!(request(b"USER  a"), Err(ArgumentError::Spacing));
        assert_eq!(request(b"LIST 1 "), Err(ArgumentError::Spacing));
        assert_eq!(request(b"APOP mrose"), Err(ArgumentError::Missing));
        assert_eq!(request(b"APOP mrose c4c9"), Err(ArgumentError::BadDigest));
        assert_eq!(
            request(b"APOP mrose c4c9334bac560ecc979e58001b3e22fg"),
            Err(ArgumentError::BadDigest)
        );
        assert_eq!(request(b"STAT 1"), Err(ArgumentError::Extra));
        assert_eq!(request(b"NOOP x"), Err(ArgumentError::Extra));
        assert_eq!(request(b"RSET x"), Err(ArgumentError::Extra));
        assert_eq!(request(b"QUIT x"), Err(ArgumentError::Extra));
        assert_eq!(request(b"CAPA x"), Err(ArgumentError::Extra));
        assert_eq!(request(b"LIST 1 2"), Err(ArgumentError::Extra));
        assert_eq!(request(b"UIDL 1 2"), Err(ArgumentError::Extra));
        assert_eq!(request(b"RETR"), Err(ArgumentError::Missing));
        assert_eq!(request(b"DELE"), Err(ArgumentError::Missing));
        assert_eq!(request(b"TOP 1"), Err(ArgumentError::Missing));
        assert_eq!(request(b"TOP 1 2 3"), Err(ArgumentError::Extra));
        for bad in [
            "0",
            "-1",
            "+1",
            "1a",
            "4294967296",
            "99999999999999999999999",
        ] {
            assert_eq!(
                request(format!("RETR {bad}").as_bytes()),
                Err(ArgumentError::BadNumber),
                "{bad}"
            );
            assert_eq!(
                request(format!("LIST {bad}").as_bytes()),
                Err(ArgumentError::BadNumber),
                "{bad}"
            );
        }
        assert_eq!(request(b"RETR 4294967295"), Ok(Request::Retr(n(u32::MAX))));
        assert_eq!(request(b"RETR 007"), Ok(Request::Retr(n(7))));
        assert_eq!(request(b"TOP 1 x"), Err(ArgumentError::BadNumber));
        assert_eq!(request(b"TOP 1 4294967296"), Err(ArgumentError::BadNumber));
        assert_eq!(request(b"DELE 0"), Err(ArgumentError::BadNumber));
        assert_eq!(request(b"UIDL 0"), Err(ArgumentError::BadNumber));
    }

    #[test]
    fn command_errors() {
        assert_eq!(
            command(b""),
            Err(ParseError::Command(CommandError::BadKeyword))
        );
        assert_eq!(
            command(b"RE 1"),
            Err(ParseError::Command(CommandError::BadKeyword))
        );
        assert_eq!(
            command(b"RETRY 1"),
            Err(ParseError::Command(CommandError::BadKeyword))
        );
        assert_eq!(
            command(b"RE\xc3\xa9 1"),
            Err(ParseError::Command(CommandError::BadKeyword))
        );
        assert_eq!(
            command(b" RETR 1"),
            Err(ParseError::Command(CommandError::BadKeyword))
        );
        assert_eq!(
            command(b"RETR\t1"),
            Err(ParseError::Command(CommandError::BadCharacter))
        );
        assert_eq!(
            command(b"PASS a\rb"),
            Err(ParseError::Command(CommandError::BadCharacter))
        );
        assert_eq!(
            command(b"PASS \xff"),
            Err(ParseError::Command(CommandError::BadCharacter))
        );
        assert_eq!(
            command(b"PASS \x7f"),
            Err(ParseError::Command(CommandError::BadCharacter))
        );
        let long = [b"PASS ".as_slice(), &[b'a'; 249]].concat();
        assert!(matches!(
            command(&long),
            Err(ParseError::Framing(DecodeError::Line(
                codec::LineError::TooLong { .. }
            )))
        ));
        assert!(command(&long[..253]).is_ok());
        // Unknown keywords are commands still, and requests of their own.
        let auth = command(b"AUTH PLAIN").unwrap();
        assert_eq!(
            auth,
            Command {
                keyword: "AUTH".into(),
                argument: Some("PLAIN".into())
            }
        );
        assert_eq!(
            Request::from_command(&auth),
            Ok(Request::Other(auth.clone()))
        );
        assert_eq!(
            command(b"UTF8"),
            Ok(Command {
                keyword: "UTF8".into(),
                argument: None
            })
        );
        // A space with nothing after it is no argument.
        assert_eq!(
            command(b"LIST "),
            Ok(Command {
                keyword: "LIST".into(),
                argument: None
            })
        );
        // Passwords keep their spaces, and may be long.
        assert_eq!(
            request(b"PASS open sesame "),
            Ok(Request::Pass("open sesame ".into()))
        );
        let pass = [b"PASS ".as_slice(), &[b'p'; 200]].concat();
        assert_eq!(request(&pass), Ok(Request::Pass("p".repeat(200))));
    }

    #[test]
    fn rfc2595_stls() {
        assert_eq!(request(b"STLS"), Ok(Request::Stls));
        assert_eq!(Request::Stls.to_bytes().unwrap(), b"STLS\r\n");
        assert!(status(b"+OK Begin TLS negotiation").unwrap().ok);
        assert_eq!(request(b"STLS now"), Err(ArgumentError::Extra));
    }

    #[test]
    fn codes_match_without_case_and_detail() {
        // RFC 2449, section 8: codes are read in any case, and clients
        // ignore detail they do not know.
        let r = status(b"-ERR [sys/temp/disk] full").unwrap();
        assert!(r.has_code(code::SYS_TEMP));
        assert!(r.has_code("SYS"));
        assert!(!r.has_code(code::SYS_PERM));
        assert!(!r.has_code("SY"));
        assert!(!r.has_code(""));
        assert!(!Reply::err("x").has_code(code::AUTH));
    }

    #[test]
    fn numbers_may_have_many_leading_zeros() {
        assert_eq!(
            request(b"RETR 0000000000000000000000001"),
            Ok(Request::Retr(n(1)))
        );
    }

    #[test]
    fn timestamp_is_printable() {
        // timestamp = "<" *VCHAR ">" (RFC 2449, section 3).
        assert_eq!(Reply::ok("ready <a b>").timestamp(), None);
        assert_eq!(Reply::ok("ready <a@b> x").timestamp(), Some("<a@b>"));
    }

    #[test]
    fn body_lines_preserve_content() {
        for body in [
            &b""[..],
            b"\n",
            b"a",
            b"a\n",
            b"a\n\n",
            b"\r\n\r",
            b"a\r\r\nb\r",
        ] {
            let lines: Vec<&[u8]> = body_lines(body).collect();
            let mut want: Vec<&[u8]> = body.split(|&c| c == b'\n').collect();
            if body.is_empty() || body.ends_with(b"\n") {
                want.pop();
            }
            for l in &mut want {
                *l = l.strip_suffix(b"\r").unwrap_or(l);
            }
            assert_eq!(lines, want, "{body:?}");
        }
    }

    #[test]
    fn sizes_may_have_text_right_after_them() {
        // RFC 1939, section 5 sets no rule on what follows the size.
        assert_eq!(Reply::ok("2 320(octets)").drop_listing(), Some((2, 320)));
        assert_eq!(Reply::ok("2 320 octets").drop_listing(), Some((2, 320)));
        assert_eq!(scan(b"1 120(octets)"), Some((n(1), 120)));
        assert_eq!(scan(b"1 12 extra"), Some((n(1), 12)));
        assert_eq!(Reply::ok("2 (320)").drop_listing(), None);
        assert_eq!(Reply::ok("2x 320").drop_listing(), None);
        assert_eq!(scan(b"1x 120"), None);
        assert_eq!(scan(b"1  120"), None);
    }

    #[test]
    fn long_codes_keep_their_meaning() {
        // RFC 2449, section 8: clients ignore detail they do not know.
        let line = [b"-ERR [SYS/TEMP/".as_slice(), &[b'x'; 120], b"] retry"].concat();
        let r = status(&line).unwrap();
        assert!(r.has_code(code::SYS_TEMP));
        assert_eq!(r.text, "retry");
        assert_eq!(r.to_bytes().unwrap(), [&line[..], b"\r\n"].concat());
    }

    #[test]
    fn rfc1939_session() {
        let greeting = status(b"+OK POP3 server ready <1896.697170952@dbc.mit.edu>").unwrap();
        assert!(greeting.ok);
        assert_eq!(greeting.timestamp(), Some("<1896.697170952@dbc.mit.edu>"));

        let apop = request(b"APOP mrose c4c9334bac560ecc979e58001b3e22fb").unwrap();
        let Request::Apop { name, digest } = &apop else {
            panic!()
        };
        assert_eq!(name, "mrose");
        assert_eq!(digest[..2], [0xc4, 0xc9]);
        assert_eq!(digest[15], 0xfb);
        assert_eq!(
            apop.to_bytes().unwrap(),
            b"APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n"
        );
        // Upper-case hex is read too, and written in lower case.
        assert_eq!(
            request(b"APOP mrose C4C9334BAC560ECC979E58001B3E22FB"),
            Ok(apop)
        );

        assert_eq!(request(b"STAT"), Ok(Request::Stat));
        let stat = status(b"+OK 2 320").unwrap();
        assert_eq!(stat.drop_listing(), Some((2, 320)));
        assert_eq!(Reply::stat(2, 320), stat);

        assert_eq!(request(b"LIST"), Ok(Request::List(None)));
        let stream = b"+OK 2 messages (320 octets)\r\n1 120\r\n2 200\r\n.\r\n";
        let list = Reply::parse(stream).unwrap();
        assert_eq!(list.text, "2 messages (320 octets)");
        let listing: Vec<_> = list
            .lines()
            .filter_map(|b| ScanListing::parse(b).ok().map(|v| (v.message, v.octets)))
            .collect();
        assert_eq!(listing, [(n(1), 120), (n(2), 200)]);
        assert_eq!(list.to_bytes().unwrap(), stream);
        assert_eq!(request(b"LIST 2"), Ok(Request::List(Some(n(2)))));
        assert_eq!(
            ScanListing::parse(status(b"+OK 2 200").unwrap().text.as_bytes())
                .ok()
                .map(|v| (v.message, v.octets)),
            Some((n(2), 200))
        );
        let none = status(b"-ERR no such message, only 2 messages in maildrop").unwrap();
        assert!(!none.ok);

        assert_eq!(request(b"RETR 1"), Ok(Request::Retr(n(1))));
        assert_eq!(request(b"DELE 1"), Ok(Request::Dele(n(1))));
        assert_eq!(request(b"NOOP"), Ok(Request::Noop));
        assert_eq!(request(b"RSET"), Ok(Request::Rset));
        assert_eq!(request(b"QUIT"), Ok(Request::Quit));
        assert_eq!(
            request(b"TOP 1 10"),
            Ok(Request::Top {
                msg: n(1),
                lines: 10
            })
        );
        assert_eq!(
            request(b"TOP 1 0"),
            Ok(Request::Top {
                msg: n(1),
                lines: 0
            })
        );
        assert_eq!(request(b"USER mrose"), Ok(Request::User("mrose".into())));
        assert_eq!(request(b"PASS secret"), Ok(Request::Pass("secret".into())));
        // Keywords are read in any case.
        assert_eq!(request(b"user frated"), Ok(Request::User("frated".into())));
        assert_eq!(request(b"rEtR 2"), Ok(Request::Retr(n(2))));

        assert_eq!(request(b"UIDL"), Ok(Request::Uidl(None)));
        let uidl =
            Reply::parse(b"+OK\r\n1 whqtswO00WBw418f9t5JxYwZ\r\n2 QhdPYR:00WBw1Ph7x7\r\n.\r\n")
                .unwrap();
        let ids: Vec<_> = uidl
            .lines()
            .filter_map(|b| UniqueIdListing::parse(b).ok().map(|v| (v.message, v.id)))
            .collect();
        assert_eq!(
            ids,
            [
                (n(1), "whqtswO00WBw418f9t5JxYwZ".into()),
                (n(2), "QhdPYR:00WBw1Ph7x7".into())
            ]
        );
        assert_eq!(
            UniqueIdListing {
                message: n(2),
                id: "QhdPYR:00WBw1Ph7x7".into()
            }
            .to_bytes()
            .unwrap(),
            b"2 QhdPYR:00WBw1Ph7x7"
        );
    }

    #[test]
    fn rfc2449_capa_and_codes() {
        assert_eq!(request(b"CAPA"), Ok(Request::Capa));
        let stream = b"+OK Capability list follows\r\nTOP\r\nUSER\r\nSASL CRAM-MD5 KERBEROS_V4\r\n\
            RESP-CODES\r\nLOGIN-DELAY 900\r\nPIPELINING\r\nEXPIRE 60\r\nUIDL\r\n\
            IMPLEMENTATION Shlemazle-Plotz-v302\r\n.\r\n";
        let capa = Reply::parse(stream).unwrap();
        assert!(Request::Capa.multi_line());
        assert_eq!(capa.lines().count(), 9);
        assert_eq!(capa.lines().nth(2), Some(&b"SASL CRAM-MD5 KERBEROS_V4"[..]));
        assert_eq!(capa.to_bytes().unwrap(), stream);

        let in_use = status(b"-ERR [IN-USE] Do you have another POP session running?").unwrap();
        assert_eq!(in_use.code.as_deref(), Some(code::IN_USE));
        assert_eq!(in_use.text, "Do you have another POP session running?");
        assert_eq!(
            Reply::err("Do you have another POP session running?").with_code(code::IN_USE),
            in_use
        );
        let delay = status(b"-ERR [LOGIN-DELAY] wait a while").unwrap();
        assert_eq!(delay.code.as_deref(), Some(code::LOGIN_DELAY));
        // RFC 3206 codes have levels.
        let temp = status(b"-ERR [SYS/TEMP] Mail system overloaded").unwrap();
        assert_eq!(temp.code.as_deref(), Some(code::SYS_TEMP));
        assert_eq!(
            temp.to_bytes().unwrap(),
            b"-ERR [SYS/TEMP] Mail system overloaded\r\n"
        );
        // A code with no text.
        let bare = status(b"-ERR [AUTH]").unwrap();
        assert_eq!(
            (bare.code.as_deref(), bare.text.as_str()),
            (Some(code::AUTH), "")
        );
        assert_eq!(bare.to_bytes().unwrap(), b"-ERR [AUTH]\r\n");
    }

    #[test]
    fn brackets_that_are_not_a_code_are_text() {
        // Servers without RESP-CODES may send any text (RFC 1939).
        for line in [
            &b"-ERR [no such message]"[..],
            b"+OK [",
            b"+OK []",
            b"+OK [SYS/] x",
        ] {
            let r = status(line).unwrap();
            assert_eq!(r.code, None);
            assert_eq!(
                r.text.as_bytes(),
                &line[line.iter().position(|&c| c == b'[').unwrap()..]
            );
            assert_eq!(r.to_bytes().unwrap(), [line, b"\r\n"].concat());
        }
        // A code may fill the line (RFC 2449 sets no limit of its own).
        let long_code = [b"+OK [".as_slice(), &[b'A'; MAX_CODE], b"]"].concat();
        assert_eq!(long_code.len(), MAX_REPLY_LINE - 2);
        let r = status(&long_code).unwrap();
        assert_eq!(r.code.as_deref().map(str::len), Some(MAX_CODE));
        assert_eq!(r.to_bytes().unwrap(), [&long_code[..], b"\r\n"].concat());
    }

    #[test]
    fn dot_stuffing() {
        let wire = b"+OK 120 octets\r\nSubject: hi\r\n\r\n..\r\n...more\r\n.x\r\n.\r\n";
        let reply = Reply::parse(wire).unwrap();
        assert_eq!(
            reply.body.as_deref(),
            Some(b"Subject: hi\r\n\r\n.\r\n..more\r\nx\r\n".as_slice())
        );
        assert_eq!(
            reply.to_bytes().unwrap(),
            b"+OK 120 octets\r\nSubject: hi\r\n\r\n..\r\n...more\r\nx\r\n.\r\n"
        );
        contract::check_decode_with_alloc_limit(
            || reply_reader(true),
            wire,
            2 * (MAX_AUTH_LINE + 2),
        );
        contract::check_wire::<Reply>(wire);
        refused(&Reply::ok("x").with_body(b".a\nb".to_vec()));
        let empty = Reply::ok("").with_body(vec![]);
        assert_eq!(empty.to_bytes().unwrap(), b"+OK\r\n.\r\n");
        assert_eq!(Reply::parse(&empty.to_bytes().unwrap()), Ok(empty));
        let mut stream = Stream::new(reply_reader(true));
        assert_eq!(stream.push(b"-ERR no\r\n1 2\r\n.\r\n"), 17);
        assert_eq!(stream.next(), Some(Ok(Ok(Output::Reply(Reply::err("no"))))));
        assert_eq!(stream.unread(), b"1 2\r\n.\r\n");
        refused(&Reply::err("no").with_body(b"x".to_vec()));
    }

    #[test]
    fn reply_errors() {
        for line in [
            b"".as_slice(),
            b"+ok",
            b"+OKAY",
            b"-ERROR",
            b"OK",
            b"+OK caf\xe9",
            b"+OK a\0b",
            b"+OK a\rb",
        ] {
            assert_eq!(
                status(line),
                Err(ParseError::Reply(ReplyItemError::Reply(
                    ReplyError::BadStatus
                ))),
                "{line:?}"
            );
        }
        for line in [b"+OK [IN-USE".as_slice(), b"+OK [/X]", b"+OK [A B]"] {
            assert_eq!(status(line).unwrap().code, None, "{line:?}");
        }
        let long = [b"+OK ".as_slice(), &[b'a'; 507]].concat();
        assert!(status(&long).is_err());
        assert!(status(&long[..510]).is_ok());
        let mut data = b"+OK\r\n".to_vec();
        data.extend(vec![b'x'; MAX_DATA_LINE - 1]);
        data.extend_from_slice(b"\r\n.\r\n");
        assert!(matches!(
            Reply::parse(&data),
            Err(ParseError::Framing(DecodeError::Line(_)))
        ));
        data.remove(5);
        assert!(Reply::parse(&data).is_ok());
        let line = [vec![b'y'; MAX_DATA_LINE - 2], b"\r\n".to_vec()].concat();
        let big = [
            b"+OK\r\n".to_vec(),
            line.repeat(MAX_BODY / line.len() + 1),
            b".\r\n".to_vec(),
        ]
        .concat();
        assert_eq!(
            Reply::parse(&big),
            Err(ParseError::Framing(DecodeError::BodyTooLong))
        );
        for line in [b"0 12".as_slice(), b"1", b"1 x"] {
            assert!(ScanListing::parse(line).is_err());
        }
        for line in [
            b"1 ".as_slice(),
            b"1 a b",
            &[b"1 ".as_slice(), &[b'u'; 71]].concat(),
        ] {
            assert!(UniqueIdListing::parse(line).is_err());
        }
        assert_eq!(Reply::ok("x").drop_listing(), None);
        assert_eq!(Reply::ok("no timestamp").timestamp(), None);
    }

    #[test]
    fn decoder_keeps_going_after_a_bad_command() {
        let wire = [
            b"NOOP\r\n".to_vec(),
            vec![b'x'; 1000],
            b"\r\nBADKEY\r\nQUIT\r\n".to_vec(),
        ]
        .concat();
        let expected = vec![
            Ok(Input::Command(command(b"NOOP").unwrap())),
            Err(CommandError::LineTooLong),
            Err(CommandError::BadKeyword),
            Ok(Input::Command(command(b"QUIT").unwrap())),
        ];
        assert_eq!(decode_all(Commands::new, &wire), (expected, None));
        contract::check_decode_with_alloc_limit(Commands::new, &wire, 2 * (MAX_AUTH_LINE + 2));
    }

    #[test]
    fn reply_errors_follow_the_expected_boundary() {
        let mut replies = Replies::new();
        for multi in [false, true] {
            replies.expect(multi).unwrap();
        }
        let mut stream = Stream::new(replies);
        let wire = b"+OK hi\r\nHELLO\r\n+OK\r\n";
        assert_eq!(stream.push(wire), wire.len());
        assert_eq!(stream.next(), Some(Ok(Ok(Output::Reply(Reply::ok("hi"))))));
        let error = Fail::Protocol(DecodeError::Reply(ReplyError::BadStatus));
        assert_eq!(stream.next(), Some(Err(error)));
        assert_eq!(stream.next(), None);
        assert!(stream.failed().is_some());
    }

    #[test]
    fn truncated_prefixes() {
        for wire in [
            b"+OK 2 messages\r\n1 120\r\n..2 200\r\n.\r\n".as_slice(),
            b"-ERR [SYS/TEMP] later\r\n",
        ] {
            let multi = wire.starts_with(b"+OK");
            contract::check_decode_with_alloc_limit(
                || reply_reader(multi),
                wire,
                2 * (MAX_AUTH_LINE + 2),
            );
            for cut in 0..wire.len() {
                let (items, _) = decode_all(|| reply_reader(multi), &wire[..cut]);
                assert!(items.is_empty(), "{cut}");
            }
        }
        let cmd = b"APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n";
        for cut in 0..cmd.len() {
            assert!(Command::parse(&cmd[..cut]).is_err());
        }
        assert!(Command::parse(cmd).is_ok());
    }

    #[test]
    fn requests_round_trip() {
        let requests = [
            Request::User("mrose".into()),
            Request::Pass("a b c".into()),
            Request::Apop {
                name: "x".into(),
                digest: [0xab; 16],
            },
            Request::Stat,
            Request::List(None),
            Request::List(Some(n(3))),
            Request::Retr(n(u32::MAX)),
            Request::Dele(n(1)),
            Request::Noop,
            Request::Rset,
            Request::Quit,
            Request::Top {
                msg: n(2),
                lines: 0,
            },
            Request::Uidl(None),
            Request::Uidl(Some(n(9))),
            Request::Capa,
            Request::Stls,
        ];
        let mut wire = Vec::new();
        for request in &requests {
            request.write(&mut wire).unwrap();
            contract::check_wire_value(request);
        }
        let (items, error) = decode_all(Commands::new, &wire);
        assert_eq!(error, None);
        let got: Vec<_> = items
            .into_iter()
            .map(|item| {
                let Input::Command(command) = item.unwrap() else {
                    panic!()
                };
                Request::from_command(&command).unwrap()
            })
            .collect();
        assert_eq!(got, requests);
        contract::check_decode_with_alloc_limit(Commands::new, &wire, 2 * (MAX_AUTH_LINE + 2));
    }

    #[test]
    fn writers_refuse_values_they_would_change() {
        for request in [
            Request::User(format!("a b\r\n{}", "é".repeat(200))),
            Request::User(" \r".into()),
            Request::Pass("\n".into()),
            Request::Pass("p".repeat(1000)),
            Request::User(String::new()),
            Request::Pass(String::new()),
            Request::Apop {
                name: "a b".into(),
                digest: [0; 16],
            },
            Request::Apop {
                name: "u".repeat(216),
                digest: [0; 16],
            },
            Request::Other(Command {
                keyword: "user".into(),
                argument: Some("x".into()),
            }),
        ] {
            refused(&request);
        }
        for (keyword, argument) in [
            ("R\r\n", Some("x\ny")),
            ("RETR", Some("x\ny")),
            ("RETRY", Some("1")),
            ("DELETE", Some("1")),
            ("R E\tT R", None),
            ("x-ab", Some("")),
            ("NOOP", Some("a\tb")),
        ] {
            refused(&Command {
                keyword: keyword.into(),
                argument: argument.map(String::from),
            });
        }
        for reply in [
            Reply::ok(&format!("[x\n{}", "é".repeat(400))),
            Reply::ok(&format!("[AUTH]{}", "a".repeat(600))),
            Reply::err("[A] x"),
            Reply::err("t").with_code("SYS/ /T]EMP/"),
            Reply::err("t").with_code("] /"),
            Reply::err("t").with_code(&"A".repeat(600)),
            Reply::err("t").with_code(&format!("{}/{}", "A".repeat(300), "B".repeat(300))),
        ] {
            refused(&reply);
        }
    }

    #[test]
    fn keywords_are_any_printable_ascii() {
        assert_eq!(
            command(b"X-AB 1"),
            Ok(Command {
                keyword: "X-AB".into(),
                argument: Some("1".into())
            })
        );
        assert!(command(b"\xc3\xa9AB").is_err());
        refused(&Command {
            keyword: "x-ab".into(),
            argument: None,
        });
        assert_eq!(command(b"x-ab").unwrap().to_bytes().unwrap(), b"X-AB\r\n");
    }

    #[test]
    fn arguments_may_pass_40_bytes() {
        let user = "firstname.lastname@mail.some-long-domain.example";
        assert!(user.len() > 40);
        let request = Request::User(user.into());
        assert_eq!(Request::parse(&request.to_bytes().unwrap()), Ok(request));
        refused(&Request::Apop {
            name: user.repeat(10),
            digest: [1; 16],
        });
    }

    #[test]
    fn code_may_run_into_text() {
        assert!(status(b"-ERR [a\xff]x").is_err());
        let reply = status(b"-ERR [IN-USE]locked").unwrap();
        assert_eq!(
            (reply.code.as_deref(), reply.text.as_str()),
            (Some("IN-USE"), "locked")
        );
        let make = || {
            let mut r = reply_reader(false);
            r.expect(false).unwrap();
            r
        };
        let wire = b"-ERR [AUTH]no\r\n+OK\r\n";
        assert_eq!(
            decode_all(make, wire),
            (
                vec![
                    Ok(Output::Reply(Reply::err("no").with_code("AUTH"))),
                    Ok(Output::Reply(Reply::ok("")))
                ],
                None
            )
        );
        contract::check_decode_with_alloc_limit(make, wire, 2 * (MAX_AUTH_LINE + 2));
    }

    #[test]
    fn writers_stop_reading_input_past_their_limits() {
        let started = std::time::Instant::now();
        refused(&Reply::ok("").with_body(vec![b'\n'; MAX_BODY * 8]));
        let text = "t".repeat(MAX_BODY);
        refused(&Reply::ok(&text));
        refused(&Request::Pass(text.clone()));
        refused(&Request::User(text));
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn decoders_take_many_small_lines_in_linear_time() {
        let wire = b"NOOP\r\n".repeat(200_000);
        let started = std::time::Instant::now();
        let (items, error) = decode_all(Commands::new, &wire);
        assert_eq!(error, None);
        assert_eq!(items.len(), 200_000);
        let body = [
            b"+OK\r\n".to_vec(),
            b"a\r\n".repeat(200_000),
            b".\r\n".to_vec(),
        ]
        .concat();
        assert_eq!(Reply::parse(&body).unwrap().lines().count(), 200_000);
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
        contract::check_decode_with_alloc_limit(Commands::new, &wire, 2 * (MAX_AUTH_LINE + 2));
        contract::check_decode_with_alloc_limit(
            || reply_reader(true),
            &body,
            2 * (MAX_AUTH_LINE + 2),
        );
    }

    #[test]
    fn decoders_keep_bounded_buffers() {
        let wire = [vec![b'x'; 1 << 20], b"\r\nQUIT\r\n".to_vec()].concat();
        let (items, error) = decode_all(Commands::new, &wire);
        assert_eq!(error, None);
        assert_eq!(
            items,
            vec![
                Err(CommandError::LineTooLong),
                Ok(Input::Command(command(b"QUIT").unwrap()))
            ]
        );
        contract::check_decode_with_alloc_limit(Commands::new, &wire, 2 * (MAX_AUTH_LINE + 2));
        for multi in [false, true] {
            let make = || {
                let mut r = reply_reader(multi);
                r.expect(false).unwrap();
                r
            };
            let wire = [b"+OK\r\n".to_vec(), vec![b'x'; 1 << 20], b"\r\n".to_vec()].concat();
            assert!(matches!(
                decode_all(make, &wire).1,
                Some(Fail::Protocol(DecodeError::Line(_)))
            ));
            contract::check_decode_with_alloc_limit(make, &wire, 2 * (MAX_AUTH_LINE + 2));
        }
        let many = b"NOOP\r\n".repeat(1 << 17);
        contract::check_decode_with_alloc_limit(Commands::new, &many, 2 * (MAX_AUTH_LINE + 2));
    }

    #[test]
    fn bodies_that_do_not_fit_are_refused_not_cut() {
        let line = [vec![b'b'; MAX_DATA_LINE - 2], b"\r\n".to_vec()].concat();
        refused(
            &Reply::ok("1 message")
                .with_body([vec![b'a'; MAX_DATA_LINE], b"\r\n".to_vec()].concat()),
        );
        refused(&Reply::ok("").with_body(line.repeat(MAX_BODY / line.len() + 1)));
        let dotted = [b".".as_slice(), &[b'c'; MAX_DATA_LINE - 4], b"\r\n"].concat();
        let reply = Reply::ok("").with_body([line.clone(), dotted].concat());
        assert_eq!(Reply::parse(&reply.to_bytes().unwrap()), Ok(reply));
        let lines = MAX_BODY / line.len() - 1;
        let body = [
            line.repeat(lines),
            vec![b'd'; MAX_BODY - lines * line.len() - 2],
            b"\r\n".to_vec(),
        ]
        .concat();
        assert_eq!(body.len(), MAX_BODY);
        let reply = Reply::ok("").with_body(body);
        assert_eq!(Reply::parse(&reply.to_bytes().unwrap()), Ok(reply));
    }

    #[test]
    fn arguments_are_counted_not_collected() {
        let spaces = Command {
            keyword: "USER".into(),
            argument: Some(" ".repeat(8 << 20)),
        };
        assert_eq!(Request::from_command(&spaces), Err(ArgumentError::Spacing));
        let many = Command {
            keyword: "LIST".into(),
            argument: Some("1 ".repeat(1 << 20) + "1"),
        };
        assert_eq!(Request::from_command(&many), Err(ArgumentError::Extra));
        assert_eq!(request(b"TOP 1 2 3 "), Err(ArgumentError::Spacing));
        assert_eq!(request(b"USER a b c d"), Err(ArgumentError::Extra));
        refused(&Reply::err("").with_code(&"A".repeat(16 << 20)));
        let reply = Reply::ok("").with_body(b"a\nb\r\nc".to_vec());
        let mut lines = reply.lines();
        assert_eq!(lines.next(), Some(b"a".as_slice()));
        assert_eq!(lines.count(), 2);
        assert_eq!(Reply::ok("").lines().count(), 0);
    }

    #[test]
    fn credentials_are_written_unchanged() {
        refused(&Request::Pass("p".repeat(249)));
        for request in [
            Request::Pass("p".repeat(248)),
            Request::Pass("open sesame ".into()),
            Request::User("é".into()),
            Request::Apop {
                name: "u".repeat(215),
                digest: [7; 16],
            },
            Request::Other(Command {
                keyword: "AUTH".into(),
                argument: Some("PLAIN".into()),
            }),
            Request::Quit,
        ] {
            assert_eq!(
                Request::parse(&request.to_bytes().unwrap()),
                Ok(request.clone())
            );
            contract::check_wire_value(&request);
        }
    }

    #[test]
    fn unique_ids_are_never_merged() {
        for id in [
            " ".into(),
            "".into(),
            "u".repeat(MAX_UID + 1),
            format!("{}X", "a".repeat(70)),
            format!("{}Y", "a".repeat(70)),
            "a b".into(),
            "aé".into(),
        ] {
            refused(&UniqueIdListing { message: n(1), id });
        }
        let value = UniqueIdListing {
            message: n(1),
            id: "u".repeat(MAX_UID),
        };
        assert_eq!(
            UniqueIdListing::parse(&value.to_bytes().unwrap()),
            Ok(value)
        );
    }

    #[test]
    fn full_status_lines_round_trip() {
        let wire = [b"-ERR [AUTH]".as_slice(), &[b'x'; 499], b"\r\n"].concat();
        let reply = Reply::parse(&wire).unwrap();
        assert_eq!(reply.text.len(), 499);
        assert_eq!(reply.to_bytes().unwrap(), wire);
        refused(&Reply::err(&format!(" {}", "y".repeat(498))).with_code("AUTH"));
        for text in [" more", "more", "é"] {
            refused(&Reply::ok(text).with_code(&"A".repeat(MAX_CODE - 1)));
        }
        for reply in [
            Reply::ok("a\nb"),
            Reply::ok("t").with_code("SYS/"),
            Reply::ok(&"t".repeat(508)),
            Reply::err("x").with_body(vec![]),
        ] {
            refused(&reply);
        }
        assert_eq!(
            Reply::ok(&"t".repeat(506)).to_bytes().unwrap().len(),
            MAX_REPLY_LINE
        );
        contract::check_wire::<Reply>(&wire);
    }

    #[test]
    fn auth_exchanges_read_as_lines() {
        let answer = "QUFB".repeat(1000);
        let mut stream = Stream::new(Commands::new());
        let wire = format!("AUTH PLAIN\r\n{answer}\r\n*\r\nQUIT\r\n");
        assert_eq!(stream.push(wire.as_bytes()), wire.len());
        assert!(
            matches!(stream.next(), Some(Ok(Ok(Input::Command(c)))) if matches!(Request::from_command(&c), Ok(Request::Other(_))))
        );
        for line in [answer.as_bytes(), b"*"] {
            stream.decoder().expect_line().unwrap();
            assert_eq!(stream.next(), Some(Ok(Ok(Input::Line(line.to_vec())))));
        }
        assert!(matches!(stream.next(), Some(Ok(Ok(Input::Command(c)))) if c.keyword == "QUIT"));
        let mut stream = Stream::new(reply_reader(false));
        let wire = b"+ \r\n+ PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2U+\r\n+OK done\r\n";
        assert_eq!(stream.push(wire), wire.len());
        for line in [b"+ ".as_slice(), b"+ PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2U+"] {
            stream.decoder().expect_line().unwrap();
            assert_eq!(stream.next(), Some(Ok(Ok(Output::Line(line.to_vec())))));
        }
        assert_eq!(
            stream.next(),
            Some(Ok(Ok(Output::Reply(Reply::ok("done")))))
        );
        let mut stream = Stream::new(reply_reader(true));
        assert_eq!(stream.push(b"+OK\r\nx\r\n"), 8);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().expect_line(), Err(DecodeError::State));
        assert_eq!(stream.push(b".\r\n"), 3);
        assert!(stream.next().unwrap().unwrap().is_ok());
        let make = || {
            let mut r = reply_reader(false);
            r.expect_line().unwrap();
            r
        };
        let long = vec![b'+'; MAX_AUTH_LINE + 2];
        assert!(matches!(
            decode_all(make, &long).1,
            Some(Fail::Protocol(DecodeError::Line(_)))
        ));
        contract::check_decode_with_alloc_limit(make, &long, 2 * (MAX_AUTH_LINE + 2));
    }

    #[test]
    fn generated_streams_and_values_obey_contracts() {
        const PIECES: &[&[u8]] = &[
            b"USER ",
            b"PASS ",
            b"APOP ",
            b"LIST",
            b"RETR ",
            b"TOP ",
            b"UIDL",
            b"CAPA",
            b"STLS",
            b"STAT",
            b"QUIT",
            b"+OK",
            b"-ERR",
            b"+OK ",
            b"-ERR ",
            b" [",
            b"[IN-USE]",
            b"[sys/temp/x]y",
            b"SYS/TEMP",
            b"]",
            b"/",
            b"\r\n",
            b"\n",
            b"\r",
            b".\r\n",
            b"..",
            b".",
            b" ",
            b"1",
            b"0",
            b"42",
            b"c4c9334bac560ecc979e58001b3e22fb",
            b"<1.2@x>",
            b"\0",
            b"\xff",
            b"\xc3\xa9",
        ];
        let seeds: &[&[u8]] = &[
            b"USER alice\r\nPASS open sesame\r\nLIST\r\n",
            b"APOP alice c4c9334bac560ecc979e58001b3e22fb\r\n",
            b"TOP 1 0\r\nRETR 1\r\nUIDL\r\nCAPA\r\n",
            b"+OK [SYS/TEMP] x\r\n",
            b"+OK\r\n..dot\r\n.\r\n",
            b"-ERR [AUTH]no\r\n",
        ];
        let mut rng = Lcg::new(0x9093);
        for _ in 0..512 {
            let mut data = seeds[rng.index(seeds.len())].to_vec();
            if rng.coin() {
                for _ in 0..rng.index(32) {
                    data.extend_from_slice(PIECES[rng.index(PIECES.len())]);
                }
            }
            for _ in 0..rng.index(5) {
                mutate(&mut rng, &mut data);
            }
            contract::check_decode_with_alloc_limit(Commands::new, &data, 2 * (MAX_AUTH_LINE + 2));
            for multi in [false, true] {
                contract::check_decode_with_alloc_limit(
                    || reply_reader(multi),
                    &data,
                    2 * (MAX_AUTH_LINE + 2),
                );
            }
            contract::check_wire::<Command>(&data);
            contract::check_wire::<Request>(&data);
            contract::check_wire::<Reply>(&data);
            contract::check_wire::<ScanListing>(&data);
            contract::check_wire::<UniqueIdListing>(&data);
            let text = rng.text(530);
            let other = rng.text(530);
            contract::check_wire_value(&Command {
                keyword: rng.text(8),
                argument: Some(text.clone()),
            });
            contract::check_wire_value(&Reply {
                ok: rng.coin(),
                code: rng.coin().then(|| other.clone()),
                text: text.clone(),
                body: rng.coin().then(|| rng.bytes(256)),
            });
            for request in [
                Request::User(text.clone()),
                Request::Pass(other.clone()),
                Request::Apop {
                    name: text,
                    digest: [rng.next() as u8; 16],
                },
            ] {
                contract::check_wire_value(&request);
            }
            contract::check_wire_value(&UniqueIdListing {
                message: n(1),
                id: other,
            });
            contract::check_wire_value(&ScanListing {
                message: n(1),
                octets: (rng.next() << 33) | (rng.next() << 2) | rng.below(4),
            });
        }
    }
}
