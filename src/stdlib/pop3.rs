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
//! Nothing here reads a socket. A world that plays a mail server feeds the
//! bytes it reads from a [`tcp`](crate::stdlib::tcp) connection to a
//! [`CommandDecoder`], gets [`Command`]s back, reads each one's
//! [`Request`], and writes a [`Reply`]'s bytes back to the connection. A
//! world that plays a client does the reverse with [`ReplyDecoder`]. Which
//! mailboxes exist, who may log in, and what each message holds are up to
//! world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Legacy decoders skip command lines over [`MAX_COMMAND_LINE`]
//! and go on to the next line. A legacy reply decoder
//! stops at its first error, since a client that has lost its place in a
//! reply cannot find it again. Bodies are held to [`MAX_BODY`] bytes and
//! their lines to [`MAX_DATA_LINE`]. Legacy readers accept a bare LF as a line
//! end, as many servers do.
//! New stacks use [`Commands`] or [`Replies`] with [`codec::Stream`]. They
//! require CRLF. Bad or overlong commands are error items, and decoding
//! resumes at the next line. Bad status lines end the stream when a body
//! was expected; other bad status lines are error items. The [`Wire`]
//! implementations parse exact values and write transactionally.
//! Legacy decoders and `to_bytes` methods keep their original behavior.
//!
//! Writers never write what the readers refuse. The `to_bytes` writers
//! always give bytes, and make what does not fit fit: they drop characters
//! a field may not hold and cut text to its line. A reply whose body does
//! not fit is written as `-ERR [SYS/PERM]` rather than cut, so a client
//! never takes part of a message for all of it. The `try_to_bytes`
//! writers write a value only if it reads back the same.
//!
//! During an `AUTH` exchange (RFC 5034) the lines between the command and
//! the final `+OK` or `-ERR` are neither commands nor replies. Read them
//! with [`Commands::expect_line`] and [`Replies::expect_line`], called
//! between items. Each selects one raw line, without consuming a reply
//! expectation. Legacy callers use [`CommandDecoder::next_line`] and
//! [`ReplyDecoder::next_line`].
//!
//! ```
//! use fictionet::stdlib::pop3::{
//!     CommandDecoder, Reply, ReplyDecoder, Request, parse_scan_listing, write_scan_listing,
//! };
//! use std::num::NonZeroU32;
//!
//! // A server with two messages answers four commands.
//! let sizes = [120u64, 200];
//! let mut commands = CommandDecoder::new();
//! commands.feed(b"USER alice\r\nPASS open sesame\r\nLIST\r\nRETR 9\r\n");
//! let mut out = Vec::new();
//! while let Some(line) = commands.next_command() {
//!     let reply = match line.map(|c| Request::from_command(&c)) {
//!         Ok(Ok(Request::User(name))) => Reply::ok(&format!("{name} is welcome")),
//!         Ok(Ok(Request::Pass(_))) => Reply::ok("Maildrop locked and ready"),
//!         Ok(Ok(Request::List(None))) => {
//!             let mut body = Vec::new();
//!             for (n, size) in (1..).zip(sizes) {
//!                 let n = NonZeroU32::new(n).unwrap();
//!                 body.extend_from_slice(write_scan_listing(n, size).as_bytes());
//!                 body.extend_from_slice(b"\r\n");
//!             }
//!             Reply::ok("2 messages").with_body(body)
//!         }
//!         Ok(Ok(Request::Retr(n))) => Reply::err(&format!("No message {n}")),
//!         Ok(Ok(_)) => Reply::err("Not supported"),
//!         Ok(Err(e)) => Reply::err(&e.to_string()),
//!         Err(e) => Reply::err(&e.to_string()),
//!     };
//!     out.extend(reply.to_bytes());
//! }
//! assert_eq!(
//!     out,
//!     b"+OK alice is welcome\r\n\
//!       +OK Maildrop locked and ready\r\n\
//!       +OK 2 messages\r\n1 120\r\n2 200\r\n.\r\n\
//!       -ERR No message 9\r\n"
//! );
//!
//! // The client reads the replies. Whether a +OK reply has a body depends
//! // on the command it answers, so the client says which it sent.
//! let sent = [
//!     Request::User("alice".to_string()),
//!     Request::Pass("open sesame".to_string()),
//!     Request::List(None),
//!     Request::Retr(NonZeroU32::new(9).unwrap()),
//! ];
//! let mut replies = ReplyDecoder::new();
//! replies.feed(&out);
//! let got: Vec<Reply> = sent.iter().map(|r| replies.next_reply(r.multi_line()).unwrap().unwrap()).collect();
//! let listing: Vec<_> = got[2].lines().into_iter().filter_map(parse_scan_listing).collect();
//! assert_eq!(listing, [(NonZeroU32::new(1).unwrap(), 120), (NonZeroU32::new(2).unwrap(), 200)]);
//! assert!(!got[3].ok);
//! assert_eq!(got[3].body, None);
//! ```

extern crate alloc;

use self::alloc::{collections::VecDeque, string::String, vec::Vec};
use super::codec::{self, Decode, Wire};
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
/// select, excluding CRLF. Legacy [`CommandDecoder::next_line`] and
/// [`ReplyDecoder::next_line`] count the line end in this limit. The base64
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
    /// Reads one command line, without its CRLF.
    pub fn parse(line: &[u8]) -> Result<Command, CommandError> {
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

    /// The command as a line, with its CRLF. Characters a keyword may not
    /// hold are dropped from it, and a keyword that is then not three or
    /// four characters long is written as `NOOP` with no argument. A longer
    /// keyword is never cut, since `RETRY` cut to `RETR` would be another
    /// command. Control characters are dropped from the argument, and it is
    /// cut to fit in [`MAX_COMMAND_LINE`]. [`Command::try_to_bytes`] does
    /// none of this.
    pub fn to_bytes(&self) -> Vec<u8> {
        let keyword: String = self
            .keyword
            .chars()
            .filter(char::is_ascii_graphic)
            .take(MAX_KEYWORD + 1)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if !(MIN_KEYWORD..=MAX_KEYWORD).contains(&keyword.len()) {
            return b"NOOP\r\n".to_vec();
        }
        let mut out = keyword.into_bytes();
        if let Some(arg) = &self.argument {
            let arg = clean(arg);
            let arg = cut(&arg, MAX_COMMAND_LINE - 3 - out.len());
            if !arg.is_empty() {
                out.push(b' ');
                out.extend_from_slice(arg.as_bytes());
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The command as a line, with its CRLF, or why it cannot be written
    /// as it is. The line reads back as this command, with its keyword in
    /// upper case and an empty argument read as none.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, CommandError> {
        let arg = self.argument.as_deref().unwrap_or("");
        if self.keyword.len().saturating_add(arg.len()) > MAX_COMMAND_LINE {
            return Err(CommandError::LineTooLong);
        }
        if !(MIN_KEYWORD..=MAX_KEYWORD).contains(&self.keyword.len())
            || !self.keyword.bytes().all(|c| c.is_ascii_graphic())
        {
            return Err(CommandError::BadKeyword);
        }
        if arg.chars().any(char::is_control) {
            return Err(CommandError::BadCharacter);
        }
        let mut out = self.keyword.to_ascii_uppercase().into_bytes();
        if !arg.is_empty() {
            out.push(b' ');
            out.extend_from_slice(arg.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        if out.len() > MAX_COMMAND_LINE {
            return Err(CommandError::LineTooLong);
        }
        Ok(out)
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
    /// starts a new [`CommandDecoder`] once TLS is up.
    Stls,
    /// Any other keyword, such as `AUTH`, left as it came. A command with
    /// a keyword this module knows is written as it is, so it reads back
    /// as that request or as an [`ArgumentError`].
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

    /// The request as a command. Names have spaces and control characters
    /// dropped, and a password has its control characters dropped. Names
    /// and passwords are cut so the line fits in [`MAX_COMMAND_LINE`]. An
    /// empty name or password is written as `_`, so the line still reads
    /// back as the same kind of request. [`Request::try_to_bytes`] refuses
    /// instead.
    pub fn to_command(&self) -> Command {
        let with = |keyword: &str, argument: Option<String>| Command {
            keyword: keyword.to_string(),
            argument,
        };
        match self {
            // "USER " and CRLF take 7 bytes of the line.
            Request::User(name) => with("USER", Some(word(name, MAX_COMMAND_LINE - 7))),
            Request::Pass(p) => {
                let p = clean(p);
                with("PASS", Some(if p.is_empty() { "_".to_string() } else { p }))
            }
            Request::Apop { name, digest } => {
                let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                // "APOP ", a space, the digest and CRLF take 40 bytes.
                let name = word(name, MAX_COMMAND_LINE - 40);
                with("APOP", Some(format!("{name} {hex}")))
            }
            Request::Stat => with("STAT", None),
            Request::List(m) => with("LIST", m.map(|m| m.to_string())),
            Request::Retr(m) => with("RETR", Some(m.to_string())),
            Request::Dele(m) => with("DELE", Some(m.to_string())),
            Request::Noop => with("NOOP", None),
            Request::Rset => with("RSET", None),
            Request::Quit => with("QUIT", None),
            Request::Top { msg, lines } => with("TOP", Some(format!("{msg} {lines}"))),
            Request::Uidl(m) => with("UIDL", m.map(|m| m.to_string())),
            Request::Capa => with("CAPA", None),
            Request::Stls => with("STLS", None),
            Request::Other(c) => c.clone(),
        }
    }

    /// The request as a line, with its CRLF.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_command().to_bytes()
    }

    /// The request as a line, with its CRLF, or `None` if
    /// [`Request::to_bytes`] would have to change it to write it: a name
    /// with a space, an empty name or password, a control character, or a
    /// line longer than [`MAX_COMMAND_LINE`]. A client uses this for
    /// credentials, which must go as they are or not at all. The line
    /// reads back as this request. [`Request::Other`] is written if its
    /// keyword is not one this module knows.
    pub fn try_to_bytes(&self) -> Option<Vec<u8>> {
        let short = |s: &str| (s.len() <= MAX_COMMAND_LINE).then(|| s.to_string());
        let bytes = match self {
            Request::User(name) => Command {
                keyword: "USER".into(),
                argument: Some(short(name)?),
            }
            .try_to_bytes(),
            Request::Pass(p) => Command {
                keyword: "PASS".into(),
                argument: Some(short(p)?),
            }
            .try_to_bytes(),
            Request::Apop { name, digest } => {
                let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                Command {
                    keyword: "APOP".into(),
                    argument: Some(format!("{} {hex}", short(name)?)),
                }
                .try_to_bytes()
            }
            Request::Other(c) => c.try_to_bytes(),
            _ => Ok(self.to_bytes()),
        }
        .ok()?;
        let back = Request::from_command(&Command::parse(bytes.strip_suffix(b"\r\n")?).ok()?).ok()?;
        let same = match (self, &back) {
            (Request::Other(_), Request::Other(_)) => true,
            _ => back == *self,
        };
        same.then_some(bytes)
    }

    /// Whether a `+OK` answer to this request carries a body: `LIST` and
    /// `UIDL` with no argument, `RETR`, `TOP` and `CAPA`. A `-ERR` answer
    /// never does. Pass this to [`ReplyDecoder::next_reply`].
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
    /// The text of the status line after the status and the code. Bytes
    /// that are not UTF-8 are read as `?`, one for each byte, before the
    /// code is looked for.
    pub text: String,
    /// The body, for a reply that has one, with the extra dots taken off.
    /// Every line in it ends with CRLF.
    pub body: Option<Vec<u8>>,
}

/// Why bytes are not a reply. [`Replies`] distinguishes recoverable items
/// from errors that lose the reply boundary. The legacy [`ReplyDecoder`]
/// stops at every error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// A status line was longer than [`MAX_REPLY_LINE`], or a body line
    /// longer than [`MAX_DATA_LINE`].
    LineTooLong,
    /// The status line did not start with `+OK` or `-ERR` followed by a
    /// space or the end of the line.
    BadStatus,
    /// A body line used bare LF or contained an embedded CR.
    BadBodyLine,
    /// The body was longer than [`MAX_BODY`].
    BodyTooLong,
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReplyError::LineTooLong => "reply line too long",
            ReplyError::BadStatus => "status is not +OK or -ERR",
            ReplyError::BodyTooLong => "reply body too long",
            ReplyError::BadBodyLine => "body line requires CRLF without embedded CR",
        })
    }
}

impl std::error::Error for ReplyError {}

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

    /// The reply with a body. Lines may end with CRLF or LF alone.
    pub fn with_body(mut self, body: Vec<u8>) -> Reply {
        self.body = Some(body);
        self
    }

    /// The answer to `STAT`: how many messages, and their size in bytes.
    pub fn stat(count: u32, octets: u64) -> Reply {
        Reply::ok(&format!("{count} {octets}"))
    }

    /// Reads a status line, without its CRLF. Text in brackets right after
    /// the status is a response code if it fits the grammar of RFC 2449,
    /// section 3. The text may follow
    /// the `]` straight away or after one space. Text in brackets that is
    /// not a code is read as plain text, since a server without
    /// `RESP-CODES` may write any text there.
    pub fn parse_line(line: &[u8]) -> Result<Reply, ReplyError> {
        if line.len() > MAX_REPLY_LINE - 2 {
            return Err(ReplyError::LineTooLong);
        }
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
        // Bytes that are not UTF-8 become '?' first, so the code is read
        // from the same text the writer would write.
        let rest = text_of(rest);
        let (code, text) = match split_code(rest.as_bytes()) {
            Some((code, text)) => (
                Some(String::from_utf8_lossy(code).into_owned()),
                String::from_utf8_lossy(text).into_owned(),
            ),
            None => (None, rest),
        };
        Ok(Reply {
            ok,
            code,
            text,
            body: None,
        })
    }

    /// Reads the reply at the start of `b`. `multi_line` says whether a
    /// `+OK` reply has a body, as [`Request::multi_line`] tells. It returns
    /// `Ok(None)` if `b` holds only part of a reply, and otherwise the
    /// reply and how many bytes of `b` it took.
    pub fn parse(b: &[u8], multi_line: bool) -> Result<Option<(Reply, usize)>, ReplyError> {
        // Fed a piece at a time, so only the bytes up to the reply's end,
        // and one piece more, are copied.
        let mut d = ReplyDecoder::new();
        for piece in b.chunks(PARSE_PIECE) {
            d.feed(piece);
            match d.next_reply(multi_line) {
                None => {}
                Some(Ok(r)) => return Ok(Some((r, d.lines.consumed))),
                Some(Err(e)) => return Err(e),
            }
        }
        Ok(None)
    }

    /// The reply as bytes. A body is written only for a `+OK` reply, with a
    /// dot added in front of lines that start with one, and the closing
    /// line. LFs are dropped from the text, and the status line is cut to
    /// fit in [`MAX_REPLY_LINE`]. The code comes first: characters it may
    /// not hold are dropped from it, and levels that do not fit on the line
    /// with it. Text that would not fit after the code and a space follows
    /// the `]` with no space, as RFC 2449, section 3 allows. A reply with
    /// no code whose text would be read as one, such as `[AUTH] x`, gets a
    /// space in front of its text.
    ///
    /// A body is never cut or changed, since a client would take part of a
    /// message for all of it. A `+OK` reply whose body has a line longer
    /// than [`MAX_DATA_LINE`], or is longer than [`MAX_BODY`], is written
    /// as `-ERR [SYS/PERM]` with the error as its text.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.write(false) {
            Ok(bytes) => bytes,
            Err(e) => Reply::err(&e.to_string())
                .with_code(code::SYS_PERM)
                .write(false)
                .unwrap_or_default(),
        }
    }

    /// The reply as bytes, or why it cannot be written as it is. The bytes
    /// read back as this reply, given whether it has a body, with each
    /// body line ending in CRLF, as [`Reply::with_body`] says. It fails with
    /// [`ReplyError::LineTooLong`] if the status line would be cut or a
    /// body line is too long, [`ReplyError::BodyTooLong`] if the body is,
    /// and [`ReplyError::BadStatus`] if the text holds an LF, the code is
    /// not a response code, a reply with no code has text that would be
    /// read as one, or a `-ERR` reply has a body.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, ReplyError> {
        self.write(true)
    }

    fn write(&self, strict: bool) -> Result<Vec<u8>, ReplyError> {
        let status = if self.ok { "+OK" } else { "-ERR" };
        let max_line = MAX_REPLY_LINE - 2;
        // Each character is a byte or more, so this is enough to fill a line.
        let text: String = self
            .text
            .chars()
            .filter(|&c| c != '\n')
            .take(MAX_REPLY_LINE)
            .collect();
        if strict && text.len() != self.text.len() {
            return Err(if self.text.len() > max_line {
                ReplyError::LineTooLong
            } else {
                ReplyError::BadStatus
            });
        }
        // " [" and "]" take 3 bytes.
        let code_room = max_line - status.len() - 3;
        let code = self
            .code
            .as_deref()
            .and_then(|c| clean_code(c, code_room));
        if let (true, Some(want)) = (strict, &self.code)
            && code.as_deref() != Some(want.as_str())
        {
            return Err(if want.len() > code_room {
                ReplyError::LineTooLong
            } else {
                ReplyError::BadStatus
            });
        }
        if strict && !self.ok && self.body.is_some() {
            return Err(ReplyError::BadStatus);
        }
        let has_code = code.is_some();
        let mut line = String::from(status);
        let mut was_cut = false;
        match code {
            Some(code) => {
                line.push_str(" [");
                line.push_str(&code);
                line.push(']');
                // The text is cut here, so the choice of a space before it
                // is made on what is written, and writing what is read back
                // gives the same line. Text that starts with a space needs
                // the space before it, since a reader takes one off.
                // Otherwise the space goes only if the text fits after it.
                let room = max_line.saturating_sub(line.len());
                let bare = cut(&text, room);
                let spaced = cut(&text, room.saturating_sub(1));
                let written = if text.starts_with(' ') || bare.len() < room {
                    if !spaced.is_empty() {
                        line.push(' ');
                    }
                    spaced
                } else {
                    bare
                };
                line.push_str(written);
                was_cut = written.len() < text.len();
            }
            None if !text.is_empty() => {
                line.push(' ');
                line.push_str(&text);
            }
            None => {}
        }
        was_cut |= line.len() > max_line;
        let mut line = cut(&line, max_line).to_string();
        // Text that would be read as a code gets a space in front of it.
        if !has_code
            && line
                .as_bytes()
                .get(status.len() + 1..)
                .and_then(split_code)
                .is_some()
        {
            if strict {
                return Err(ReplyError::BadStatus);
            }
            line.insert(status.len(), ' ');
            was_cut |= line.len() > max_line;
            line = cut(&line, max_line).to_string();
        }
        if strict && was_cut {
            return Err(ReplyError::LineTooLong);
        }
        let mut out = line.into_bytes();
        out.extend_from_slice(b"\r\n");
        if let (true, Some(body)) = (self.ok, &self.body) {
            let mut size = 0usize;
            for content in body_lines(body) {
                let stuffed = content.first() == Some(&b'.');
                if content.len() + usize::from(stuffed) + 2 > MAX_DATA_LINE {
                    return Err(ReplyError::LineTooLong);
                }
                size = size
                    .checked_add(content.len() + 2)
                    .filter(|&n| n <= MAX_BODY)
                    .ok_or(ReplyError::BodyTooLong)?;
                if stuffed {
                    out.push(b'.');
                }
                out.extend_from_slice(content);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b".\r\n");
        }
        Ok(out)
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
pub fn parse_scan_listing(line: &[u8]) -> Option<(NonZeroU32, u64)> {
    let s = std::str::from_utf8(line).ok()?;
    let (msg, rest) = s.split_once(' ')?;
    Some((message(msg).ok()?, leading_decimal(rest)?))
}

/// Writes a scan listing, `msg octets`, without a line end.
pub fn write_scan_listing(msg: NonZeroU32, octets: u64) -> String {
    format!("{msg} {octets}")
}

/// Reads a unique-id listing, `msg uid`: one line of the answer to
/// `UIDL`, or the text of the answer to `UIDL msg`. The unique-id is 1 to
/// [`MAX_UID`] printable ASCII characters other than space.
pub fn parse_unique_id_listing(line: &[u8]) -> Option<(NonZeroU32, String)> {
    let s = std::str::from_utf8(line).ok()?;
    let (msg, uid) = s.split_once(' ')?;
    if uid.is_empty() || uid.len() > MAX_UID || !uid.bytes().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    Some((message(msg).ok()?, uid.to_string()))
}

/// Writes a unique-id listing, `msg uid`, without a line end, or gives
/// `None` if `uid` is not 1 to [`MAX_UID`] printable ASCII characters other
/// than space. A unique-id must differ from every other message's and stay
/// the same across sessions (RFC 1939, section 7), so one that does not fit
/// is not changed to fit: two could become one.
pub fn write_unique_id_listing(msg: NonZeroU32, uid: &str) -> Option<String> {
    let fits = !uid.is_empty() && uid.len() <= MAX_UID && uid.bytes().all(|c| c.is_ascii_graphic());
    fits.then(|| format!("{msg} {uid}"))
}

/// How many bytes of its input [`Reply::parse`] feeds its decoder at once.
const PARSE_PIECE: usize = 64 << 10;

/// Splits a byte stream into lines, and skips lines that are too long.
/// No line longer than [`MAX_AUTH_LINE`], the longest any reader takes, is
/// kept whole: only its first `MAX_AUTH_LINE` bytes and its LF are, which
/// is still too long for every reader.
#[derive(Clone, Debug, Default)]
struct Lines {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped when they make up half of `buf`, so taking many short lines
    /// out of one large feed takes linear time.
    start: usize,
    /// How many bytes after `start` are known to hold no LF.
    scanned: usize,
    /// How many bytes at the end of `buf` follow its last LF.
    tail: usize,
    /// Whether the bytes up to the next LF belong to a line too long to
    /// keep.
    skipping: bool,
    /// How many bytes have been taken out or skipped, in all. Bytes of a
    /// long line dropped as it is fed are not counted: a reader that meets
    /// that line fails, so it never asks how far it got past it.
    consumed: usize,
}

impl Lines {
    fn feed(&mut self, mut bytes: &[u8]) {
        if self.skipping {
            match bytes.iter().position(|&c| c == b'\n') {
                Some(i) => {
                    self.skipping = false;
                    self.consumed = self.consumed.saturating_add(i + 1);
                    bytes = &bytes[i + 1..];
                }
                None => {
                    self.consumed = self.consumed.saturating_add(bytes.len());
                    return;
                }
            }
        }
        while !bytes.is_empty() {
            let (content, lf, rest) = match bytes.iter().position(|&c| c == b'\n') {
                Some(i) => (&bytes[..i], true, &bytes[i + 1..]),
                None => (bytes, false, &[][..]),
            };
            let room = MAX_AUTH_LINE.saturating_sub(self.tail);
            let kept = content.get(..room).unwrap_or(content);
            self.buf.extend_from_slice(kept);
            if lf {
                self.buf.push(b'\n');
                self.tail = 0;
            } else {
                self.tail += kept.len();
            }
            bytes = rest;
        }
    }

    fn held(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or(&[])
    }

    fn clear(&mut self) {
        self.consumed = self.consumed.saturating_add(self.held().len());
        self.buf = Vec::new();
        self.start = 0;
        self.scanned = 0;
        self.tail = 0;
    }

    fn take(&mut self, n: usize) {
        let n = n.min(self.held().len());
        self.start += n;
        self.consumed = self.consumed.saturating_add(n);
        self.scanned = 0;
        if self.start >= self.buf.len() - self.start {
            self.buf.drain(..self.start);
            self.start = 0;
            // A large feed taken out leaves no large buffer behind.
            self.buf.shrink_to(MAX_AUTH_LINE);
        }
        if self.buf.is_empty() {
            self.tail = 0;
        }
    }

    /// The next line, without its LF or the CR before it, or `Err(())`
    /// for a line longer than `max` bytes with its line end. A line too
    /// long is dropped, up to its LF.
    fn next_line(&mut self, max: usize) -> Option<Result<Vec<u8>, ()>> {
        let held = self.held();
        // Bytes fed one at a time are each looked at once.
        let from = self.scanned.min(held.len());
        match held[from..].iter().position(|&c| c == b'\n') {
            Some(p) => {
                let i = from + p;
                if i + 1 > max {
                    self.take(i + 1);
                    return Some(Err(()));
                }
                let line = &held[..i];
                let line = line.strip_suffix(b"\r").unwrap_or(line).to_vec();
                self.take(i + 1);
                Some(Ok(line))
            }
            None if held.len() >= max => {
                self.clear();
                self.skipping = true;
                Some(Err(()))
            }
            None => {
                self.scanned = held.len();
                None
            }
        }
    }
}

/// Splits the stream a server reads into commands. Feed it the bytes a
/// connection reads, in order, and take commands out until it has none.
#[derive(Clone, Debug, Default)]
pub struct CommandDecoder {
    lines: Lines,
}

impl CommandDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> CommandDecoder {
        CommandDecoder::default()
    }

    /// Adds bytes read from the connection.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.lines.feed(bytes);
    }

    /// The next whole line, read as a command. It returns `None` when it
    /// needs more bytes. An error covers one line only, and the next call
    /// reads the line after it. Once this returns `None`, the decoder holds
    /// less than one line, so it holds at most that plus what was fed
    /// since, and never more than [`MAX_AUTH_LINE`] bytes and an LF of any
    /// one line.
    pub fn next_command(&mut self) -> Option<Result<Command, CommandError>> {
        Some(match self.lines.next_line(MAX_COMMAND_LINE)? {
            Ok(line) => Command::parse(&line),
            Err(()) => Err(CommandError::LineTooLong),
        })
    }

    /// The next whole line as it came, without its CRLF, for what is not a
    /// command: the client's base64 answers during `AUTH`, and `*` to
    /// cancel it (RFC 5034, section 4). A line longer than
    /// [`MAX_AUTH_LINE`] is [`CommandError::LineTooLong`], and the next
    /// call reads the line after it.
    pub fn next_line(&mut self) -> Option<Result<Vec<u8>, CommandError>> {
        Some(
            self.lines
                .next_line(MAX_AUTH_LINE)?
                .map_err(|()| CommandError::LineTooLong),
        )
    }

    /// How many bytes are held, waiting for the rest of a line.
    pub fn buffered(&self) -> usize {
        self.lines.held().len()
    }
}

/// Splits the stream a client reads into replies, joining each body's
/// lines. Feed it the bytes a connection reads, in order, and take replies
/// out until it has none.
#[derive(Clone, Debug, Default)]
pub struct ReplyDecoder {
    lines: Lines,
    /// A `+OK` reply whose body is still coming.
    pending: Option<Reply>,
    failed: Option<ReplyError>,
}

impl ReplyDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> ReplyDecoder {
        ReplyDecoder::default()
    }

    /// Adds bytes read from the connection. After a [`ReplyError`] the
    /// stream cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            self.lines.feed(bytes);
        }
    }

    /// The next whole reply, if one has come. `multi_line` says whether a
    /// `+OK` reply to the command it answers has a body, as
    /// [`Request::multi_line`] tells. It is read when the status line
    /// comes, so pass the same value until the reply is returned. The
    /// first reply on a connection, the greeting, has no body.
    ///
    /// It returns `None` when it needs more bytes, and keeps returning the
    /// same error once the stream has broken. Once this returns `None`, the
    /// decoder holds at most one body of [`MAX_BODY`] bytes and less than
    /// one line, plus what was fed since.
    pub fn next_reply(&mut self, multi_line: bool) -> Option<Result<Reply, ReplyError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        loop {
            let Some(pending) = &mut self.pending else {
                let reply = match self.lines.next_line(MAX_REPLY_LINE)? {
                    Ok(line) => Reply::parse_line(&line),
                    Err(()) => Err(ReplyError::LineTooLong),
                };
                match reply {
                    Ok(r) if r.ok && multi_line => {
                        self.pending = Some(Reply {
                            body: Some(Vec::new()),
                            ..r
                        });
                        continue;
                    }
                    Ok(r) => return Some(Ok(r)),
                    Err(e) => return Some(Err(self.fail(e))),
                }
            };
            let line = match self.lines.next_line(MAX_DATA_LINE)? {
                Ok(line) if line.len() <= MAX_DATA_LINE - 2 => line,
                _ => return Some(Err(self.fail(ReplyError::LineTooLong))),
            };
            if line == b"." {
                return self.pending.take().map(Ok);
            }
            let content = line.strip_prefix(b".").unwrap_or(&line);
            let body = pending.body.get_or_insert_with(Vec::new);
            if body.len().saturating_add(content.len() + 2) > MAX_BODY {
                return Some(Err(self.fail(ReplyError::BodyTooLong)));
            }
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n");
        }
    }

    /// The next whole line as it came, without its CRLF, for what is not a
    /// reply: the server's `+ ` challenges during `AUTH` (RFC 5034, section
    /// 4). The exchange ends with a reply, read with
    /// [`ReplyDecoder::next_reply`]. It returns `None` while the body of a
    /// reply is still coming, or until a whole line has come. A line longer
    /// than [`MAX_AUTH_LINE`] breaks the stream, as other errors do.
    pub fn next_line(&mut self) -> Option<Result<Vec<u8>, ReplyError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        if self.pending.is_some() {
            return None;
        }
        Some(match self.lines.next_line(MAX_AUTH_LINE)? {
            Ok(line) => Ok(line),
            Err(()) => Err(self.fail(ReplyError::LineTooLong)),
        })
    }

    /// How many bytes are held, waiting for the rest of a line, not
    /// counting the body of a reply still coming.
    pub fn buffered(&self) -> usize {
        self.lines.held().len()
    }

    fn fail(&mut self, e: ReplyError) -> ReplyError {
        self.failed = Some(e);
        self.lines = Lines::default();
        self.pending = None;
        e
    }
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

/// A response code with what it may not hold dropped, cut to `max` bytes,
/// or `None` if nothing is left. No more than `max` bytes of a level are
/// copied, however long it is.
fn clean_code(code: &str, max: usize) -> Option<String> {
    let mut out = String::new();
    for level in code.split('/') {
        let level: String = level
            .chars()
            .filter(|&c| u8::try_from(c).is_ok_and(rchar))
            .take(max.saturating_add(1))
            .collect();
        if level.is_empty() {
            continue;
        }
        if out.is_empty() {
            out = level;
            out.truncate(max);
        } else if out.len() + 1 + level.len() <= max {
            out.push('/');
            out.push_str(&level);
        } else {
            break;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Status text: UTF-8, with each byte that is not read as `?`, so the
/// text has as many bytes as the line had.
fn text_of(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    for chunk in b.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(std::iter::repeat_n('?', chunk.invalid().len()));
    }
    out
}

/// A body's lines: split at LF, with the CR before each LF dropped. A last
/// line with no LF counts as a line, and loses a CR at its end too. Lines
/// are found one at a time, so a writer that stops at [`MAX_BODY`] never
/// looks at the rest of a large body.
fn body_lines(body: &[u8]) -> impl Iterator<Item = &[u8]> {
    let body = (!body.is_empty()).then(|| body.strip_suffix(b"\n").unwrap_or(body));
    body.into_iter()
        .flat_map(|b| b.split(|&c| c == b'\n'))
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

/// `s` without control characters, and no longer than a command line, so
/// a large input is never copied whole.
fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_COMMAND_LINE)
        .collect()
}

/// `s` without spaces or control characters, cut to `max` bytes, or `_`
/// if nothing is left.
fn word(s: &str, max: usize) -> String {
    let s: String = s
        .chars()
        .filter(|c| !c.is_control() && *c != ' ')
        .take(max)
        .collect();
    let s = cut(&s, max);
    if s.is_empty() {
        "_".to_string()
    } else {
        s.to_string()
    }
}

/// The longest start of `s` that fits in `max` bytes and ends on a
/// character boundary.
fn cut(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
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
    Reply(ReplyError),
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
            Self::Framing(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete POP3 value"),
            Self::Trailing => f.write_str("bytes after POP3 value"),
        }
    }
}
impl core::error::Error for ParseError {}

/// The value cannot be written within the limits without changing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteError;

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("POP3 value cannot be written unchanged")
    }
}
impl core::error::Error for WriteError {}

impl Wire for Command {
    type ParseError = ParseError;
    type WriteError = WriteError;

    /// Reads exactly one command with its required CRLF.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut lines = codec::Lines::new(MAX_COMMAND_LINE - 2, codec::Ending::Crlf);
        match pop_line(&mut lines, bytes, true, false).map_err(ParseError::Framing)? {
            codec::Step::Item(line, used) if used == bytes.len() => {
                let line = line.map_err(|_| ParseError::Command(CommandError::BadCharacter))?;
                Command::parse(&line).map_err(ParseError::Command)
            }
            codec::Step::Item(_, _) => Err(ParseError::Trailing),
            _ => Err(ParseError::Incomplete),
        }
    }

    /// Appends CRLF. Refuses normalization and leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        let bytes = self.try_to_bytes().map_err(|_| WriteError)?;
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

    /// Reads exactly one status line, or a status and a dot-terminated body.
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
                DecodeError::Reply(e) => ParseError::Reply(e),
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

    /// Appends CRLF lines with dot-stuffing. Errors leave `out` unchanged.
    /// Body lines must already end in CRLF. No text or bytes are normalized.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        if self.body.as_ref().is_some_and(|b| b.len() > MAX_BODY) {
            return Err(WriteError);
        }
        let bytes = self.try_to_bytes().map_err(|_| WriteError)?;
        if <Self as Wire>::parse(&bytes).as_ref() != Ok(self) {
            return Err(WriteError);
        }
        out.extend_from_slice(&bytes);
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
    /// A raw line without CRLF, selected by [`Replies::expect_line`].
    Line(Vec<u8>),
}

/// Reads POP3 commands over CRLF lines bounded by [`MAX_COMMAND_LINE`].
///
/// This retains RFC 2449's command limit, which extends RFC 1939.
/// Syntax errors, bare LF, and overlong lines are error items; the decoder
/// skips the rest of an overlong line through LF, then reads the next line.
/// Unterminated lines end the stream. No input is retained.
/// Call [`expect_line`](Self::expect_line) between items for one raw AUTH
/// answer, bounded by [`MAX_AUTH_LINE`] bytes excluding CRLF. Input capacity
/// is always `MAX_AUTH_LINE + 2`, so mode changes fit the same buffer.
/// The legacy [`CommandDecoder`] keeps its void feed and LF tolerance.
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
                            Command::parse(&b).map(Input::Command)
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
/// For an AUTH challenge, call [`expect_line`](Self::expect_line) between
/// items. It reads one raw line without consuming an expectation, then
/// returns to status mode. The queued expectation remains for AUTH's final
/// `+OK` or `-ERR`. Raw lines use [`MAX_AUTH_LINE`] excluding CRLF; input
/// capacity is always `MAX_AUTH_LINE + 2`.
///
/// CRLF is required. Status lines use RFC 1939's [`MAX_REPLY_LINE`]. Body
/// lines use the local [`MAX_DATA_LINE`], including stuffing and CRLF;
/// RFC 1939 supplies no body-line maximum. Dot-stuffing is removed and
/// [`MAX_BODY`] bounds the assembled body. Scanning is linear.
/// A malformed status line is an error item for a single-line expectation,
/// and ends the stream for a multiline expectation. A bad body line rejects
/// its whole reply at the terminator with [`ReplyError::BadBodyLine`]. This
/// covers bare LF and embedded CR. Line overflow and incomplete bodies end
/// the stream. Retained state is bounded by [`MAX_REPLY_HELD`].
/// The legacy [`ReplyDecoder`] keeps its per-call expectation and void feed.
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
    /// Call between items, before reading the challenge. Refuses an active body,
    /// a partial line, or an already selected raw line without changing state.
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
    type Item = Result<Output, ReplyError>;
    type Error = DecodeError;
    const NAME: &'static str = "POP3 replies";

    fn capacity(&self) -> usize {
        MAX_AUTH_LINE + 2
    }

    fn held(&self) -> usize {
        self.expected.len()
            + self.pending.as_ref().map_or(0, |r| {
                r.text.len()
                    + r.code.as_ref().map_or(0, String::len)
                    + r.body.as_ref().map_or(0, Vec::len)
            })
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
            return Ok(codec::Step::Item(
                Ok(Output::Line(line.map_err(DecodeError::Line)?)),
                used,
            ));
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
                reply => return Ok(codec::Step::Item(reply.map(Output::Reply), used)),
            }
        }
        if line.as_deref() == Ok(b".".as_slice()) {
            let reply = self.pending.take().ok_or(ReplyError::BadStatus);
            self.lines = codec::Lines::new(MAX_REPLY_LINE - 2, codec::Ending::Crlf);
            self.body_size = 0;
            return Ok(codec::Step::Item(
                if core::mem::take(&mut self.rejected) {
                    Err(ReplyError::BadBodyLine)
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

    fn n(v: u32) -> NonZeroU32 {
        NonZeroU32::new(v).unwrap()
    }

    fn commands(stream: &[u8]) -> Vec<Result<Command, CommandError>> {
        let mut d = CommandDecoder::new();
        d.feed(stream);
        std::iter::from_fn(|| d.next_command()).collect()
    }

    fn commands_bytewise(stream: &[u8]) -> Vec<Result<Command, CommandError>> {
        let mut d = CommandDecoder::new();
        let mut out = Vec::new();
        for b in stream {
            d.feed(std::slice::from_ref(b));
            out.extend(std::iter::from_fn(|| d.next_command()));
            assert!(d.buffered() < MAX_COMMAND_LINE);
        }
        out
    }

    fn request(line: &[u8]) -> Result<Request, ArgumentError> {
        Request::from_command(&Command::parse(line).unwrap())
    }

    /// Whether the `i`th reply in a test stream has a body if `+OK`.
    fn flag(i: usize) -> bool {
        i % 3 != 1
    }

    /// The replies in a stream, up to the first error, read whole or a
    /// byte at a time, with bodies expected as `flag` says.
    fn replies(stream: &[u8], bytewise: bool) -> Vec<Result<Reply, ReplyError>> {
        let mut d = ReplyDecoder::new();
        let mut out = Vec::new();
        let size = if bytewise { 1 } else { stream.len().max(1) };
        for chunk in stream.chunks(size) {
            d.feed(chunk);
            while let Some(r) = d.next_reply(flag(out.len())) {
                let stop = r.is_err();
                out.push(r);
                if stop {
                    return out;
                }
            }
        }
        out
    }

    // The example session in RFC 1939, section 10, and the commands in
    // sections 5 to 7.

    #[test]
    fn rfc1939_session() {
        let greeting =
            Reply::parse_line(b"+OK POP3 server ready <1896.697170952@dbc.mit.edu>").unwrap();
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
            apop.to_bytes(),
            b"APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n"
        );
        // Upper-case hex is read too, and written in lower case.
        assert_eq!(
            request(b"APOP mrose C4C9334BAC560ECC979E58001B3E22FB"),
            Ok(apop)
        );

        assert_eq!(request(b"STAT"), Ok(Request::Stat));
        let stat = Reply::parse_line(b"+OK 2 320").unwrap();
        assert_eq!(stat.drop_listing(), Some((2, 320)));
        assert_eq!(Reply::stat(2, 320), stat);

        assert_eq!(request(b"LIST"), Ok(Request::List(None)));
        let stream = b"+OK 2 messages (320 octets)\r\n1 120\r\n2 200\r\n.\r\n";
        let (list, used) = Reply::parse(stream, true).unwrap().unwrap();
        assert_eq!(used, stream.len());
        assert_eq!(list.text, "2 messages (320 octets)");
        let listing: Vec<_> = list
            .lines()
            .filter_map(parse_scan_listing)
            .collect();
        assert_eq!(listing, [(n(1), 120), (n(2), 200)]);
        assert_eq!(list.to_bytes(), stream);
        assert_eq!(request(b"LIST 2"), Ok(Request::List(Some(n(2)))));
        assert_eq!(
            parse_scan_listing(Reply::parse_line(b"+OK 2 200").unwrap().text.as_bytes()),
            Some((n(2), 200))
        );
        let none = Reply::parse_line(b"-ERR no such message, only 2 messages in maildrop").unwrap();
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
        let uidl = Reply::parse(
            b"+OK\r\n1 whqtswO00WBw418f9t5JxYwZ\r\n2 QhdPYR:00WBw1Ph7x7\r\n.\r\n",
            true,
        )
        .unwrap()
        .unwrap()
        .0;
        let ids: Vec<_> = uidl
            .lines()
            .filter_map(parse_unique_id_listing)
            .collect();
        assert_eq!(
            ids,
            [
                (n(1), "whqtswO00WBw418f9t5JxYwZ".into()),
                (n(2), "QhdPYR:00WBw1Ph7x7".into())
            ]
        );
        assert_eq!(
            write_unique_id_listing(n(2), "QhdPYR:00WBw1Ph7x7").as_deref(),
            Some("2 QhdPYR:00WBw1Ph7x7")
        );
    }

    #[test]
    fn rfc2449_capa_and_codes() {
        assert_eq!(request(b"CAPA"), Ok(Request::Capa));
        let stream = b"+OK Capability list follows\r\nTOP\r\nUSER\r\nSASL CRAM-MD5 KERBEROS_V4\r\n\
            RESP-CODES\r\nLOGIN-DELAY 900\r\nPIPELINING\r\nEXPIRE 60\r\nUIDL\r\n\
            IMPLEMENTATION Shlemazle-Plotz-v302\r\n.\r\n";
        let (capa, used) = Reply::parse(stream, Request::Capa.multi_line())
            .unwrap()
            .unwrap();
        assert_eq!(used, stream.len());
        assert_eq!(capa.lines().count(), 9);
        assert_eq!(capa.lines().nth(2), Some(&b"SASL CRAM-MD5 KERBEROS_V4"[..]));
        assert_eq!(capa.to_bytes(), stream);

        let in_use =
            Reply::parse_line(b"-ERR [IN-USE] Do you have another POP session running?").unwrap();
        assert_eq!(in_use.code.as_deref(), Some(code::IN_USE));
        assert_eq!(in_use.text, "Do you have another POP session running?");
        assert_eq!(
            Reply::err("Do you have another POP session running?").with_code(code::IN_USE),
            in_use
        );
        let delay = Reply::parse_line(b"-ERR [LOGIN-DELAY] wait a while").unwrap();
        assert_eq!(delay.code.as_deref(), Some(code::LOGIN_DELAY));
        // RFC 3206 codes have levels.
        let temp = Reply::parse_line(b"-ERR [SYS/TEMP] Mail system overloaded").unwrap();
        assert_eq!(temp.code.as_deref(), Some(code::SYS_TEMP));
        assert_eq!(
            temp.to_bytes(),
            b"-ERR [SYS/TEMP] Mail system overloaded\r\n"
        );
        // A code with no text.
        let bare = Reply::parse_line(b"-ERR [AUTH]").unwrap();
        assert_eq!(
            (bare.code.as_deref(), bare.text.as_str()),
            (Some(code::AUTH), "")
        );
        assert_eq!(bare.to_bytes(), b"-ERR [AUTH]\r\n");
    }

    #[test]
    fn rfc2595_stls() {
        assert_eq!(request(b"STLS"), Ok(Request::Stls));
        assert_eq!(Request::Stls.to_bytes(), b"STLS\r\n");
        assert!(Reply::parse_line(b"+OK Begin TLS negotiation").unwrap().ok);
        assert_eq!(request(b"STLS now"), Err(ArgumentError::Extra));
    }

    #[test]
    fn dot_stuffing() {
        let stream = b"+OK 120 octets\r\nSubject: hi\r\n\r\n..\r\n...more\r\n.x\r\n.\r\n";
        let (r, used) = Reply::parse(stream, true).unwrap().unwrap();
        assert_eq!(used, stream.len());
        assert_eq!(
            r.body.as_deref(),
            Some(&b"Subject: hi\r\n\r\n.\r\n..more\r\nx\r\n"[..])
        );
        // A lone dot that was not stuffed is read as its line, not the end.
        let back = r.to_bytes();
        assert_eq!(
            back,
            b"+OK 120 octets\r\nSubject: hi\r\n\r\n..\r\n...more\r\nx\r\n.\r\n"
        );
        assert_eq!(Reply::parse(&back, true).unwrap().unwrap().0, r);
        // Bodies with LF line ends are written with CRLF.
        let r = Reply::ok("x").with_body(b".a\nb".to_vec());
        assert_eq!(r.to_bytes(), b"+OK x\r\n..a\r\nb\r\n.\r\n");
        // An empty body.
        let r = Reply::ok("").with_body(Vec::new());
        assert_eq!(r.to_bytes(), b"+OK\r\n.\r\n");
        assert_eq!(Reply::parse(&r.to_bytes(), true).unwrap().unwrap().0, r);
        // A -ERR reply never has a body.
        let (e, used) = Reply::parse(b"-ERR no\r\n1 2\r\n.\r\n", true)
            .unwrap()
            .unwrap();
        assert_eq!((e.body, used), (None, 9));
        assert_eq!(
            Reply::err("no").with_body(b"x".to_vec()).to_bytes(),
            b"-ERR no\r\n"
        );
    }

    #[test]
    fn command_errors() {
        assert_eq!(Command::parse(b""), Err(CommandError::BadKeyword));
        assert_eq!(Command::parse(b"RE 1"), Err(CommandError::BadKeyword));
        assert_eq!(Command::parse(b"RETRY 1"), Err(CommandError::BadKeyword));
        assert_eq!(
            Command::parse(b"RE\xc3\xa9 1"),
            Err(CommandError::BadKeyword)
        );
        assert_eq!(Command::parse(b" RETR 1"), Err(CommandError::BadKeyword));
        assert_eq!(Command::parse(b"RETR\t1"), Err(CommandError::BadCharacter));
        assert_eq!(
            Command::parse(b"PASS a\rb"),
            Err(CommandError::BadCharacter)
        );
        assert_eq!(
            Command::parse(b"PASS \xff"),
            Err(CommandError::BadCharacter)
        );
        assert_eq!(
            Command::parse(b"PASS \x7f"),
            Err(CommandError::BadCharacter)
        );
        let long = [b"PASS ".as_slice(), &[b'a'; 249]].concat();
        assert_eq!(Command::parse(&long), Err(CommandError::LineTooLong));
        assert!(Command::parse(&long[..253]).is_ok());
        // Unknown keywords are commands still, and requests of their own.
        let auth = Command::parse(b"AUTH PLAIN").unwrap();
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
            Command::parse(b"UTF8"),
            Ok(Command {
                keyword: "UTF8".into(),
                argument: None
            })
        );
        // A space with nothing after it is no argument.
        assert_eq!(
            Command::parse(b"LIST "),
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
    fn reply_errors() {
        assert_eq!(Reply::parse_line(b""), Err(ReplyError::BadStatus));
        assert_eq!(Reply::parse_line(b"+ok"), Err(ReplyError::BadStatus));
        assert_eq!(Reply::parse_line(b"+OKAY"), Err(ReplyError::BadStatus));
        assert_eq!(Reply::parse_line(b"-ERROR"), Err(ReplyError::BadStatus));
        assert_eq!(Reply::parse_line(b"OK"), Err(ReplyError::BadStatus));
        // Brackets that do not hold a code are plain text.
        for line in [&b"+OK [IN-USE"[..], b"+OK [/X]", b"+OK [A B]"] {
            assert_eq!(Reply::parse_line(line).unwrap().code, None);
        }
        let long = [b"+OK ".as_slice(), &[b'a'; 507]].concat();
        assert_eq!(Reply::parse_line(&long), Err(ReplyError::LineTooLong));
        assert!(Reply::parse_line(&long[..510]).is_ok());
        // Through the decoder.
        let mut stream = long.clone();
        stream.extend_from_slice(b"\r\n");
        assert_eq!(Reply::parse(&stream, false), Err(ReplyError::LineTooLong));
        assert_eq!(
            Reply::parse(&stream[..512], false),
            Err(ReplyError::LineTooLong)
        );
        let mut data = b"+OK\r\n".to_vec();
        data.extend(std::iter::repeat_n(b'x', MAX_DATA_LINE - 1));
        data.extend_from_slice(b"\r\n.\r\n");
        assert_eq!(Reply::parse(&data, true), Err(ReplyError::LineTooLong));
        // One byte shorter fits.
        data.remove(5);
        assert!(Reply::parse(&data, true).unwrap().is_some());
        // A body over the limit.
        let line = [vec![b'y'; MAX_DATA_LINE - 2], b"\r\n".to_vec()].concat();
        let mut big = b"+OK\r\n".to_vec();
        for _ in 0..MAX_BODY / line.len() + 1 {
            big.extend_from_slice(&line);
        }
        big.extend_from_slice(b".\r\n");
        assert_eq!(Reply::parse(&big, true), Err(ReplyError::BodyTooLong));
        // Bytes that are not UTF-8 are read as '?'.
        assert_eq!(Reply::parse_line(b"+OK caf\xe9").unwrap().text, "caf?");
        // Helpers refuse what they cannot read.
        assert_eq!(parse_scan_listing(b"0 12"), None);
        assert_eq!(parse_scan_listing(b"1"), None);
        assert_eq!(parse_scan_listing(b"1 x"), None);
        assert_eq!(parse_scan_listing(b"1 12 extra"), Some((n(1), 12)));
        assert_eq!(parse_unique_id_listing(b"1 "), None);
        assert_eq!(parse_unique_id_listing(b"1 a b"), None);
        assert_eq!(
            parse_unique_id_listing(&[b"1 ".as_slice(), &[b'u'; 71]].concat()),
            None
        );
        assert_eq!(Reply::ok("x").drop_listing(), None);
        assert_eq!(Reply::ok("no timestamp").timestamp(), None);
    }

    #[test]
    fn decoder_keeps_going_after_a_bad_command() {
        let mut stream = b"NOOP\r\n".to_vec();
        stream.extend(std::iter::repeat_n(b'x', 1000));
        stream.extend_from_slice(b"\r\nBADKEY\r\nQUIT\n");
        let want = vec![
            Ok(Command {
                keyword: "NOOP".into(),
                argument: None,
            }),
            Err(CommandError::LineTooLong),
            Err(CommandError::BadKeyword),
            Ok(Command {
                keyword: "QUIT".into(),
                argument: None,
            }),
        ];
        assert_eq!(commands(&stream), want);
        assert_eq!(commands_bytewise(&stream), want);
    }

    #[test]
    fn reply_decoder_stops_at_an_error() {
        let mut d = ReplyDecoder::new();
        d.feed(b"+OK hi\r\nHELLO\r\n+OK\r\n");
        assert_eq!(d.next_reply(false), Some(Ok(Reply::ok("hi"))));
        assert_eq!(d.next_reply(false), Some(Err(ReplyError::BadStatus)));
        assert_eq!(d.next_reply(false), Some(Err(ReplyError::BadStatus)));
        d.feed(b"+OK\r\n");
        assert_eq!(d.next_reply(false), Some(Err(ReplyError::BadStatus)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn truncated_prefixes() {
        let stream: &[u8] = b"+OK 2 messages\r\n1 120\r\n..2 200\r\n.\r\n";
        for i in 0..stream.len() {
            assert_eq!(Reply::parse(&stream[..i], true), Ok(None), "{i} bytes");
        }
        assert!(Reply::parse(stream, true).unwrap().is_some());
        let line: &[u8] = b"-ERR [SYS/TEMP] later\r\n";
        for i in 0..line.len() {
            assert_eq!(Reply::parse(&line[..i], false), Ok(None), "{i} bytes");
        }
        let cmd: &[u8] = b"APOP mrose c4c9334bac560ecc979e58001b3e22fb\r\n";
        for i in 0..cmd.len() {
            assert!(commands(&cmd[..i]).is_empty(), "{i} bytes");
        }
        assert_eq!(commands(cmd).len(), 1);
    }

    #[test]
    fn requests_round_trip() {
        let all = [
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
        let stream: Vec<u8> = all.iter().flat_map(Request::to_bytes).collect();
        let got: Vec<Request> = commands_bytewise(&stream)
            .into_iter()
            .map(|c| Request::from_command(&c.unwrap()).unwrap())
            .collect();
        assert_eq!(got, all);
    }

    #[test]
    fn writers_cap_what_they_write() {
        // Names lose spaces and are cut; empty ones become '_'.
        let user = Request::User(format!("a b\r\n{}", "é".repeat(200)));
        let bytes = user.to_bytes();
        assert!(bytes.len() <= MAX_COMMAND_LINE);
        let Ok(Request::User(name)) = request(bytes.strip_suffix(b"\r\n").unwrap()) else {
            panic!()
        };
        assert!(name.starts_with("abé"));
        assert_eq!(Request::User(" \r".into()).to_bytes(), b"USER _\r\n");
        assert_eq!(Request::Pass("\n".into()).to_bytes(), b"PASS _\r\n");
        let pass = Request::Pass("p".repeat(1000)).to_bytes();
        assert_eq!(pass.len(), MAX_COMMAND_LINE);
        assert!(matches!(commands(&pass)[..], [Ok(_)]));
        // Bad keywords are written as NOOP, with no argument.
        let c = Command {
            keyword: "R\r\n".into(),
            argument: Some("x\ny".into()),
        };
        assert_eq!(c.to_bytes(), b"NOOP\r\n");
        let c = Command {
            keyword: "RETR".into(),
            argument: Some("x\ny".into()),
        };
        assert_eq!(c.to_bytes(), b"RETR xy\r\n");
        // Status text loses LFs, is cut, and does not start a code by mistake.
        let r = Reply::ok(&format!("[x\n{}", "é".repeat(400)));
        let b = r.to_bytes();
        assert!(b.len() <= MAX_REPLY_LINE);
        let back = Reply::parse(&b, false).unwrap().unwrap().0;
        assert_eq!(back.code, None);
        assert!(back.text.starts_with("[xé"));
        let r = Reply::ok(&format!("[AUTH]{}", "a".repeat(600)));
        let b = r.to_bytes();
        assert!(b.starts_with(b"+OK  [AUTH]aaa") && b.len() == MAX_REPLY_LINE);
        let back = Reply::parse(&b, false).unwrap().unwrap().0;
        assert_eq!(back.code, None);
        assert_eq!(Reply::err("[A] x").to_bytes(), b"-ERR  [A] x\r\n");
        assert_eq!(Reply::err("[A] x").try_to_bytes(), Err(ReplyError::BadStatus));
        // Codes lose what they may not hold.
        let r = Reply::err("t").with_code("SYS/ /T]EMP/");
        assert_eq!(r.to_bytes(), b"-ERR [SYS/TEMP] t\r\n");
        let r = Reply::err("t").with_code("] /");
        assert_eq!(r.to_bytes(), b"-ERR t\r\n");
        // A code is cut to fit the line, a level at a time, before text.
        let r = Reply::err("t").with_code(&"A".repeat(600));
        let back = Reply::parse(&r.to_bytes(), false).unwrap().unwrap().0;
        assert_eq!(back.code.unwrap().len(), MAX_CODE - 1);
        assert_eq!(back.text, "");
        let r = Reply::err("t").with_code(&format!("{}/{}", "A".repeat(300), "B".repeat(300)));
        let back = Reply::parse(&r.to_bytes(), false).unwrap().unwrap().0;
        assert_eq!(back.code.unwrap(), "A".repeat(300));
        // A unique-id that does not fit is not written.
        assert_eq!(write_unique_id_listing(n(1), " "), None);
        assert_eq!(write_unique_id_listing(n(1), ""), None);
        assert_eq!(write_unique_id_listing(n(1), &"u".repeat(MAX_UID + 1)), None);
        let w = write_unique_id_listing(n(1), &"u".repeat(MAX_UID)).unwrap();
        assert_eq!(
            parse_unique_id_listing(w.as_bytes()).unwrap().1.len(),
            MAX_UID
        );
    }

    // Problems found in review against RFC 1939, 2449 and 2595.

    #[test]
    fn keywords_are_any_printable_ascii() {
        // RFC 2449, section 3: keyword = 3*4VCHAR.
        assert_eq!(
            Command::parse(b"X-AB 1"),
            Ok(Command {
                keyword: "X-AB".into(),
                argument: Some("1".into())
            })
        );
        assert_eq!(
            Command {
                keyword: "x-ab".into(),
                argument: None
            }
            .to_bytes(),
            b"X-AB\r\n"
        );
        assert_eq!(Command::parse(b"\xc3\xa9AB"), Err(CommandError::BadKeyword));
    }

    #[test]
    fn arguments_may_pass_40_bytes() {
        // RFC 2449, section 4 lifts the 40-byte limit of RFC 1939; only
        // the 255-byte line limit is left.
        let user = "firstname.lastname@mail.some-long-domain.example";
        assert!(user.len() > 40);
        assert_eq!(
            request(format!("USER {user}").as_bytes()),
            Ok(Request::User(user.into()))
        );
        let apop = Request::Apop {
            name: user.repeat(10),
            digest: [1; 16],
        };
        let bytes = apop.to_bytes();
        assert!(bytes.len() <= MAX_COMMAND_LINE);
        let Ok(Request::Apop { digest, .. }) = request(bytes.strip_suffix(b"\r\n").unwrap()) else {
            panic!()
        };
        assert_eq!(digest, [1; 16]);
    }

    #[test]
    fn code_may_run_into_text() {
        // text = resp-code *CHAR (RFC 2449, section 3).
        // Bytes that are not UTF-8 are read as '?' before the code.
        let r = Reply::parse_line(b"-ERR [a\xff]x").unwrap();
        assert_eq!((r.code.as_deref(), r.text.as_str()), (Some("a?"), "x"));
        assert_eq!(r.to_bytes(), b"-ERR [a?] x\r\n");
        let r = Reply::parse_line(b"-ERR [IN-USE]locked").unwrap();
        assert_eq!(
            (r.code.as_deref(), r.text.as_str()),
            (Some("IN-USE"), "locked")
        );
        let mut d = ReplyDecoder::new();
        d.feed(b"-ERR [AUTH]no\r\n+OK\r\n");
        assert!(d.next_reply(false).unwrap().is_ok());
        assert_eq!(d.next_reply(false), Some(Ok(Reply::ok(""))));
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
            let r = Reply::parse_line(line).unwrap();
            assert_eq!(r.code, None);
            assert_eq!(
                r.text.as_bytes(),
                &line[line.iter().position(|&c| c == b'[').unwrap()..]
            );
            assert_eq!(r.to_bytes(), [line, b"\r\n"].concat());
        }
        // A code may fill the line (RFC 2449 sets no limit of its own).
        let long_code = [b"+OK [".as_slice(), &[b'A'; MAX_CODE], b"]"].concat();
        assert_eq!(long_code.len(), MAX_REPLY_LINE - 2);
        let r = Reply::parse_line(&long_code).unwrap();
        assert_eq!(r.code.as_deref().map(str::len), Some(MAX_CODE));
        assert_eq!(r.try_to_bytes().unwrap(), [&long_code[..], b"\r\n"].concat());
    }

    #[test]
    fn codes_match_without_case_and_detail() {
        // RFC 2449, section 8: codes are read in any case, and clients
        // ignore detail they do not know.
        let r = Reply::parse_line(b"-ERR [sys/temp/disk] full").unwrap();
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

    // Problems found in the hardening review.

    #[test]
    fn long_keywords_are_not_cut_into_other_commands() {
        // "RETRY" must not be written as "RETR", a different command.
        let c = Command {
            keyword: "RETRY".into(),
            argument: Some("1".into()),
        };
        assert_eq!(c.to_bytes(), b"NOOP\r\n");
        let r = Request::Other(Command {
            keyword: "DELETE".into(),
            argument: Some("1".into()),
        });
        assert_eq!(r.to_bytes(), b"NOOP\r\n");
        // Dropped characters still count only once they are gone.
        let c = Command {
            keyword: "R E\tT R".into(),
            argument: None,
        };
        assert_eq!(c.to_bytes(), b"RETR\r\n");
    }

    #[test]
    fn writers_stop_reading_input_past_their_limits() {
        // A body of many empty lines, far past MAX_BODY, is refused in
        // about the time it takes to write MAX_BODY bytes.
        let started = std::time::Instant::now();
        let r = Reply::ok("").with_body(vec![b'\n'; MAX_BODY * 8]);
        assert_eq!(r.try_to_bytes(), Err(ReplyError::BodyTooLong));
        let back = Reply::parse(&r.to_bytes(), true).unwrap().unwrap().0;
        assert!(!back.ok);
        // Long text and arguments are cut too.
        let text = "t".repeat(MAX_BODY);
        assert_eq!(Reply::ok(&text).to_bytes().len(), MAX_REPLY_LINE);
        assert_eq!(
            Request::Pass(text.clone()).to_bytes().len(),
            MAX_COMMAND_LINE
        );
        assert_eq!(Request::User(text).to_bytes().len(), MAX_COMMAND_LINE);
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn body_lines_match_the_old_split() {
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
    fn decoders_take_many_small_lines_in_linear_time() {
        let stream: Vec<u8> = b"NOOP\r\n"
            .iter()
            .copied()
            .cycle()
            .take(6 * 200_000)
            .collect();
        let started = std::time::Instant::now();
        assert_eq!(commands(&stream).len(), 200_000);
        let mut body = b"+OK\r\n".to_vec();
        body.extend(b"a\r\n".iter().copied().cycle().take(3 * 200_000));
        body.extend_from_slice(b".\r\n");
        let r = Reply::parse(&body, true).unwrap().unwrap().0;
        assert_eq!(r.lines().count(), 200_000);
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
    }

    // Problems found in the third review.

    #[test]
    fn decoders_keep_no_long_line_or_large_buffer() {
        // A long line fed at once is not kept past MAX_AUTH_LINE, with or
        // without its line end in the same feed.
        let long = vec![b'x'; 1 << 20];
        let mut d = CommandDecoder::new();
        d.feed(&[long.as_slice(), b"\r\nQUIT\r\n"].concat());
        assert!(d.buffered() <= MAX_AUTH_LINE + 9, "{}", d.buffered());
        let got: Vec<_> = std::iter::from_fn(|| d.next_command()).collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], Err(CommandError::LineTooLong));
        assert_eq!(got[1].as_ref().unwrap().keyword, "QUIT");
        let mut d = CommandDecoder::new();
        d.feed(&long);
        d.feed(&long);
        assert!(d.buffered() <= MAX_AUTH_LINE, "{}", d.buffered());
        d.feed(b"\r\nQUIT\r\n");
        let got: Vec<_> = std::iter::from_fn(|| d.next_command()).collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], Err(CommandError::LineTooLong));
        // The same for replies, as a status line and as a body line.
        for multi in [false, true] {
            let mut d = ReplyDecoder::new();
            d.feed(&[b"+OK\r\n".as_slice(), &long, b"\r\n"].concat());
            assert!(d.buffered() <= MAX_AUTH_LINE + 6, "{}", d.buffered());
            let first = d.next_reply(multi);
            if !multi {
                assert_eq!(first, Some(Ok(Reply::ok(""))));
            }
            let mut last = first;
            while let Some(Ok(_)) = last {
                last = d.next_reply(multi);
            }
            assert_eq!(last, Some(Err(ReplyError::LineTooLong)));
        }
        // A reply read from the front of a large input says how far it
        // went.
        let stream = [b"+OK hi\r\n".as_slice(), &long, b"\r\n"].concat();
        assert_eq!(
            Reply::parse(&stream, false),
            Ok(Some((Reply::ok("hi"), 8)))
        );
        // Many short lines fed at once leave no large buffer once read.
        let mut d = CommandDecoder::new();
        let many: Vec<u8> = b"NOOP\r\n".iter().copied().cycle().take(6 << 17).collect();
        d.feed(&many);
        d.feed(b"NO");
        assert_eq!(std::iter::from_fn(|| d.next_command()).count(), 1 << 17);
        assert_eq!(d.buffered(), 2);
        assert!(d.lines.buf.capacity() <= MAX_AUTH_LINE, "{}", d.lines.buf.capacity());
    }

    #[test]
    fn bodies_that_do_not_fit_are_refused_not_cut() {
        // RFC 1939, section 5: RETR sends the whole message. A body that
        // cannot be sent whole gives -ERR, so a client never deletes a
        // message it got only part of.
        let mut body = vec![b'a'; MAX_DATA_LINE];
        body.extend_from_slice(b"\r\n");
        let r = Reply::ok("1 message").with_body(body);
        assert_eq!(r.try_to_bytes(), Err(ReplyError::LineTooLong));
        assert_eq!(r.to_bytes(), b"-ERR [SYS/PERM] reply line too long\r\n");
        let line = [vec![b'b'; MAX_DATA_LINE - 2], b"\r\n".to_vec()].concat();
        let r = Reply::ok("").with_body(line.repeat(MAX_BODY / line.len() + 1));
        assert_eq!(r.try_to_bytes(), Err(ReplyError::BodyTooLong));
        assert_eq!(r.to_bytes(), b"-ERR [SYS/PERM] reply body too long\r\n");
        // The longest lines fit, dot or not, and read back the same.
        let dotted = [b".".as_slice(), &[b'c'; MAX_DATA_LINE - 4], b"\r\n"].concat();
        let r = Reply::ok("").with_body([line.clone(), dotted].concat());
        let bytes = r.try_to_bytes().unwrap();
        assert_eq!(bytes, r.to_bytes());
        assert_eq!(Reply::parse(&bytes, true).unwrap().unwrap().0, r);
        // A body exactly MAX_BODY long fits.
        let lines = MAX_BODY / line.len() - 1;
        let last = vec![b'd'; MAX_BODY - lines * line.len() - 2];
        let body = [line.repeat(lines), last, b"\r\n".to_vec()].concat();
        assert_eq!(body.len(), MAX_BODY);
        let r = Reply::ok("").with_body(body);
        assert_eq!(Reply::parse(&r.try_to_bytes().unwrap(), true).unwrap().unwrap().0, r);
    }

    #[test]
    fn arguments_are_counted_not_collected() {
        // A public Command may hold far more than a line.
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
        // A huge code is cut to the line.
        let r = Reply::err("").with_code(&"A".repeat(16 << 20));
        assert_eq!(r.to_bytes().len(), MAX_REPLY_LINE);
        // Lines are found one at a time.
        let r = Reply::ok("").with_body(b"a\nb\r\nc".to_vec());
        let mut lines = r.lines();
        assert_eq!(lines.next(), Some(&b"a"[..]));
        assert_eq!(lines.count(), 2);
        assert_eq!(Reply::ok("").lines().count(), 0);
    }

    #[test]
    fn writers_can_refuse_rather_than_change() {
        // A password one byte too long for the line is refused, not cut.
        let p = Request::Pass("p".repeat(249));
        assert_eq!(p.try_to_bytes(), None);
        assert_eq!(p.to_bytes().len(), MAX_COMMAND_LINE);
        let p = Request::Pass("p".repeat(248));
        assert_eq!(p.try_to_bytes(), Some(p.to_bytes()));
        for bad in [
            Request::User("a b".into()),
            Request::User(String::new()),
            Request::User("a\r".into()),
            Request::Pass(String::new()),
            Request::Pass("a\nb".into()),
            Request::Apop {
                name: "a b".into(),
                digest: [0; 16],
            },
            Request::Apop {
                name: "u".repeat(216),
                digest: [0; 16],
            },
            // A keyword this module knows is not Other, and RETRY is not
            // a keyword.
            Request::Other(Command {
                keyword: "user".into(),
                argument: Some("x".into()),
            }),
            Request::Other(Command {
                keyword: "RETRY".into(),
                argument: Some("1".into()),
            }),
        ] {
            assert_eq!(bad.try_to_bytes(), None, "{bad:?}");
            // to_bytes still writes something the parsers take.
            let line = bad.to_bytes();
            let c = Command::parse(line.strip_suffix(b"\r\n").unwrap()).unwrap();
            assert!(Request::from_command(&c).is_ok(), "{bad:?}");
        }
        for good in [
            Request::Pass("open sesame ".into()),
            Request::User("é".into()),
            Request::Apop {
                name: "u".repeat(215),
                digest: [7; 16],
            },
            Request::Other(Command {
                keyword: "auth".into(),
                argument: Some("PLAIN".into()),
            }),
            Request::Quit,
        ] {
            let bytes = good.try_to_bytes().unwrap();
            let c = Command::parse(bytes.strip_suffix(b"\r\n").unwrap()).unwrap();
            match (&good, Request::from_command(&c).unwrap()) {
                (Request::Other(_), Request::Other(back)) => assert_eq!(back.keyword, "AUTH"),
                (_, back) => assert_eq!(back, good),
            }
        }
        // A bad keyword becomes a bare NOOP, which reads as Noop.
        let c = Command {
            keyword: "RETRY".into(),
            argument: Some("1".into()),
        };
        let line = c.to_bytes();
        let back = Command::parse(line.strip_suffix(b"\r\n").unwrap()).unwrap();
        assert_eq!(Request::from_command(&back), Ok(Request::Noop));
        assert_eq!(c.try_to_bytes(), Err(CommandError::BadKeyword));
        let c = |k: &str, a: Option<&str>| Command {
            keyword: k.into(),
            argument: a.map(String::from),
        };
        assert_eq!(c("NOOP", Some("a\tb")).try_to_bytes(), Err(CommandError::BadCharacter));
        assert_eq!(
            c("PASS", Some(&"p".repeat(249))).try_to_bytes(),
            Err(CommandError::LineTooLong)
        );
        assert_eq!(c("x-ab", Some("")).try_to_bytes(), Ok(b"X-AB\r\n".to_vec()));
    }

    #[test]
    fn unique_ids_are_never_merged() {
        // RFC 1939, section 7: unique-ids differ between messages.
        let a = format!("{}X", "a".repeat(70));
        let b = format!("{}Y", "a".repeat(70));
        assert_eq!(write_unique_id_listing(n(1), &a), None);
        assert_eq!(write_unique_id_listing(n(2), &b), None);
        assert_eq!(write_unique_id_listing(n(1), "a b"), None);
        assert_eq!(write_unique_id_listing(n(1), "aé"), None);
    }

    #[test]
    fn full_status_lines_round_trip() {
        // RFC 2449, section 3: text may follow the code with no space.
        let line = [b"-ERR [AUTH]".as_slice(), &[b'x'; 499]].concat();
        assert_eq!(line.len(), MAX_REPLY_LINE - 2);
        let r = Reply::parse_line(&line).unwrap();
        assert_eq!(r.text.len(), 499);
        let want = [&line[..], b"\r\n"].concat();
        assert_eq!(r.to_bytes(), want);
        assert_eq!(r.try_to_bytes(), Ok(want));
        // Text that starts with a space keeps the space before it.
        let r = Reply::err(&format!(" {}", "y".repeat(498))).with_code("AUTH");
        assert_eq!(r.try_to_bytes(), Err(ReplyError::LineTooLong));
        let back = Reply::parse(&r.to_bytes(), false).unwrap().unwrap().0;
        assert!(back.text.starts_with(" y"));
        // Text cut away whole leaves no space after the code, and what is
        // written reads back and writes the same.
        for text in [" more", "more", "é"] {
            let r = Reply::ok(text).with_code(&"A".repeat(MAX_CODE - 1));
            let bytes = r.to_bytes();
            assert_eq!(bytes.len(), MAX_REPLY_LINE - 1 + usize::from(text == "more"));
            let back = Reply::parse(&bytes, false).unwrap().unwrap().0;
            assert_eq!(back.to_bytes(), bytes, "{text:?}");
        }
        // try_to_bytes refuses what to_bytes would change.
        assert_eq!(Reply::ok("a\nb").try_to_bytes(), Err(ReplyError::BadStatus));
        assert_eq!(
            Reply::ok("t").with_code("SYS/").try_to_bytes(),
            Err(ReplyError::BadStatus)
        );
        assert_eq!(
            Reply::ok(&"t".repeat(508)).try_to_bytes(),
            Err(ReplyError::LineTooLong)
        );
        assert_eq!(
            Reply::err("x").with_body(Vec::new()).try_to_bytes(),
            Err(ReplyError::BadStatus)
        );
        assert_eq!(
            Reply::ok(&"t".repeat(506)).try_to_bytes().map(|b| b.len()),
            Ok(MAX_REPLY_LINE)
        );
    }

    #[test]
    fn long_codes_keep_their_meaning() {
        // RFC 2449, section 8: clients ignore detail they do not know.
        let line = [b"-ERR [SYS/TEMP/".as_slice(), &[b'x'; 120], b"] retry"].concat();
        let r = Reply::parse_line(&line).unwrap();
        assert!(r.has_code(code::SYS_TEMP));
        assert_eq!(r.text, "retry");
        assert_eq!(r.to_bytes(), [&line[..], b"\r\n"].concat());
    }

    #[test]
    fn auth_exchanges_read_as_lines() {
        // RFC 5034, section 4: the server sends "+ " challenges, and the
        // client base64 answers or "*".
        let mut d = CommandDecoder::new();
        let answer = "QUFB".repeat(1000);
        d.feed(format!("AUTH PLAIN\r\n{answer}\r\n*\r\nQUIT\r\n").as_bytes());
        let auth = d.next_command().unwrap().unwrap();
        assert!(matches!(Request::from_command(&auth), Ok(Request::Other(_))));
        assert_eq!(d.next_line(), Some(Ok(answer.into_bytes())));
        assert_eq!(d.next_line(), Some(Ok(b"*".to_vec())));
        assert_eq!(d.next_command().unwrap().unwrap().keyword, "QUIT");
        assert_eq!(d.next_line(), None);
        let mut d = CommandDecoder::new();
        d.feed(&[&[b'Q'; MAX_AUTH_LINE][..], b"\r\n=\r\n"].concat());
        assert_eq!(d.next_line(), Some(Err(CommandError::LineTooLong)));
        assert_eq!(d.next_line(), Some(Ok(b"=".to_vec())));

        let mut d = ReplyDecoder::new();
        d.feed(b"+ \r\n+ PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2U+\r\n+OK done\r\n");
        assert_eq!(d.next_line(), Some(Ok(b"+ ".to_vec())));
        assert_eq!(
            d.next_line(),
            Some(Ok(b"+ PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2U+".to_vec()))
        );
        assert_eq!(d.next_reply(false), Some(Ok(Reply::ok("done"))));
        // No line is taken out of a body still coming.
        let mut d = ReplyDecoder::new();
        d.feed(b"+OK\r\nx\r\n");
        assert_eq!(d.next_reply(true), None);
        assert_eq!(d.next_line(), None);
        d.feed(b".\r\n");
        assert!(d.next_reply(true).unwrap().is_ok());
        let mut d = ReplyDecoder::new();
        d.feed(&[b'+'; MAX_AUTH_LINE + 1]);
        assert_eq!(d.next_line(), Some(Err(ReplyError::LineTooLong)));
        assert_eq!(d.next_reply(false), Some(Err(ReplyError::LineTooLong)));
    }

    #[test]
    fn sizes_may_have_text_right_after_them() {
        // RFC 1939, section 5 sets no rule on what follows the size.
        assert_eq!(Reply::ok("2 320(octets)").drop_listing(), Some((2, 320)));
        assert_eq!(Reply::ok("2 320 octets").drop_listing(), Some((2, 320)));
        assert_eq!(parse_scan_listing(b"1 120(octets)"), Some((n(1), 120)));
        assert_eq!(Reply::ok("2 (320)").drop_listing(), None);
        assert_eq!(Reply::ok("2x 320").drop_listing(), None);
        assert_eq!(parse_scan_listing(b"1x 120"), None);
        assert_eq!(parse_scan_listing(b"1  120"), None);
    }

    /// A small deterministic generator, so the fuzz loop needs no crates.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }

        fn buffer(&mut self) -> Vec<u8> {
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
            let n = self.below(40);
            let mut out = Vec::new();
            for _ in 0..n {
                match self.below(24) {
                    0 | 1 => out.push(self.next() as u8),
                    2 => out.extend(std::iter::repeat_n(b'x', self.below(3) * MAX_COMMAND_LINE)),
                    3 => out.extend(std::iter::repeat_n(b'y', self.below(3) * MAX_DATA_LINE / 2)),
                    _ => out.extend_from_slice(PIECES[self.below(PIECES.len())]),
                }
            }
            out
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x9093);
        for _ in 0..4000 {
            let data = rng.buffer();
            let whole = commands(&data);
            assert_eq!(whole, commands_bytewise(&data));
            // Chunks of random sizes, taking commands out after each.
            let mut d = CommandDecoder::new();
            let mut chunked = Vec::new();
            let mut rest = data.as_slice();
            while !rest.is_empty() {
                let (chunk, tail) =
                    rest.split_at(1 + rng.below(rest.len().min(MAX_COMMAND_LINE + 9)));
                d.feed(chunk);
                assert!(d.buffered() <= chunk.len() + MAX_COMMAND_LINE);
                chunked.extend(std::iter::from_fn(|| d.next_command()));
                assert!(d.buffered() < MAX_COMMAND_LINE);
                rest = tail;
            }
            assert_eq!(chunked, whole);
            for c in whole.iter().flatten() {
                assert_eq!(commands(&c.to_bytes()), [Ok(c.clone())]);
                assert_eq!(c.try_to_bytes(), Ok(c.to_bytes()));
                if let Ok(r) = Request::from_command(c) {
                    let bytes = r.try_to_bytes().unwrap();
                    assert_eq!(bytes, r.to_bytes());
                    let again = commands(&bytes);
                    assert_eq!(again.len(), 1);
                    let back = Request::from_command(again[0].as_ref().unwrap()).unwrap();
                    assert_eq!(back, r);
                }
            }
            let got = replies(&data, false);
            assert_eq!(got, replies(&data, true));
            for r in got.iter().flatten() {
                let bytes = r.to_bytes();
                assert_eq!(r.try_to_bytes().as_ref(), Ok(&bytes));
                let (back, used) = Reply::parse(&bytes, r.body.is_some()).unwrap().unwrap();
                assert_eq!(&back, r);
                assert_eq!(used, bytes.len());
                if let Some(code) = &r.code {
                    assert!(r.has_code(code) && r.has_code(&code.to_ascii_lowercase()));
                }
                if let Some((c, o)) = r.drop_listing() {
                    assert_eq!(Reply::stat(c, o).drop_listing(), Some((c, o)));
                }
                for line in r.lines() {
                    if let Some((m, o)) = parse_scan_listing(line) {
                        assert_eq!(
                            parse_scan_listing(write_scan_listing(m, o).as_bytes()),
                            Some((m, o))
                        );
                    }
                    if let Some((m, u)) = parse_unique_id_listing(line) {
                        let w = write_unique_id_listing(m, &u).unwrap();
                        assert_eq!(parse_unique_id_listing(w.as_bytes()), Some((m, u)));
                    }
                }
            }
            // Any bytes as one line, and as one reply.
            let _ = Command::parse(&data);
            let _ = Reply::parse_line(&data);
            let _ = Reply::parse(&data, true);
            let _ = Reply::parse(&data, false);
            // Writers never write what readers refuse, whatever the fields
            // hold, each chosen on its own.
            let s = String::from_utf8_lossy(&data);
            let other = rng.buffer();
            let t = String::from_utf8_lossy(&other);
            let pick = rng.next();
            let reply = Reply {
                ok: pick & 1 == 0,
                code: [None, Some(s.to_string()), Some(t.to_string())][(pick as usize >> 1) % 3].clone(),
                text: if pick & 8 == 0 { t.to_string() } else { s.to_string() },
                body: [None, Some(data.clone()), Some(other.clone())][(pick as usize >> 4) % 3].clone(),
            };
            let has_body = reply.ok && reply.body.is_some();
            let bytes = reply.to_bytes();
            let (back, used) = Reply::parse(&bytes, has_body).unwrap().unwrap();
            assert_eq!(used, bytes.len());
            // What the writer wrote, read and written again, is the same.
            assert_eq!(back.to_bytes(), bytes);
            if let Ok(strict) = reply.try_to_bytes() {
                assert_eq!(strict, bytes);
                assert_eq!(
                    (back.ok, &back.code, &back.text),
                    (reply.ok, &reply.code, &reply.text)
                );
            }
            // Any keyword and argument, as a request of its own.
            let req = Request::Other(Command {
                keyword: t.to_string(),
                argument: Some(s.to_string()),
            });
            let line = req.to_bytes();
            let c = Command::parse(line.strip_suffix(b"\r\n").unwrap()).unwrap();
            let bare = Command {
                keyword: c.keyword.clone(),
                argument: None,
            };
            match Request::from_command(&bare) {
                Ok(Request::Other(_)) => {
                    assert!(matches!(Request::from_command(&c), Ok(Request::Other(_))))
                }
                Ok(Request::Noop) if c.argument.is_none() => {}
                // A keyword this module knows, put in Other by hand.
                _ => assert_eq!(c.keyword, t.chars().filter(char::is_ascii_graphic).collect::<String>().to_ascii_uppercase()),
            }
            if let Some(bytes) = req.try_to_bytes() {
                assert_eq!(commands(&bytes).len(), 1);
            }
            let c = Command {
                keyword: s.to_string(),
                argument: Some(s.to_string()),
            };
            let [Ok(back)] = &commands(&c.to_bytes())[..] else {
                panic!("{c:?}")
            };
            // The keyword is written as given, less what it may not hold,
            // or as NOOP; never as some other command.
            let want: String = s
                .chars()
                .filter(char::is_ascii_graphic)
                .map(|c| c.to_ascii_uppercase())
                .collect();
            assert!(back.keyword == want || back.keyword == "NOOP", "{c:?}");
            assert!(
                Request::from_command(
                    &Command::parse(
                        Request::User(s.to_string())
                            .to_bytes()
                            .strip_suffix(b"\r\n")
                            .unwrap()
                    )
                    .unwrap()
                )
                .is_ok()
            );
        }
    }
}
