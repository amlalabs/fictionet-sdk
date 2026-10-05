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
//! likes. A command line longer than [`MAX_COMMAND_LINE`] is an error, and
//! the decoder skips it and goes on to the next line. A reply decoder
//! stops at its first error, since a client that has lost its place in a
//! reply cannot find it again. Bodies are held to [`MAX_BODY`] bytes and
//! their lines to [`MAX_DATA_LINE`].
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
/// The longest response code, the text between the brackets.
pub const MAX_CODE: usize = 128;
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
    /// The line was longer than [`MAX_COMMAND_LINE`].
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
    /// four characters long is written as `NOOP`. A longer keyword is never
    /// cut, since `RETRY` cut to `RETR` would be another command. Control
    /// characters are dropped from the argument, and it is cut to fit in
    /// [`MAX_COMMAND_LINE`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut keyword: String = self
            .keyword
            .chars()
            .filter(char::is_ascii_graphic)
            .take(MAX_KEYWORD + 1)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if !(MIN_KEYWORD..=MAX_KEYWORD).contains(&keyword.len()) {
            keyword = "NOOP".to_string();
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
    /// Any other keyword, such as `AUTH`, left as it came.
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
        let args = || -> Result<Vec<&str>, ArgumentError> {
            let Some(a) = arg else { return Ok(Vec::new()) };
            let args: Vec<&str> = a.split(' ').collect();
            if args.iter().any(|a| a.is_empty()) {
                return Err(ArgumentError::Spacing);
            }
            Ok(args)
        };
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
    /// and passwords are cut so the line fits in [`MAX_COMMAND_LINE`]. An empty name or password is written as
    /// `_`, so the line still reads back as the same kind of request.
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

/// Why bytes are not a reply. The client has lost its place in the
/// stream, and a real one closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// A status line was longer than [`MAX_REPLY_LINE`], or a body line
    /// longer than [`MAX_DATA_LINE`].
    LineTooLong,
    /// The status line did not start with `+OK` or `-ERR` followed by a
    /// space or the end of the line.
    BadStatus,
    /// The body was longer than [`MAX_BODY`].
    BodyTooLong,
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReplyError::LineTooLong => "reply line too long",
            ReplyError::BadStatus => "status is not +OK or -ERR",
            ReplyError::BodyTooLong => "reply body too long",
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
    /// section 3, and is no longer than [`MAX_CODE`]. The text may follow
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
        let mut d = ReplyDecoder::new();
        d.feed(b);
        match d.next_reply(multi_line) {
            None => Ok(None),
            Some(Ok(r)) => Ok(Some((r, d.lines.consumed))),
            Some(Err(e)) => Err(e),
        }
    }

    /// The reply as bytes. A body is written only for a `+OK` reply, with a
    /// dot added in front of lines that start with one, and the closing
    /// line. LFs are dropped from the text, and the status line is cut to
    /// fit in [`MAX_REPLY_LINE`]. A reply with no code whose text would be
    /// read as one, such as `[AUTH] x`, gets a space in front of its text. Characters a response code may not hold
    /// are dropped from it, and levels that do not fit in [`MAX_CODE`]
    /// with it. Body lines longer than [`MAX_DATA_LINE`] are split, and
    /// lines that do not fit in [`MAX_BODY`] are left out.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut line = String::from(if self.ok { "+OK" } else { "-ERR" });
        // Each character is a byte or more, so this is enough to fill a line.
        let text: String = self
            .text
            .chars()
            .filter(|&c| c != '\n')
            .take(MAX_REPLY_LINE)
            .collect();
        let code = self.code.as_deref().and_then(clean_code);
        let has_code = code.is_some();
        match code {
            Some(code) => {
                line.push_str(" [");
                line.push_str(&code);
                line.push(']');
                if !text.is_empty() {
                    line.push(' ');
                    line.push_str(&text);
                }
            }
            None if !text.is_empty() => {
                line.push(' ');
                line.push_str(&text);
            }
            None => {}
        }
        let mut line = cut(&line, MAX_REPLY_LINE - 2).to_string();
        let status = if self.ok { 3 } else { 4 };
        // Text that would be read as a code gets a space in front of it.
        if !has_code
            && line
                .as_bytes()
                .get(status + 1..)
                .and_then(split_code)
                .is_some()
        {
            line.insert(status, ' ');
            line = cut(&line, MAX_REPLY_LINE - 2).to_string();
        }
        let mut out = line.into_bytes();
        out.extend_from_slice(b"\r\n");
        if let (true, Some(body)) = (self.ok, &self.body) {
            let mut size = 0usize;
            'lines: for content in body_lines(body) {
                let mut rest = content;
                loop {
                    let room = if rest.first() == Some(&b'.') {
                        MAX_DATA_LINE - 3
                    } else {
                        MAX_DATA_LINE - 2
                    };
                    let (piece, tail) = rest.split_at(rest.len().min(room));
                    let Some(next) = size.checked_add(piece.len() + 2).filter(|&n| n <= MAX_BODY)
                    else {
                        break 'lines;
                    };
                    size = next;
                    if piece.first() == Some(&b'.') {
                        out.push(b'.');
                    }
                    out.extend_from_slice(piece);
                    out.extend_from_slice(b"\r\n");
                    if tail.is_empty() {
                        break;
                    }
                    rest = tail;
                }
            }
            out.extend_from_slice(b".\r\n");
        }
        out
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

    /// The body's lines, without their line ends. A reply with no body
    /// has none.
    pub fn lines(&self) -> Vec<&[u8]> {
        self.body
            .as_deref()
            .map(|b| body_lines(b).collect())
            .unwrap_or_default()
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

    /// The count and size an answer to `STAT` gives.
    pub fn drop_listing(&self) -> Option<(u32, u64)> {
        let mut parts = self.text.splitn(3, ' ');
        let count = u32::try_from(decimal(parts.next()?)?).ok()?;
        Some((count, decimal(parts.next()?)?))
    }
}

/// Reads a scan listing, `msg octets`: one line of the answer to `LIST`,
/// or the text of the answer to `LIST msg`. Text after the size is
/// allowed and ignored.
pub fn parse_scan_listing(line: &[u8]) -> Option<(NonZeroU32, u64)> {
    let s = std::str::from_utf8(line).ok()?;
    let mut parts = s.splitn(3, ' ');
    let msg = message(parts.next()?).ok()?;
    Some((msg, decimal(parts.next()?)?))
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

/// Writes a unique-id listing, `msg uid`, without a line end. Characters a
/// unique-id may not hold are dropped, it is cut to [`MAX_UID`], and an
/// empty one is written as `_`.
pub fn write_unique_id_listing(msg: NonZeroU32, uid: &str) -> String {
    let mut uid: String = uid
        .chars()
        .filter(char::is_ascii_graphic)
        .take(MAX_UID)
        .collect();
    if uid.is_empty() {
        uid.push('_');
    }
    format!("{msg} {uid}")
}

/// Splits a byte stream into lines, and skips lines that are too long.
#[derive(Clone, Debug, Default)]
struct Lines {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped when they make up half of `buf`, so taking many short lines
    /// out of one large feed takes linear time.
    start: usize,
    /// How many bytes after `start` are known to hold no LF.
    scanned: usize,
    /// Whether the bytes up to the next LF belong to a line too long to
    /// keep.
    skipping: bool,
    /// How many bytes have been taken out or skipped, in all.
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
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    fn held(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or(&[])
    }

    fn clear(&mut self) {
        self.consumed = self.consumed.saturating_add(self.held().len());
        self.buf = Vec::new();
        self.start = 0;
        self.scanned = 0;
    }

    fn take(&mut self, n: usize) {
        let n = n.min(self.held().len());
        self.start += n;
        self.consumed = self.consumed.saturating_add(n);
        self.scanned = 0;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
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
    /// since.
    pub fn next_command(&mut self) -> Option<Result<Command, CommandError>> {
        Some(match self.lines.next_line(MAX_COMMAND_LINE)? {
            Ok(line) => Command::parse(&line),
            Err(()) => Err(CommandError::LineTooLong),
        })
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

/// Exactly `N` arguments.
fn exact<const N: usize>(args: Vec<&str>) -> Result<[&str; N], ArgumentError> {
    match args.len().cmp(&N) {
        std::cmp::Ordering::Less => Err(ArgumentError::Missing),
        std::cmp::Ordering::Greater => Err(ArgumentError::Extra),
        std::cmp::Ordering::Equal => args.try_into().map_err(|_| ArgumentError::Missing),
    }
}

/// No arguments or one.
fn optional(args: Vec<&str>) -> Result<Option<&str>, ArgumentError> {
    match args.as_slice() {
        [] => Ok(None),
        [a] => Ok(Some(a)),
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
/// `None` if the text does not start with a code no longer than
/// [`MAX_CODE`].
fn split_code(rest: &[u8]) -> Option<(&[u8], &[u8])> {
    let after = rest.strip_prefix(b"[")?;
    let end = after.iter().position(|&c| c == b']')?;
    let (inner, tail) = (after.get(..end)?, after.get(end + 1..)?);
    if inner.len() > MAX_CODE
        || !inner
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

/// A response code with what it may not hold dropped, cut to
/// [`MAX_CODE`], or `None` if nothing is left.
fn clean_code(code: &str) -> Option<String> {
    let mut out = String::new();
    for level in code.split('/') {
        let level: String = level
            .chars()
            .filter(|&c| u8::try_from(c).is_ok_and(rchar))
            .collect();
        if level.is_empty() {
            continue;
        }
        if out.is_empty() {
            out = level;
            out.truncate(MAX_CODE);
        } else if out.len() + 1 + level.len() <= MAX_CODE {
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
        let chunks: Vec<&[u8]> = if bytewise {
            stream.chunks(1).collect()
        } else {
            vec![stream]
        };
        for chunk in chunks {
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
            .into_iter()
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
            .into_iter()
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
            write_unique_id_listing(n(2), "QhdPYR:00WBw1Ph7x7"),
            "2 QhdPYR:00WBw1Ph7x7"
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
        assert_eq!(capa.lines().len(), 9);
        assert_eq!(capa.lines()[2], b"SASL CRAM-MD5 KERBEROS_V4");
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
        // Bad keywords are written as NOOP.
        let c = Command {
            keyword: "R\r\n".into(),
            argument: Some("x\ny".into()),
        };
        assert_eq!(c.to_bytes(), b"NOOP xy\r\n");
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
        // Codes lose what they may not hold.
        let r = Reply::err("t").with_code("SYS/ /T]EMP/");
        assert_eq!(r.to_bytes(), b"-ERR [SYS/TEMP] t\r\n");
        let r = Reply::err("t").with_code("] /");
        assert_eq!(r.to_bytes(), b"-ERR t\r\n");
        let r = Reply::err("t").with_code(&"A".repeat(500));
        assert_eq!(
            Reply::parse(&r.to_bytes(), false)
                .unwrap()
                .unwrap()
                .0
                .code
                .unwrap()
                .len(),
            MAX_CODE
        );
        let r = Reply::err("t").with_code(&format!("{}/{}", "A".repeat(100), "B".repeat(100)));
        assert_eq!(
            Reply::parse(&r.to_bytes(), false)
                .unwrap()
                .unwrap()
                .0
                .code
                .unwrap(),
            "A".repeat(100)
        );
        // Long body lines are split, and a body too big is cut.
        let mut body = vec![b'.'; MAX_DATA_LINE * 2];
        body.extend_from_slice(b"\r\nend\r\n");
        let r = Reply::ok("").with_body(body);
        let back = Reply::parse(&r.to_bytes(), true).unwrap().unwrap().0;
        let lines = back.lines();
        assert_eq!(lines.len(), 4);
        assert_eq!(
            lines.iter().map(|l| l.len()).sum::<usize>(),
            MAX_DATA_LINE * 2 + 3
        );
        let r = Reply::ok("").with_body(vec![b'z'; MAX_BODY + 10]);
        let back = Reply::parse(&r.to_bytes(), true).unwrap().unwrap().0;
        assert!(back.body.unwrap().len() <= MAX_BODY);
        // A unique-id loses what it may not hold.
        assert_eq!(write_unique_id_listing(n(1), " "), "1 _");
        let w = write_unique_id_listing(n(1), &"u v".repeat(50));
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
        let long_code = [b"-ERR [".as_slice(), &[b'A'; MAX_CODE + 1], b"]"].concat();
        assert_eq!(Reply::parse_line(&long_code).unwrap().code, None);
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
        assert_eq!(c.to_bytes(), b"NOOP 1\r\n");
        let r = Request::Other(Command {
            keyword: "DELETE".into(),
            argument: Some("1".into()),
        });
        assert_eq!(r.to_bytes(), b"NOOP 1\r\n");
        // Dropped characters still count only once they are gone.
        let c = Command {
            keyword: "R E\tT R".into(),
            argument: None,
        };
        assert_eq!(c.to_bytes(), b"RETR\r\n");
    }

    #[test]
    fn writers_stop_reading_input_past_their_limits() {
        // A body of many empty lines, far past MAX_BODY, is written as
        // MAX_BODY bytes and in about the time that takes.
        let started = std::time::Instant::now();
        let r = Reply::ok("").with_body(vec![b'\n'; MAX_BODY * 8]);
        let bytes = r.to_bytes();
        let back = Reply::parse(&bytes, true).unwrap().unwrap().0;
        assert_eq!(back.body.unwrap().len(), MAX_BODY);
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
        assert_eq!(r.lines().len(), 200_000);
        assert!(
            started.elapsed().as_secs() < 5,
            "took {:?}",
            started.elapsed()
        );
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
                chunked.extend(std::iter::from_fn(|| d.next_command()));
                rest = tail;
            }
            assert_eq!(chunked, whole);
            for c in whole.iter().flatten() {
                assert_eq!(commands(&c.to_bytes()), [Ok(c.clone())]);
                if let Ok(r) = Request::from_command(c) {
                    let again = commands(&r.to_bytes());
                    assert_eq!(again.len(), 1);
                    let back = Request::from_command(again[0].as_ref().unwrap()).unwrap();
                    if !matches!(r, Request::Other(_)) {
                        assert_eq!(back, r);
                    }
                }
            }
            let got = replies(&data, false);
            assert_eq!(got, replies(&data, true));
            for r in got.iter().flatten() {
                let bytes = r.to_bytes();
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
                        let w = write_unique_id_listing(m, &u);
                        assert_eq!(parse_unique_id_listing(w.as_bytes()), Some((m, u)));
                    }
                }
            }
            // Any bytes as one line, and as one reply.
            let _ = Command::parse(&data);
            let _ = Reply::parse_line(&data);
            let _ = Reply::parse(&data, true);
            let _ = Reply::parse(&data, false);
            // Writers never write what readers refuse.
            let s = String::from_utf8_lossy(&data);
            let reply = Reply {
                ok: true,
                code: Some(s.to_string()),
                text: s.to_string(),
                body: Some(data.clone()),
            };
            assert!(Reply::parse(&reply.to_bytes(), true).unwrap().is_some());
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
