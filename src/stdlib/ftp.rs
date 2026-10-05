//! FTP: reading and writing the control connection's commands and replies,
//! with no I/O.
//!
//! New stacks use [`Commands`] and [`Replies`] with [`codec::Stream`].
//! Both accept CRLF and bare LF. [`codec::Wire`] provides exact parsing
//! and strict, transactional writing for [`Command`] and [`Reply`].
//! The legacy decoders and writers retain their original behavior.
//!
//! FTP moves files between a client and a server. The client sends
//! commands over a TCP connection, usually to port 21, one per line, such
//! as `USER anonymous` or `RETR notes.txt`. The server answers each with a
//! reply: a three-digit code and some text, on one line or several. The
//! files themselves travel over a second connection, the data connection,
//! whose address the two sides agree with `PORT`, `PASV`, `EPRT` or
//! `EPSV`. This module follows RFC 959 (FTP), RFC 2428 (the extended
//! address commands, for IPv6), RFC 2389 (`FEAT` and `OPTS`) and RFC 3659
//! (`SIZE`, `MDTM`, `REST`, `MLST` and `MLSD`).
//!
//! Nothing here reads a socket. A world that plays an FTP server feeds the
//! bytes it reads from a TCP connection to a [`CommandDecoder`], gets
//! [`Command`]s back, reads each one's [`Request`], and writes a [`Reply`]'s
//! bytes back to the connection. A world that plays a client does the
//! reverse with [`ReplyDecoder`]. Which files exist, who may log in, and
//! what each command does are up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A line longer than [`MAX_LINE`] is an error, and a server's
//! decoder skips it and goes on to the next line, as real servers do. The
//! error says which reply a server sends: a bad line ([`CommandError`]) is
//! answered with [`code::SYNTAX_ERROR`] (500), and a bad argument
//! ([`ArgumentError`]) with [`code::ARGUMENT_ERROR`] (501). A decoder holds
//! at most [`MAX_BUFFERED`] bytes that have not been taken out, and its
//! `feed` says how many bytes it took.
//!
//! A command writer refuses ([`WriteError`]) rather than send a line that
//! would read back as a different command. A pathname may hold a carriage
//! return: RFC 2640 sends it as CR NUL, and a reader turns CR NUL back into
//! CR. A command reader also drops Telnet commands, such as the interrupt
//! and synch that clients send before `ABOR`.
//!
//! ```
//! use fictionet::stdlib::ftp::{code, CommandDecoder, Reply, ReplyDecoder, Request};
//! use std::net::{Ipv4Addr, SocketAddrV4};
//!
//! // A server answers three commands.
//! let mut commands = CommandDecoder::new();
//! let stream = b"USER anonymous\r\nPASV\r\nEPRT |1|10.0.0.5|6275|\r\n";
//! assert_eq!(commands.feed(stream), stream.len());
//! let mut out = Vec::new();
//! while let Some(line) = commands.next_command() {
//!     let reply = match line.map(|c| Request::from_command(&c)) {
//!         Ok(Ok(Request::User(name))) => Reply::new(code::NEED_PASSWORD, &format!("Password for {name}, please.")),
//!         Ok(Ok(Request::Pasv)) => Reply::passive(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 50000)),
//!         Ok(Ok(Request::Eprt(to))) if to.port() == 6275 => Reply::new(code::OK, "EPRT command successful."),
//!         Ok(Ok(_)) => Reply::new(code::NOT_IMPLEMENTED, "Not implemented."),
//!         Ok(Err(_)) => Reply::new(code::ARGUMENT_ERROR, "Syntax error in parameters."),
//!         Err(_) => Reply::new(code::SYNTAX_ERROR, "Syntax error."),
//!     };
//!     out.extend(reply.to_bytes());
//! }
//! assert_eq!(
//!     out,
//!     b"331 Password for anonymous, please.\r\n\
//!       227 Entering Passive Mode (10,0,0,1,195,80).\r\n\
//!       200 EPRT command successful.\r\n"
//! );
//!
//! // A client reads a multi-line reply to FEAT.
//! let mut replies = ReplyDecoder::new();
//! let stream = b"211-Extensions supported:\r\n EPSV\r\n MLST size*;modify*;\r\n211 End\r\n";
//! assert_eq!(replies.feed(stream), stream.len());
//! let reply = replies.next_reply().unwrap().unwrap();
//! let features = reply.features().unwrap();
//! assert_eq!(features.len(), 2);
//! assert_eq!(features[1].name, "MLST");
//! assert_eq!(features[1].params.as_deref(), Some("size*;modify*;"));
//! ```

use super::codec::{self, Decode, Step, Wire};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU8;

pub use code::ReplyCode;

/// The TCP port FTP servers listen on for control connections.
pub const PORT: u16 = 21;
/// The longest line, counting its CRLF, that a reader takes and a writer
/// writes. RFC 959 sets no limit. Common servers stop at about this many
/// bytes.
pub const MAX_LINE: usize = 4096;
/// The longest command verb. RFC 959 says verbs have four or fewer letters.
pub const MAX_VERB: usize = 4;
/// The most lines one reply may hold, first and last included.
pub const MAX_REPLY_LINES: usize = 1024;
/// The most features one `FEAT` reply may list: every line but the first
/// and the last.
pub const MAX_FEATURES: usize = MAX_REPLY_LINES - 2;
/// The most bytes a decoder holds that have not been taken out. A `feed`
/// that would hold more takes only part of its bytes, and says how many.
pub const MAX_BUFFERED: usize = 16 * MAX_LINE;

/// The longest line's content, without its CRLF.
const MAX_CONTENT: usize = MAX_LINE - 2;
/// The longest text on a reply's first or last line, after the code and
/// its separator.
const MAX_REPLY_TEXT: usize = MAX_CONTENT - 4;

/// A command line as it was sent: a verb and the argument after it. It
/// says nothing about what the verb means. [`Request::from_command`] reads
/// that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// The verb, such as `RETR`, in upper case. Verbs are case-insensitive,
    /// and a reader turns them to upper case.
    pub verb: String,
    /// Everything after the space that follows the verb, or `None` if no
    /// space follows it. `RETR` has no argument, and `RETR ` has an empty
    /// one. It holds a CR where the line held CR NUL, and a LF only right
    /// after such a CR (RFC 2640, section 3.1).
    pub arg: Option<String>,
}

/// Why a line is not a command. A server answers each of these with
/// [`code::SYNTAX_ERROR`] and reads the next line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    /// The line was longer than [`MAX_LINE`]. The decoder dropped all of it.
    LineTooLong,
    /// The line was empty.
    Empty,
    /// The line did not start with one to four letters followed by a space
    /// or the end of the line.
    Verb,
    /// The line was not UTF-8 once Telnet commands were dropped, held a NUL
    /// or a carriage return other than as CR NUL, or ended inside a Telnet
    /// command.
    Text,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CommandError::LineTooLong => "command line too long",
            CommandError::Empty => "empty command line",
            CommandError::Verb => "command verb is not one to four letters",
            CommandError::Text => "command line is not UTF-8 text without a bare CR or NUL",
        })
    }
}

impl std::error::Error for CommandError {}

impl Command {
    /// A command with `verb` and `arg`.
    pub fn new(verb: &str, arg: Option<&str>) -> Command {
        Command { verb: verb.to_string(), arg: arg.map(str::to_string) }
    }

    /// Reads one command line, without its line ending. Telnet commands in
    /// it, such as `IAC IP` and `IAC DM`, are dropped, and CR NUL is read
    /// as CR.
    pub fn parse(line: &[u8]) -> Result<Command, CommandError> {
        if line.len() > MAX_CONTENT {
            return Err(CommandError::LineTooLong);
        }
        let line = command_text(line).ok_or(CommandError::Text)?;
        let line = line.as_str();
        if line.is_empty() {
            return Err(CommandError::Empty);
        }
        let (verb, arg) = match line.split_once(' ') {
            Some((verb, arg)) => (verb, Some(arg)),
            None => (line, None),
        };
        if verb.is_empty() || verb.len() > MAX_VERB || !verb.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(CommandError::Verb);
        }
        Ok(Command { verb: verb.to_ascii_uppercase(), arg: arg.map(str::to_string) })
    }

    /// The command line's bytes, ending in CRLF, with the verb in upper
    /// case and each CR in the argument sent as CR NUL. It fails if the
    /// verb is not one to four ASCII letters, if the argument holds a NUL
    /// or a LF that does not follow a CR, or if the line would not fit in
    /// [`MAX_LINE`]. What it writes reads back as the same command.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WriteError> {
        write_command(&self.verb, self.arg.as_deref())
    }
}

/// Why a command could not be written. A writer refuses rather than send
/// a line that reads back as something else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The verb was not one to four ASCII letters.
    Verb,
    /// The argument held a NUL, or a LF that does not follow a CR. A line
    /// can carry neither.
    Text,
    /// The line would be longer than [`MAX_LINE`].
    LineTooLong,
    /// The request's argument does not fit its verb, so a server would not
    /// read it back as this request.
    Argument(ArgumentError),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::Verb => f.write_str("command verb is not one to four letters"),
            WriteError::Text => f.write_str("argument holds a NUL or a LF not after a CR"),
            WriteError::LineTooLong => f.write_str("command line too long"),
            WriteError::Argument(e) => write!(f, "argument does not fit the verb: {e}"),
        }
    }
}

impl std::error::Error for WriteError {}

/// Writes `verb` and `arg` as a command line, checking them first so
/// that nothing large is copied before the checks pass.
fn write_command(verb: &str, arg: Option<&str>) -> Result<Vec<u8>, WriteError> {
    if verb.is_empty() || verb.len() > MAX_VERB || !verb.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(WriteError::Verb);
    }
    let mut len = verb.len() + 2;
    if let Some(arg) = arg {
        let b = arg.as_bytes();
        if b.len() > MAX_LINE {
            return Err(WriteError::LineTooLong);
        }
        for (i, &c) in b.iter().enumerate() {
            match c {
                0 => return Err(WriteError::Text),
                b'\n' if i == 0 || b[i - 1] != b'\r' => return Err(WriteError::Text),
                b'\r' => len += 1,
                _ => {}
            }
        }
        len += 1 + b.len();
    }
    if len > MAX_LINE {
        return Err(WriteError::LineTooLong);
    }
    let mut out = Vec::with_capacity(len);
    out.extend(verb.bytes().map(|b| b.to_ascii_uppercase()));
    if let Some(arg) = arg {
        out.push(b' ');
        for &c in arg.as_bytes() {
            out.push(c);
            if c == b'\r' {
                out.push(0);
            }
        }
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// The representation type that `TYPE` sets (RFC 959, section 3.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataType {
    /// `A`: ASCII text, with an optional format.
    Ascii(Option<Format>),
    /// `E`: EBCDIC text, with an optional format.
    Ebcdic(Option<Format>),
    /// `I`: bytes as they are. This is what clients use for most files.
    Image,
    /// `L`: bytes of the given size in bits, from 1 to 255.
    Local(NonZeroU8),
}

/// The format of an ASCII or EBCDIC transfer (RFC 959, section 3.1.1.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `N`: no vertical format information. The default.
    NonPrint,
    /// `T`: Telnet format controls.
    Telnet,
    /// `C`: ASA carriage control characters.
    CarriageControl,
}

/// The file structure that `STRU` sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Structure {
    /// `F`: a file is a run of bytes. The default.
    File,
    /// `R`: a file is a run of records.
    Record,
    /// `P`: a file is a set of indexed pages.
    Page,
}

/// The transfer mode that `MODE` sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferMode {
    /// `S`: the data as a stream of bytes. The default.
    Stream,
    /// `B`: the data in blocks, each with a header.
    Block,
    /// `C`: the data compressed.
    Compressed,
}

/// The argument of `EPSV` (RFC 2428, section 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpsvArg {
    /// A network protocol number: 1 for IPv4, 2 for IPv6.
    Protocol(u16),
    /// `ALL`: the client will use only `EPSV` from now on.
    All,
}

/// A command read for what it means. Each variant's doc gives its verb.
/// Verbs this module does not know stay as [`Request::Other`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// `USER`: the user name to log in as.
    User(String),
    /// `PASS`: the password for the user.
    Pass(String),
    /// `ACCT`: the account to use.
    Acct(String),
    /// `CWD`, or `XCWD`: change to this directory.
    Cwd(String),
    /// `CDUP`, or `XCUP`: change to the parent directory.
    Cdup,
    /// `SMNT`: mount this file system.
    Smnt(String),
    /// `REIN`: log out, keeping the connection.
    Rein,
    /// `QUIT`: log out and close the connection.
    Quit,
    /// `PORT`: connect to this address for the next transfer.
    Port(SocketAddrV4),
    /// `PASV`: listen for the next transfer, and say where.
    Pasv,
    /// `TYPE`: the representation type.
    Type(DataType),
    /// `STRU`: the file structure.
    Stru(Structure),
    /// `MODE`: the transfer mode.
    Mode(TransferMode),
    /// `RETR`: send this file.
    Retr(String),
    /// `STOR`: store a file under this name.
    Stor(String),
    /// `STOU`: store a file under a name the server picks.
    Stou,
    /// `APPE`: append to this file.
    Appe(String),
    /// `ALLO`: set aside this much space, as written: a decimal number,
    /// then optionally ` R ` and a record or page size (RFC 959, section
    /// 5.3.2).
    Allo(String),
    /// `REST`: start the next transfer at this marker, of printable ASCII
    /// characters other than space. In stream mode it is a byte offset
    /// (RFC 3659, section 5).
    Rest(String),
    /// `RNFR`: rename this file. `RNTO` follows.
    Rnfr(String),
    /// `RNTO`: rename the file named by `RNFR` to this.
    Rnto(String),
    /// `ABOR`: stop the transfer in progress.
    Abor,
    /// `DELE`: delete this file.
    Dele(String),
    /// `RMD`, or `XRMD`: remove this directory.
    Rmd(String),
    /// `MKD`, or `XMKD`: make this directory.
    Mkd(String),
    /// `PWD`, or `XPWD`: say which directory is current.
    Pwd,
    /// `LIST`: list this path, or the current directory, over the data
    /// connection.
    List(Option<String>),
    /// `NLST`: list the names in this path, or the current directory.
    Nlst(Option<String>),
    /// `SITE`: a server-specific command.
    Site(String),
    /// `SYST`: say what operating system the server runs.
    Syst,
    /// `STAT`: report status, or list this path over the control
    /// connection.
    Stat(Option<String>),
    /// `HELP`: help on this topic, or in general.
    Help(Option<String>),
    /// `NOOP`: do nothing and say OK.
    Noop,
    /// `EPRT`: connect to this address, IPv4 or IPv6, for the next transfer.
    Eprt(SocketAddr),
    /// `EPSV`: listen for the next transfer and say on which port.
    Epsv(Option<EpsvArg>),
    /// `FEAT`: list the extensions the server supports.
    Feat,
    /// `OPTS`: set options for a command, as written. It starts with the
    /// command's name, of printable ASCII characters (RFC 2389, section 4).
    Opts(String),
    /// `MDTM`: say when this file was last changed.
    Mdtm(String),
    /// `SIZE`: say how large this file is.
    Size(String),
    /// `MLST`: describe this path, or the current directory, in facts.
    Mlst(Option<String>),
    /// `MLSD`: list this directory, or the current one, in facts.
    Mlsd(Option<String>),
    /// A verb this module does not know, as it was sent. One built by hand
    /// with a known verb is read back as that verb.
    Other(Command),
}

/// Why a command's argument does not fit its verb. A server answers each
/// of these with [`code::ARGUMENT_ERROR`], except an [`AddressError::Family`]
/// in `EPRT`, which RFC 2428 answers with
/// [`code::UNKNOWN_NETWORK_PROTOCOL`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgumentError {
    /// The verb needs an argument and the command had none.
    Missing,
    /// The verb takes no argument and the command had one.
    Unexpected,
    /// The argument was not one the verb accepts.
    Invalid,
    /// The address in `PORT` or `EPRT` could not be read.
    Address(AddressError),
}

impl std::fmt::Display for ArgumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgumentError::Missing => f.write_str("missing argument"),
            ArgumentError::Unexpected => f.write_str("unexpected argument"),
            ArgumentError::Invalid => f.write_str("invalid argument"),
            ArgumentError::Address(e) => write!(f, "bad address: {e}"),
        }
    }
}

impl std::error::Error for ArgumentError {}

impl Request {
    /// Reads what `command` asks for. Verbs are known in upper case, as
    /// [`Command::parse`] leaves them.
    pub fn from_command(command: &Command) -> Result<Request, ArgumentError> {
        use ArgumentError as E;
        let arg = command.arg.as_deref();
        let need = || arg.map(str::to_string).ok_or(E::Missing);
        let none = |r: Request| if arg.is_some() { Err(E::Unexpected) } else { Ok(r) };
        let maybe = || arg.map(str::to_string);
        let upper = || arg.map(str::to_ascii_uppercase).ok_or(E::Missing);
        Ok(match command.verb.as_str() {
            "USER" => Request::User(need()?),
            "PASS" => Request::Pass(need()?),
            "ACCT" => Request::Acct(need()?),
            "CWD" | "XCWD" => Request::Cwd(need()?),
            "CDUP" | "XCUP" => none(Request::Cdup)?,
            "SMNT" => Request::Smnt(need()?),
            "REIN" => none(Request::Rein)?,
            "QUIT" => none(Request::Quit)?,
            "PORT" => Request::Port(parse_port(arg.ok_or(E::Missing)?).map_err(E::Address)?),
            "PASV" => none(Request::Pasv)?,
            "TYPE" => Request::Type(parse_type(&upper()?).ok_or(E::Invalid)?),
            "STRU" => Request::Stru(match upper()?.as_str() {
                "F" => Structure::File,
                "R" => Structure::Record,
                "P" => Structure::Page,
                _ => return Err(E::Invalid),
            }),
            "MODE" => Request::Mode(match upper()?.as_str() {
                "S" => TransferMode::Stream,
                "B" => TransferMode::Block,
                "C" => TransferMode::Compressed,
                _ => return Err(E::Invalid),
            }),
            "RETR" => Request::Retr(need()?),
            "STOR" => Request::Stor(need()?),
            "STOU" => none(Request::Stou)?,
            "APPE" => Request::Appe(need()?),
            "ALLO" => Request::Allo(need().and_then(|a| if allo_ok(&a) { Ok(a) } else { Err(E::Invalid) })?),
            "REST" => Request::Rest(need().and_then(|a| if rest_ok(&a) { Ok(a) } else { Err(E::Invalid) })?),
            "RNFR" => Request::Rnfr(need()?),
            "RNTO" => Request::Rnto(need()?),
            "ABOR" => none(Request::Abor)?,
            "DELE" => Request::Dele(need()?),
            "RMD" | "XRMD" => Request::Rmd(need()?),
            "MKD" | "XMKD" => Request::Mkd(need()?),
            "PWD" | "XPWD" => none(Request::Pwd)?,
            "LIST" => Request::List(maybe()),
            "NLST" => Request::Nlst(maybe()),
            "SITE" => Request::Site(need()?),
            "SYST" => none(Request::Syst)?,
            "STAT" => Request::Stat(maybe()),
            "HELP" => Request::Help(maybe()),
            "NOOP" => none(Request::Noop)?,
            "EPRT" => Request::Eprt(parse_eprt(arg.ok_or(E::Missing)?).map_err(E::Address)?),
            "EPSV" => Request::Epsv(match arg {
                None => None,
                Some(a) if a.eq_ignore_ascii_case("ALL") => Some(EpsvArg::All),
                Some(a) => {
                    Some(EpsvArg::Protocol(decimal(a, 5).and_then(|n| u16::try_from(n).ok()).ok_or(E::Invalid)?))
                }
            }),
            "FEAT" => none(Request::Feat)?,
            "OPTS" => Request::Opts(need().and_then(|a| if opts_ok(&a) { Ok(a) } else { Err(E::Invalid) })?),
            "MDTM" => Request::Mdtm(need()?),
            "SIZE" => Request::Size(need()?),
            "MLST" => Request::Mlst(maybe()),
            "MLSD" => Request::Mlsd(maybe()),
            _ => Request::Other(command.clone()),
        })
    }

    /// The command that sends this request, for a world that plays a
    /// client. Aliases such as `XPWD` are written as their RFC 959 verbs.
    pub fn to_command(&self) -> Command {
        let (verb, arg) = self.parts();
        Command { verb: verb.to_string(), arg: arg.map(Cow::into_owned) }
    }

    /// The verb and argument of [`to_command`](Self::to_command), without
    /// copying the argument.
    fn parts(&self) -> (&str, Option<Cow<'_, str>>) {
        fn b(a: &str) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(a))
        }
        fn opt(a: &Option<String>) -> Option<Cow<'_, str>> {
            a.as_deref().map(Cow::Borrowed)
        }
        let fixed = |a: &'static str| Some(Cow::Borrowed(a));
        match self {
            Request::User(a) => ("USER", b(a)),
            Request::Pass(a) => ("PASS", b(a)),
            Request::Acct(a) => ("ACCT", b(a)),
            Request::Cwd(a) => ("CWD", b(a)),
            Request::Cdup => ("CDUP", None),
            Request::Smnt(a) => ("SMNT", b(a)),
            Request::Rein => ("REIN", None),
            Request::Quit => ("QUIT", None),
            Request::Port(addr) => ("PORT", Some(Cow::Owned(write_port(*addr)))),
            Request::Pasv => ("PASV", None),
            Request::Type(t) => ("TYPE", Some(Cow::Owned(write_type(*t)))),
            Request::Stru(s) => (
                "STRU",
                fixed(match s {
                    Structure::File => "F",
                    Structure::Record => "R",
                    Structure::Page => "P",
                }),
            ),
            Request::Mode(m) => (
                "MODE",
                fixed(match m {
                    TransferMode::Stream => "S",
                    TransferMode::Block => "B",
                    TransferMode::Compressed => "C",
                }),
            ),
            Request::Retr(a) => ("RETR", b(a)),
            Request::Stor(a) => ("STOR", b(a)),
            Request::Stou => ("STOU", None),
            Request::Appe(a) => ("APPE", b(a)),
            Request::Allo(a) => ("ALLO", b(a)),
            Request::Rest(a) => ("REST", b(a)),
            Request::Rnfr(a) => ("RNFR", b(a)),
            Request::Rnto(a) => ("RNTO", b(a)),
            Request::Abor => ("ABOR", None),
            Request::Dele(a) => ("DELE", b(a)),
            Request::Rmd(a) => ("RMD", b(a)),
            Request::Mkd(a) => ("MKD", b(a)),
            Request::Pwd => ("PWD", None),
            Request::List(a) => ("LIST", opt(a)),
            Request::Nlst(a) => ("NLST", opt(a)),
            Request::Site(a) => ("SITE", b(a)),
            Request::Syst => ("SYST", None),
            Request::Stat(a) => ("STAT", opt(a)),
            Request::Help(a) => ("HELP", opt(a)),
            Request::Noop => ("NOOP", None),
            Request::Eprt(addr) => ("EPRT", Some(Cow::Owned(write_eprt(*addr)))),
            Request::Epsv(a) => (
                "EPSV",
                a.map(|a| match a {
                    EpsvArg::Protocol(n) => Cow::Owned(n.to_string()),
                    EpsvArg::All => Cow::Borrowed("ALL"),
                }),
            ),
            Request::Feat => ("FEAT", None),
            Request::Opts(a) => ("OPTS", b(a)),
            Request::Mdtm(a) => ("MDTM", b(a)),
            Request::Size(a) => ("SIZE", b(a)),
            Request::Mlst(a) => ("MLST", opt(a)),
            Request::Mlsd(a) => ("MLSD", opt(a)),
            Request::Other(c) => (c.verb.as_str(), opt(&c.arg)),
        }
    }

    /// The request's command line, ending in CRLF. It fails as
    /// [`Command::to_bytes`] does, and with [`WriteError::Argument`] if
    /// [`Request::from_command`] would not read the line, such as `ALLO`
    /// with a size that is not a number.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WriteError> {
        let (verb, arg) = self.parts();
        let bytes = write_command(verb, arg.as_deref())?;
        let line = bytes.strip_suffix(b"\r\n").unwrap_or(&bytes);
        let command = Command::parse(line).map_err(|_| WriteError::Text)?;
        Request::from_command(&command).map_err(WriteError::Argument)?;
        Ok(bytes)
    }
}

/// Whether `a` is an `ALLO` argument: `<decimal-integer> [R <decimal-integer>]`,
/// the parts joined by single spaces.
fn allo_ok(a: &str) -> bool {
    let number = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    let mut parts = a.split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(n), None, None, None) => number(n),
        (Some(n), Some(r), Some(m), None) => number(n) && r.eq_ignore_ascii_case("R") && number(m),
        _ => false,
    }
}

/// Whether `a` is a `REST` marker: one or more printable ASCII characters
/// other than space (RFC 959, section 5.3.2).
fn rest_ok(a: &str) -> bool {
    !a.is_empty() && a.bytes().all(|c| c.is_ascii_graphic())
}

/// Whether `a` starts with a command name of printable ASCII characters,
/// followed by a space or nothing (RFC 2389, section 4).
fn opts_ok(a: &str) -> bool {
    let name = a.split(' ').next().unwrap_or("");
    !name.is_empty() && name.bytes().all(|c| c.is_ascii_graphic())
}

fn parse_type(a: &str) -> Option<DataType> {
    let mut parts = a.split(' ');
    let (kind, param) = (parts.next()?, parts.next());
    if parts.next().is_some() {
        return None;
    }
    let format = |p: Option<&str>| -> Option<Option<Format>> {
        match p {
            None => Some(None),
            Some("N") => Some(Some(Format::NonPrint)),
            Some("T") => Some(Some(Format::Telnet)),
            Some("C") => Some(Some(Format::CarriageControl)),
            Some(_) => None,
        }
    };
    Some(match (kind, param) {
        ("A", p) => DataType::Ascii(format(p)?),
        ("E", p) => DataType::Ebcdic(format(p)?),
        ("I", None) => DataType::Image,
        ("L", Some(n)) => DataType::Local(NonZeroU8::new(u8::try_from(decimal(n, 3)?).ok()?)?),
        _ => return None,
    })
}

fn write_type(t: DataType) -> String {
    let format = |f: Option<Format>| match f {
        None => "",
        Some(Format::NonPrint) => " N",
        Some(Format::Telnet) => " T",
        Some(Format::CarriageControl) => " C",
    };
    match t {
        DataType::Ascii(f) => format!("A{}", format(f)),
        DataType::Ebcdic(f) => format!("E{}", format(f)),
        DataType::Image => "I".to_string(),
        DataType::Local(n) => format!("L {n}"),
    }
}

/// Why an address in `PORT`, `EPRT` or a passive reply could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    /// The text did not have the form the command or reply needs.
    Syntax,
    /// `EPRT` named an address family other than 1 (IPv4) or 2 (IPv6).
    Family,
    /// The reply had the wrong code for the address asked of it.
    Code,
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AddressError::Syntax => "malformed address",
            AddressError::Family => "address family is not 1 (IPv4) or 2 (IPv6)",
            AddressError::Code => "reply code does not carry this address",
        })
    }
}

impl std::error::Error for AddressError {}

/// Reads the argument of `PORT`: six decimal numbers from 0 to 255 joined
/// by commas, `h1,h2,h3,h4,p1,p2`. The first four are the IPv4 address and
/// the last two the port, high byte first (RFC 959, section 4.1.2).
pub fn parse_port(arg: &str) -> Result<SocketAddrV4, AddressError> {
    match scan_host_port(arg) {
        Some((addr, used)) if used == arg.len() => Ok(addr),
        _ => Err(AddressError::Syntax),
    }
}

/// Writes an address as the argument of `PORT`, or the numbers in a reply
/// to `PASV`.
pub fn write_port(addr: SocketAddrV4) -> String {
    let [a, b, c, d] = addr.ip().octets();
    let [p1, p2] = addr.port().to_be_bytes();
    format!("{a},{b},{c},{d},{p1},{p2}")
}

/// Reads the argument of `EPRT`, such as `|1|132.235.1.2|6275|` or
/// `|2|1080::8:800:200C:417A|5282|` (RFC 2428, section 2). The first
/// character is the delimiter, which may be any printable ASCII character.
/// A family given as digits but not 1 or 2 is [`AddressError::Family`],
/// whatever the address and port after it look like.
pub fn parse_eprt(arg: &str) -> Result<SocketAddr, AddressError> {
    let d = arg.chars().next().ok_or(AddressError::Syntax)?;
    if !d.is_ascii_graphic() {
        return Err(AddressError::Syntax);
    }
    let mut fields = arg[1..].split(d);
    let (Some(family), Some(host), Some(port), Some(""), None) =
        (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(AddressError::Syntax);
    };
    if family.is_empty() || !family.bytes().all(|c| c.is_ascii_digit()) {
        return Err(AddressError::Syntax);
    }
    // Leading zeros aside, the family must be 1 or 2.
    let ip = match family.trim_start_matches('0') {
        "1" => IpAddr::V4(host.parse::<Ipv4Addr>().map_err(|_| AddressError::Syntax)?),
        "2" => IpAddr::V6(host.parse::<Ipv6Addr>().map_err(|_| AddressError::Syntax)?),
        _ => return Err(AddressError::Family),
    };
    let port = decimal(port, 5).and_then(|n| u16::try_from(n).ok()).ok_or(AddressError::Syntax)?;
    Ok(SocketAddr::new(ip, port))
}

/// Writes an address as the argument of `EPRT`, with `|` as the delimiter.
/// An IPv6 address's flow label and scope are left out, as RFC 2428 has no
/// place for them.
pub fn write_eprt(addr: SocketAddr) -> String {
    let family = if addr.is_ipv4() { 1 } else { 2 };
    format!("|{family}|{}|{}|", addr.ip(), addr.port())
}

/// Reads `h1,h2,h3,h4,p1,p2` at the start of `s`, and says how many bytes
/// it took.
fn scan_host_port(s: &str) -> Option<(SocketAddrV4, usize)> {
    let b = s.as_bytes();
    let mut n = [0u8; 6];
    let mut at = 0;
    for (i, slot) in n.iter_mut().enumerate() {
        if i > 0 {
            if b.get(at) != Some(&b',') {
                return None;
            }
            at += 1;
        }
        let digits = b.get(at..)?.iter().take(4).take_while(|c| c.is_ascii_digit()).count();
        *slot = u8::try_from(decimal(s.get(at..at + digits)?, 3)?).ok()?;
        at += digits;
    }
    let addr = SocketAddrV4::new(Ipv4Addr::new(n[0], n[1], n[2], n[3]), u16::from_be_bytes([n[4], n[5]]));
    Some((addr, at))
}

/// A string of one to `max` ASCII digits, read as a number. Leading zeros
/// are allowed. Signs and spaces are not.
fn decimal(s: &str, max: usize) -> Option<u32> {
    if s.is_empty() || s.len() > max || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.bytes().try_fold(0u32, |n, c| n.checked_mul(10)?.checked_add(u32::from(c - b'0')))
}

/// Reply codes from RFC 959, section 4.2.2, and RFC 2428, and the
/// [`ReplyCode`] type they share.
pub mod code {
    /// A reply code: three digits, the first from 1 to 5 (RFC 959, section
    /// 4.2). The first digit says how the command went, and the second what
    /// the reply is about.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ReplyCode(u16);

    impl ReplyCode {
        /// The code `n`, if it is from 100 to 599.
        pub const fn new(n: u16) -> Option<ReplyCode> {
            if n >= 100 && n <= 599 { Some(ReplyCode(n)) } else { None }
        }

        /// The code's number.
        pub const fn get(self) -> u16 {
            self.0
        }

        /// Whether the code starts with 1: the command has started, and
        /// another reply will follow.
        pub const fn is_preliminary(self) -> bool {
            self.0 / 100 == 1
        }

        /// Whether the code starts with 2: the command succeeded.
        pub const fn is_completion(self) -> bool {
            self.0 / 100 == 2
        }

        /// Whether the code starts with 3: the command needs another to
        /// finish, such as `PASS` after `USER`.
        pub const fn is_intermediate(self) -> bool {
            self.0 / 100 == 3
        }

        /// Whether the code starts with 4: the command failed, and may work if
        /// tried again.
        pub const fn is_transient_failure(self) -> bool {
            self.0 / 100 == 4
        }

        /// Whether the code starts with 5: the command failed, and will fail
        /// again.
        pub const fn is_permanent_failure(self) -> bool {
            self.0 / 100 == 5
        }
    }

    impl std::fmt::Display for ReplyCode {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    /// 110: restart marker reply.
    pub const RESTART_MARKER: ReplyCode = ReplyCode(110);
    /// 120: service ready in some minutes.
    pub const READY_SOON: ReplyCode = ReplyCode(120);
    /// 125: data connection already open, transfer starting.
    pub const TRANSFER_STARTING: ReplyCode = ReplyCode(125);
    /// 150: file status okay, about to open the data connection.
    pub const OPENING_DATA: ReplyCode = ReplyCode(150);
    /// 200: command okay.
    pub const OK: ReplyCode = ReplyCode(200);
    /// 202: command not implemented, not needed at this site.
    pub const SUPERFLUOUS: ReplyCode = ReplyCode(202);
    /// 211: system status, or the reply to `FEAT`.
    pub const SYSTEM_STATUS: ReplyCode = ReplyCode(211);
    /// 212: directory status.
    pub const DIRECTORY_STATUS: ReplyCode = ReplyCode(212);
    /// 213: file status, and the reply to `SIZE` and `MDTM`.
    pub const FILE_STATUS: ReplyCode = ReplyCode(213);
    /// 214: help message.
    pub const HELP: ReplyCode = ReplyCode(214);
    /// 215: the system type, in reply to `SYST`.
    pub const SYSTEM_TYPE: ReplyCode = ReplyCode(215);
    /// 220: service ready for a new user. Servers send it on connecting.
    pub const READY: ReplyCode = ReplyCode(220);
    /// 221: closing the control connection.
    pub const CLOSING: ReplyCode = ReplyCode(221);
    /// 225: data connection open, no transfer in progress.
    pub const DATA_OPEN: ReplyCode = ReplyCode(225);
    /// 226: closing the data connection, the transfer succeeded.
    pub const TRANSFER_COMPLETE: ReplyCode = ReplyCode(226);
    /// 227: entering passive mode, in reply to `PASV`.
    pub const PASSIVE: ReplyCode = ReplyCode(227);
    /// 229: entering extended passive mode, in reply to `EPSV`.
    pub const EXTENDED_PASSIVE: ReplyCode = ReplyCode(229);
    /// 230: user logged in.
    pub const LOGGED_IN: ReplyCode = ReplyCode(230);
    /// 250: requested file action okay, completed.
    pub const FILE_ACTION_OK: ReplyCode = ReplyCode(250);
    /// 257: the path was created, or is the current directory.
    pub const PATH_CREATED: ReplyCode = ReplyCode(257);
    /// 331: user name okay, need a password.
    pub const NEED_PASSWORD: ReplyCode = ReplyCode(331);
    /// 332: need an account to log in.
    pub const NEED_ACCOUNT: ReplyCode = ReplyCode(332);
    /// 350: file action pending further information, as after `RNFR`.
    pub const PENDING: ReplyCode = ReplyCode(350);
    /// 421: service not available, closing the control connection.
    pub const UNAVAILABLE: ReplyCode = ReplyCode(421);
    /// 425: cannot open the data connection.
    pub const CANT_OPEN_DATA: ReplyCode = ReplyCode(425);
    /// 426: connection closed, transfer aborted.
    pub const TRANSFER_ABORTED: ReplyCode = ReplyCode(426);
    /// 450: file unavailable, such as busy.
    pub const FILE_BUSY: ReplyCode = ReplyCode(450);
    /// 451: action aborted, local error in processing.
    pub const LOCAL_ERROR: ReplyCode = ReplyCode(451);
    /// 452: insufficient storage space.
    pub const NO_SPACE: ReplyCode = ReplyCode(452);
    /// 500: syntax error, command unrecognized.
    pub const SYNTAX_ERROR: ReplyCode = ReplyCode(500);
    /// 501: syntax error in parameters or arguments.
    pub const ARGUMENT_ERROR: ReplyCode = ReplyCode(501);
    /// 502: command not implemented.
    pub const NOT_IMPLEMENTED: ReplyCode = ReplyCode(502);
    /// 503: bad sequence of commands.
    pub const BAD_SEQUENCE: ReplyCode = ReplyCode(503);
    /// 504: command not implemented for that parameter.
    pub const PARAMETER_NOT_IMPLEMENTED: ReplyCode = ReplyCode(504);
    /// 522: network protocol not supported, in reply to `EPRT` or `EPSV`.
    pub const UNKNOWN_NETWORK_PROTOCOL: ReplyCode = ReplyCode(522);
    /// 530: not logged in.
    pub const NOT_LOGGED_IN: ReplyCode = ReplyCode(530);
    /// 532: need an account for storing files.
    pub const NEED_ACCOUNT_TO_STORE: ReplyCode = ReplyCode(532);
    /// 550: file unavailable, such as not found or no access.
    pub const FILE_UNAVAILABLE: ReplyCode = ReplyCode(550);
    /// 551: page type unknown.
    pub const PAGE_TYPE_UNKNOWN: ReplyCode = ReplyCode(551);
    /// 552: exceeded storage allocation.
    pub const STORAGE_EXCEEDED: ReplyCode = ReplyCode(552);
    /// 553: file name not allowed.
    pub const BAD_FILE_NAME: ReplyCode = ReplyCode(553);
}

/// A reply: a code and one or more lines of text.
///
/// A reply of one line is written `220 Ready`. A reply of several is
/// written with a hyphen after the code on the first line and a space on
/// the last, and the lines between are text as it is, with a space in
/// front of any that starts with three digits (RFC 959, section 4.2):
///
/// ```text
/// 211-Extensions supported:
///  SIZE
/// 211 End
/// ```
///
/// [`Reply::lines`] holds the first line's text after the code, the lines
/// between as they are, and the last line's text after the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The reply code.
    pub code: ReplyCode,
    /// The lines of text. A reply read always has at least one.
    pub lines: Vec<String>,
}

/// Why bytes are not an FTP reply. After any of these but
/// [`ReplyError::TooManyLines`], the stream holds no more replies a reader
/// can find, and a client closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// A line was longer than [`MAX_LINE`].
    LineTooLong,
    /// A line was not UTF-8, or held a carriage return or a NUL byte.
    Text,
    /// A reply did not start with a code from 100 to 599 followed by a
    /// space, a hyphen or the end of the line.
    Syntax,
    /// A reply ran to more than [`MAX_REPLY_LINES`] lines. A
    /// [`ReplyDecoder`] drops the reply's lines up to its last one, as RFC
    /// 1123 (section 4.1.2.11) asks, and goes on to the next reply.
    TooManyLines,
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReplyError::LineTooLong => "reply line too long",
            ReplyError::Text => "reply line is not UTF-8 text without CR or NUL",
            ReplyError::Syntax => "reply does not start with a code from 100 to 599",
            ReplyError::TooManyLines => "reply has too many lines",
        })
    }
}

impl std::error::Error for ReplyError {}

/// One feature line of a reply to `FEAT` (RFC 2389, section 3.2), such as
/// ` MLST size*;modify*;`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feature {
    /// The feature's name, such as `MDTM`, as sent. RFC 2389 (section 3.2)
    /// leaves case to each feature's own definition, so compare names with
    /// [`str::eq_ignore_ascii_case`] where that definition allows it.
    pub name: String,
    /// Everything after the space that follows the name, or `None` if
    /// nothing follows it. Parameters are printable ASCII, spaces and tabs.
    pub params: Option<String>,
}

/// Why a reply is not a list of features.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureError {
    /// The reply's code was not 211.
    Code(ReplyCode),
    /// A feature line did not start with a space and a name of printable
    /// ASCII characters, or its parameters held other characters than
    /// printable ASCII, spaces and tabs.
    Line,
}

impl std::fmt::Display for FeatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeatureError::Code(c) => write!(f, "reply code {c}, not 211"),
            FeatureError::Line => f.write_str("malformed feature line"),
        }
    }
}

impl std::error::Error for FeatureError {}

impl Reply {
    /// A reply of one line. Text that would not fit in [`MAX_LINE`] is cut,
    /// as [`Reply::to_bytes`] would cut it.
    pub fn new(code: ReplyCode, text: &str) -> Reply {
        Reply { code, lines: vec![cut(text, MAX_REPLY_TEXT).to_string()] }
    }

    /// Reads the reply at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the reply and how many bytes
    /// of `b` it took. Lines end in CRLF, or in LF alone. Each call reads
    /// `b` from its start, so to read a stream as it comes in, use a
    /// [`ReplyDecoder`], which reads each byte once.
    pub fn parse(b: &[u8]) -> Result<Option<(Reply, usize)>, ReplyError> {
        let mut builder = Builder::default();
        let mut at = 0;
        loop {
            let rest = &b[at..];
            match split_line(rest) {
                Split::Partial => return Ok(None),
                Split::TooLong(_) => return Err(ReplyError::LineTooLong),
                Split::Line { end, used } => {
                    at += used;
                    if let Some(reply) = builder.take(&rest[..end])? {
                        return Ok(Some((reply, at)));
                    }
                }
            }
        }
    }

    /// The reply's bytes, each line ending in CRLF. Lines lose any CR, LF
    /// and NUL and are cut to fit in [`MAX_LINE`]. A line between the
    /// first and the last that starts with three digits gets a space in
    /// front, as RFC 959 asks, so that no client reads it as the last. A reply with more than [`MAX_REPLY_LINES`]
    /// lines keeps the first ones and the last. A reply with no lines is
    /// written with empty text.
    pub fn to_bytes(&self) -> Vec<u8> {
        let code = self.code.get().to_string();
        let mut out = Vec::new();
        let n = self.lines.len();
        // Cut before cleaning, so a long line is never copied whole.
        let text = |t: &str, max: usize| clean(cut(t, max));
        if n <= 1 {
            let t = self.lines.first().map(|t| text(t, MAX_REPLY_TEXT)).unwrap_or_default();
            push_line(&mut out, &format!("{code} {t}"));
            return out;
        }
        let keep = n.min(MAX_REPLY_LINES);
        push_line(&mut out, &format!("{code}-{}", text(&self.lines[0], MAX_REPLY_TEXT)));
        for line in &self.lines[1..keep - 1] {
            let line = text(line, MAX_CONTENT);
            if line.bytes().take(3).filter(u8::is_ascii_digit).count() == 3 {
                push_line(&mut out, &format!(" {}", cut(&line, MAX_CONTENT - 1)));
            } else {
                push_line(&mut out, &line);
            }
        }
        push_line(&mut out, &format!("{code} {}", text(&self.lines[n - 1], MAX_REPLY_TEXT)));
        out
    }

    /// The reply to `PASV`: code 227 and the address in the form RFC 959
    /// gives, `Entering Passive Mode (h1,h2,h3,h4,p1,p2).`
    pub fn passive(addr: SocketAddrV4) -> Reply {
        Reply::new(code::PASSIVE, &format!("Entering Passive Mode ({}).", write_port(addr)))
    }

    /// The address in a reply to `PASV`. Servers word the reply in
    /// different ways, so this reads the six numbers from the first digit
    /// of a line on, as RFC 1123 (section 4.1.2.6) advises. In a reply of
    /// several lines it takes the first line that holds them.
    pub fn passive_address(&self) -> Result<SocketAddrV4, AddressError> {
        if self.code != code::PASSIVE {
            return Err(AddressError::Code);
        }
        self.lines
            .iter()
            .find_map(|line| {
                let start = line.find(|c: char| c.is_ascii_digit())?;
                scan_host_port(&line[start..]).map(|(addr, _)| addr)
            })
            .ok_or(AddressError::Syntax)
    }

    /// The reply to `EPSV`: code 229 and the port in the form RFC 2428
    /// gives, `Entering Extended Passive Mode (|||port|)`.
    pub fn extended_passive(port: u16) -> Reply {
        Reply::new(code::EXTENDED_PASSIVE, &format!("Entering Extended Passive Mode (|||{port}|)"))
    }

    /// The port in a reply to `EPSV`: the number in `(|||port|)`, where `|`
    /// may be any printable ASCII character, `)` included. In a reply of
    /// several lines it takes the first line that holds one.
    pub fn extended_passive_port(&self) -> Result<u16, AddressError> {
        if self.code != code::EXTENDED_PASSIVE {
            return Err(AddressError::Code);
        }
        self.lines.iter().find_map(|line| epsv_port(line)).ok_or(AddressError::Syntax)
    }

    /// The reply to `FEAT` that lists `features` (RFC 2389, section 3.2).
    /// With none it is the one line `211 No features.`. A name keeps only
    /// its printable ASCII characters, and a feature whose name has none
    /// is left out. Parameters keep only printable ASCII, spaces and tabs,
    /// and are left out if none are kept. A line is cut to fit in
    /// [`MAX_LINE`]. At most [`MAX_FEATURES`] are listed.
    pub fn feature_list(features: &[Feature]) -> Reply {
        let mut lines = vec!["Extensions supported:".to_string()];
        for f in features {
            if lines.len() > MAX_FEATURES {
                break;
            }
            let mut line = String::from(" ");
            line.extend(f.name.chars().filter(char::is_ascii_graphic).take(MAX_CONTENT - 1));
            if line.len() == 1 {
                continue;
            }
            if let Some(p) = &f.params {
                let room = MAX_CONTENT.saturating_sub(line.len() + 1);
                let mut params = p.chars().filter(|&c| feature_char(c)).take(room).peekable();
                if params.peek().is_some() {
                    line.push(' ');
                    line.extend(params);
                }
            }
            lines.push(line);
        }
        if lines.len() == 1 {
            return Reply::new(code::SYSTEM_STATUS, "No features.");
        }
        lines.push("End".to_string());
        Reply { code: code::SYSTEM_STATUS, lines }
    }

    /// The features a reply to `FEAT` lists. A reply of one line lists
    /// none.
    pub fn features(&self) -> Result<Vec<Feature>, FeatureError> {
        if self.code != code::SYSTEM_STATUS {
            return Err(FeatureError::Code(self.code));
        }
        let middle = if self.lines.len() > 2 { &self.lines[1..self.lines.len() - 1] } else { &[] };
        middle
            .iter()
            .map(|line| {
                let rest = line.strip_prefix(' ').ok_or(FeatureError::Line)?;
                let (name, params) = match rest.split_once(' ') {
                    // A space with nothing after it is read as no parameters.
                    Some((name, "")) => (name, None),
                    Some((name, params)) => (name, Some(params)),
                    None => (rest, None),
                };
                if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(FeatureError::Line);
                }
                if params.is_some_and(|p| !p.chars().all(feature_char)) {
                    return Err(FeatureError::Line);
                }
                Ok(Feature { name: name.to_string(), params: params.map(str::to_string) })
            })
            .collect()
    }
}

/// Whether `c` may be in a feature's parameters: printable ASCII, space or
/// tab (`TCHAR` in RFC 2389, section 2.1).
fn feature_char(c: char) -> bool {
    c.is_ascii_graphic() || c == ' ' || c == '\t'
}

/// The port in `(|||port|)` on one line of a reply to `EPSV`.
fn epsv_port(line: &str) -> Option<u16> {
    let open = line.find('(')?;
    let inside = &line[open + 1..];
    let d = inside.chars().next().filter(|c| c.is_ascii_graphic())?;
    // Split off only the three fields, so `)` may be the delimiter.
    let mut fields = inside[1..].splitn(4, d);
    let (Some(""), Some(""), Some(port), Some(rest)) = (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return None;
    };
    if !rest.starts_with(')') {
        return None;
    }
    decimal(port, 5).and_then(|n| u16::try_from(n).ok())
}

/// Builds a reply from its lines, one at a time.
#[derive(Clone, Debug, Default)]
struct Builder {
    /// The code and lines so far of a multi-line reply, and whether it ran
    /// past [`MAX_REPLY_LINES`] and its lines were dropped.
    open: Option<(ReplyCode, Vec<String>, bool)>,
}

impl Builder {
    /// Takes one line's content. It returns the reply that line finishes,
    /// if it finishes one. A reply with too many lines is an error once
    /// its last line comes, and the builder is then ready for the next.
    fn take(&mut self, line: &[u8]) -> Result<Option<Reply>, ReplyError> {
        let line = text(line).ok_or(ReplyError::Text)?;
        if let Some((code, lines, over)) = &mut self.open {
            if ends(line, *code) {
                let code = *code;
                let over = *over;
                let mut lines = std::mem::take(lines);
                self.open = None;
                if over {
                    return Err(ReplyError::TooManyLines);
                }
                lines.push(line.get(4..).unwrap_or("").to_string());
                return Ok(Some(Reply { code, lines }));
            }
            // Leave room for the last line.
            if *over || lines.len() + 1 >= MAX_REPLY_LINES {
                *over = true;
                *lines = Vec::new();
            } else {
                lines.push(line.to_string());
            }
            return Ok(None);
        }
        let b = line.as_bytes();
        let code = match b.get(..3) {
            Some(&[a, x, y]) if (b'1'..=b'5').contains(&a) && x.is_ascii_digit() && y.is_ascii_digit() => {
                let n = u16::from(a - b'0') * 100 + u16::from(x - b'0') * 10 + u16::from(y - b'0');
                ReplyCode::new(n).ok_or(ReplyError::Syntax)?
            }
            _ => return Err(ReplyError::Syntax),
        };
        let rest = line.get(4..).unwrap_or("").to_string();
        match b.get(3) {
            None | Some(b' ') => Ok(Some(Reply { code, lines: vec![rest] })),
            Some(b'-') => {
                self.open = Some((code, vec![rest], false));
                Ok(None)
            }
            Some(_) => Err(ReplyError::Syntax),
        }
    }
}

/// Whether `line` is the last line of a multi-line reply with `code`: the
/// code, then a space or the end of the line.
fn ends(line: &str, code: ReplyCode) -> bool {
    let b = line.as_bytes();
    b.len() >= 3 && b[..3] == *code.get().to_string().as_bytes() && matches!(b.get(3), None | Some(b' '))
}

/// Where the first line in a buffer ends.
enum Split {
    /// The buffer holds no whole line yet.
    Partial,
    /// A line whose content is the first `end` bytes, and which takes
    /// `used` bytes with its line ending.
    Line { end: usize, used: usize },
    /// The first line is too long. If its end is in the buffer, this says
    /// how many bytes it takes.
    TooLong(Option<usize>),
}

/// The two bytes taken to come before the bytes a reader holds: the end
/// of a line, or of nothing.
const LINE_START: [u8; 2] = [b'\n', b'\n'];

/// Where the first line end in `b` is: the first LF that does not follow
/// CR NUL. A LF after CR NUL is part of a pathname (RFC 2640, section
/// 3.1). `prev` holds the two bytes before `b`.
fn next_end(prev: [u8; 2], b: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(off) = b[from..].iter().position(|&c| c == b'\n') {
        let i = from + off;
        let p1 = if i >= 1 { b[i - 1] } else { prev[1] };
        let p2 = match i {
            0 => prev[0],
            1 => prev[1],
            _ => b[i - 2],
        };
        if !(p2 == b'\r' && p1 == 0) {
            return Some(i);
        }
        from = i + 1;
    }
    None
}

/// The last two bytes of the stream once `b` follows `prev`.
fn last_two(prev: [u8; 2], b: &[u8]) -> [u8; 2] {
    match b {
        [] => prev,
        [x] => [prev[1], *x],
        [.., x, y] => [*x, *y],
    }
}

/// Finds the first line in `b`. A line ends at a LF that does not follow
/// CR NUL, and a CR right before that LF is not part of its content. A
/// line's content may be at most [`MAX_LINE`] less 2 bytes.
fn split_line(b: &[u8]) -> Split {
    let window = &b[..b.len().min(MAX_LINE)];
    match next_end(LINE_START, window) {
        Some(i) => {
            let end = if i > 0 && b[i - 1] == b'\r' { i - 1 } else { i };
            if end > MAX_CONTENT { Split::TooLong(Some(i + 1)) } else { Split::Line { end, used: i + 1 } }
        }
        None if b.len() >= MAX_LINE => Split::TooLong(None),
        None => Split::Partial,
    }
}

/// Splits a byte stream into lines, and skips lines that are too long.
/// It keeps at most [`MAX_LINE`] bytes of any one line and at most
/// [`MAX_BUFFERED`] bytes in all.
#[derive(Clone, Debug, Default)]
struct Lines {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped when they make up half of `buf`, so taking many short lines
    /// out of one large feed takes linear time.
    start: usize,
    /// How many bytes after `start` are known to hold no line end.
    scanned: usize,
    /// How many bytes of the last line, which has no end yet, are held.
    tail: usize,
    /// Whether the bytes up to the next line end belong to a line too long
    /// to keep, and are dropped.
    dropping: bool,
    /// The last two bytes fed, kept or dropped, to tell which LF ends a
    /// line.
    prev: [u8; 2],
}

impl Lines {
    /// Takes bytes from the start of `bytes`, and says how many it took.
    fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let mut used = 0;
        while used < bytes.len() {
            let rest = &bytes[used..];
            if self.dropping {
                let Some(i) = next_end(self.prev, rest) else {
                    self.prev = last_two(self.prev, rest);
                    return bytes.len();
                };
                if self.tail > 0 {
                    // The start of the long line is held. End it, so the
                    // reader finds it too long and skips it.
                    if self.held().len() >= MAX_BUFFERED {
                        break;
                    }
                    self.buf.push(b'\n');
                    self.tail = 0;
                }
                self.dropping = false;
                self.prev = last_two(self.prev, &rest[..=i]);
                used += i + 1;
                continue;
            }
            let room = MAX_BUFFERED.saturating_sub(self.held().len());
            let n = rest.len().min(room).min(MAX_LINE - self.tail);
            if n == 0 {
                break;
            }
            let piece = &rest[..n];
            let take = match next_end(self.prev, piece) {
                Some(i) => {
                    self.tail = 0;
                    i + 1
                }
                None => {
                    self.tail += n;
                    n
                }
            };
            self.buf.extend_from_slice(&piece[..take]);
            self.prev = last_two(self.prev, &piece[..take]);
            used += take;
            if self.tail >= MAX_LINE {
                // The line is too long. Its last byte is made plain, so the
                // LF that will end it cannot read as part of a pathname.
                self.dropping = true;
                if let Some(last) = self.buf.last_mut() {
                    *last = b'x';
                }
            }
        }
        used
    }

    /// The bytes not yet taken out.
    fn held(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or(&[])
    }

    /// Drops every byte held.
    fn clear(&mut self) {
        self.buf = Vec::new();
        self.start = 0;
        self.scanned = 0;
        self.tail = 0;
    }

    /// Takes `n` bytes out.
    fn take(&mut self, n: usize) {
        self.start = self.start.saturating_add(n).min(self.buf.len());
        self.scanned = 0;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// The next line's content, or `Err(())` for a line too long, which is
    /// then dropped.
    fn next_line(&mut self) -> Option<Result<Vec<u8>, ()>> {
        let held = self.held();
        // Bytes fed one at a time are each looked at once.
        let from = self.scanned.min(held.len());
        let before = match from {
            0 => LINE_START,
            1 => [LINE_START[1], held[0]],
            _ => [held[from - 2], held[from - 1]],
        };
        if held.len() < MAX_LINE && next_end(before, &held[from..]).is_none() {
            self.scanned = held.len();
            return None;
        }
        match split_line(held) {
            Split::Partial => None,
            Split::Line { end, used } => {
                let line = held[..end].to_vec();
                self.take(used);
                Some(Ok(line))
            }
            Split::TooLong(Some(used)) => {
                self.take(used);
                Some(Err(()))
            }
            Split::TooLong(None) => {
                match next_end(LINE_START, held) {
                    Some(i) => self.take(i + 1),
                    None => {
                        // Only the long line's start is held, and the rest
                        // is being dropped as it comes.
                        self.clear();
                        self.dropping = true;
                    }
                }
                Some(Err(()))
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

    /// Adds bytes read from the connection, and says how many it took. It
    /// takes them all unless it would then hold more than
    /// [`MAX_BUFFERED`] bytes. Take commands out with
    /// [`next_command`](Self::next_command), then feed the rest again. The
    /// bytes of a line too long to keep are taken and dropped.
    #[must_use = "a decoder may take only part of the bytes"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        self.lines.feed(bytes)
    }

    /// The next whole line, read as a command. It returns `None` when it
    /// needs more bytes. An error covers one line only, and the next call
    /// reads the line after it.
    pub fn next_command(&mut self) -> Option<Result<Command, CommandError>> {
        Some(match self.lines.next_line()? {
            Ok(line) => Command::parse(&line),
            Err(()) => Err(CommandError::LineTooLong),
        })
    }

    /// How many bytes are held, waiting to be taken out. It is never more
    /// than [`MAX_BUFFERED`].
    pub fn buffered(&self) -> usize {
        self.lines.held().len()
    }
}

/// Splits the stream a client reads into replies, joining the lines of
/// multi-line replies. Feed it the bytes a connection reads, in order, and
/// take replies out until it has none.
#[derive(Clone, Debug, Default)]
pub struct ReplyDecoder {
    lines: Lines,
    builder: Builder,
    failed: Option<ReplyError>,
}

impl ReplyDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> ReplyDecoder {
        ReplyDecoder::default()
    }

    /// Adds bytes read from the connection, and says how many it took, as
    /// [`CommandDecoder::feed`] does. After a [`ReplyError`] other than
    /// [`ReplyError::TooManyLines`] the stream cannot be read any further,
    /// and it takes every byte and drops it.
    #[must_use = "a decoder may take only part of the bytes"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        self.lines.feed(bytes)
    }

    /// The next whole reply, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A reply with too many lines is one
    /// [`ReplyError::TooManyLines`], and the next call reads the reply
    /// after it. A decoder holds at most [`MAX_REPLY_LINES`] lines of one
    /// reply, plus [`MAX_BUFFERED`] bytes.
    pub fn next_reply(&mut self) -> Option<Result<Reply, ReplyError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        loop {
            let result = match self.lines.next_line()? {
                Ok(line) => self.builder.take(&line),
                Err(()) => Err(ReplyError::LineTooLong),
            };
            match result {
                Ok(Some(reply)) => return Some(Ok(reply)),
                Ok(None) => {}
                Err(ReplyError::TooManyLines) => return Some(Err(ReplyError::TooManyLines)),
                Err(e) => {
                    self.failed = Some(e);
                    self.lines = Lines::default();
                    self.builder = Builder::default();
                    return Some(Err(e));
                }
            }
        }
    }

    /// How many bytes are held, waiting to be taken out. It is never more
    /// than [`MAX_BUFFERED`].
    pub fn buffered(&self) -> usize {
        self.lines.held().len()
    }
}

/// `line` as text, if it is UTF-8 with no CR, LF or NUL.
fn text(line: &[u8]) -> Option<&str> {
    if line.iter().any(|&c| matches!(c, b'\r' | b'\n' | 0)) {
        return None;
    }
    std::str::from_utf8(line).ok()
}

/// The Telnet byte that starts a command (RFC 854).
const IAC: u8 = 0xff;

/// A command line as text: Telnet commands dropped, CR NUL read as CR, and
/// a LF kept only right after CR NUL. It is `None` if what is left is not
/// UTF-8, holds a NUL or any other CR or LF, or the line ends inside a
/// Telnet command, or IAC is followed by a byte that is not a command
/// (240 to 254, RFC 854). A doubled IAC stands for the byte 0xFF, which is
/// never UTF-8, so it is `None` too.
fn command_text(line: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(line.len());
    let mut i = 0;
    let mut after_cr_nul = false;
    while i < line.len() {
        let c = line[i];
        let was_cr_nul = after_cr_nul;
        after_cr_nul = false;
        match c {
            IAC => match line.get(i + 1)? {
                // WILL, WONT, DO and DONT name an option in the next byte.
                251..=254 => {
                    line.get(i + 2)?;
                    i += 3;
                }
                240..=250 => i += 2,
                _ => return None,
            },
            b'\r' => {
                if line.get(i + 1) != Some(&0) {
                    return None;
                }
                out.push(b'\r');
                after_cr_nul = true;
                i += 2;
            }
            b'\n' if was_cr_nul => {
                out.push(b'\n');
                i += 1;
            }
            0 | b'\n' => return None,
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// `s` without CR, LF or NUL.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '\r' | '\n' | '\0')).collect()
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

fn push_line(out: &mut Vec<u8>, line: &str) {
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Maximum text bytes retained while assembling one reply.
pub const MAX_REPLY_BYTES: usize = MAX_REPLY_LINES * MAX_CONTENT;

/// A terminal fault in the new control stream decoders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// EOF interrupted a line or a multi-line reply.
    Incomplete,
    /// A reply's framing can no longer be followed.
    Reply(ReplyError),
}
impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete => f.write_str("incomplete FTP control unit"),
            Self::Reply(e) => e.fmt(f),
        }
    }
}
impl core::error::Error for DecodeError {}

/// Why bytes do not contain exactly one complete FTP command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandParseError {
    /// The command was refused.
    Command(CommandError),
    /// The command ended early.
    Incomplete,
    /// Bytes followed the command.
    Trailing,
}
impl core::fmt::Display for CommandParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Command(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete FTP command"),
            Self::Trailing => f.write_str("bytes after FTP command"),
        }
    }
}
impl core::error::Error for CommandParseError {}

/// Why bytes do not contain exactly one complete FTP reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyParseError {
    /// The reply was refused.
    Reply(ReplyError),
    /// The reply ended early.
    Incomplete,
    /// Bytes followed the reply.
    Trailing,
}
impl core::fmt::Display for ReplyParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Reply(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete FTP reply"),
            Self::Trailing => f.write_str("bytes after FTP reply"),
        }
    }
}
impl core::error::Error for ReplyParseError {}

/// A reply cannot be written without changing its value.
///
/// Refuses empty or oversized line lists, CR, LF or NUL, oversized text,
/// and middle lines that would terminate the reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyWriteError;

impl core::fmt::Display for ReplyWriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FTP reply cannot be written unchanged")
    }
}
impl core::error::Error for ReplyWriteError {}

// Lines frames physical lines. RFC 2640's CR NUL LF is joined here into
// one logical line. Only consumed pieces are retained, under MAX_CONTENT.
#[derive(Clone, Debug)]
struct ControlLines {
    lines: codec::Lines,
    partial: Vec<u8>,
    dropping: bool,
    prev: [u8; 2],
}
impl ControlLines {
    fn new() -> Self {
        Self {
            lines: codec::Lines::new(MAX_CONTENT, codec::Ending::LfOrCrlf),
            partial: Vec::new(),
            dropping: false,
            prev: LINE_START,
        }
    }

    fn reset_line(&mut self) {
        self.lines =
            codec::Lines::new(MAX_CONTENT.saturating_sub(self.partial.len()), codec::Ending::LfOrCrlf);
    }

    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
    ) -> Result<Step<Result<Vec<u8>, CommandError>>, DecodeError> {
        if self.dropping {
            let n = next_end(self.prev, input).map_or(input.len(), |i| i.saturating_add(1));
            if n == 0 {
                return Ok(Step::Need);
            }
            let raw = input.get(..n).unwrap_or_default();
            self.dropping = next_end(self.prev, raw).is_none();
            self.prev = last_two(self.prev, raw);
            return Ok(Step::Skip(n));
        }
        let step = self.lines.decode(input, eof).unwrap_or_else(|never| match never {});
        match step {
            Step::Item(Ok(line), n) => {
                let raw = input.get(..n).unwrap_or_default();
                let escaped = raw.ends_with(b"\r\0\n");
                if escaped {
                    if raw.len() > MAX_CONTENT.saturating_sub(self.partial.len()) {
                        self.partial.clear();
                        self.dropping = true;
                        self.prev = last_two(LINE_START, raw);
                        self.reset_line();
                        return Ok(Step::Item(Err(CommandError::LineTooLong), n));
                    }
                    self.partial.extend_from_slice(raw);
                    self.reset_line();
                    Ok(Step::Skip(n))
                } else {
                    let mut whole = core::mem::take(&mut self.partial);
                    whole.extend_from_slice(&line);
                    self.reset_line();
                    Ok(Step::Item(Ok(whole), n))
                }
            }
            Step::Item(Err(codec::LineError::TooLong { .. }), n) => {
                let raw = input.get(..n).unwrap_or_default();
                self.partial.clear();
                self.dropping = next_end(LINE_START, raw).is_none();
                self.prev = last_two(LINE_START, raw);
                self.reset_line();
                Ok(Step::Item(Err(CommandError::LineTooLong), n))
            }
            Step::Item(Err(_), _) => Err(DecodeError::Incomplete),
            Step::Need if eof && !self.partial.is_empty() => Err(DecodeError::Incomplete),
            Step::Need => Ok(Step::Need),
            Step::Skip(n) => Ok(Step::Skip(n)),
            Step::End => Ok(Step::End),
        }
    }
}

/// Reads control commands through [`super::codec::Lines`].
///
/// CRLF and bare LF are accepted. RFC 2640's CR NUL escaping stays in
/// this module. Lines are bounded by [`MAX_LINE`], including CRLF.
/// Malformed and overlong commands are error items. EOF inside a command
/// is terminal. The legacy [`CommandDecoder`] keeps its feed-time dropping
/// and larger buffer; it is not a wrapper around this decoder.
#[derive(Clone, Debug)]
pub struct Commands {
    lines: ControlLines,
}
impl Commands {
    /// Creates a command reader with a capacity of [`MAX_LINE`].
    pub fn new() -> Self {
        Self { lines: ControlLines::new() }
    }
}
impl Default for Commands {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for Commands {
    type Item = Result<Command, CommandError>;
    type Error = DecodeError;
    const NAME: &'static str = "FTP commands";

    fn capacity(&self) -> usize {
        MAX_LINE
    }
    fn held(&self) -> usize {
        self.lines.partial.len()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, DecodeError> {
        Ok(match self.lines.decode(input, eof)? {
            Step::Item(line, n) => Step::Item(line.and_then(|line| Command::parse(&line)), n),
            Step::Skip(n) => Step::Skip(n),
            Step::Need => Step::Need,
            Step::End => Step::End,
        })
    }
}

/// Reads and assembles control replies through [`super::codec::Lines`].
///
/// CRLF and bare LF are accepted under [`MAX_LINE`]. Assemblies retain
/// at most [`MAX_REPLY_LINES`] lines and [`MAX_REPLY_BYTES`] text bytes.
/// A malformed first line is an error item. Invalid text inside an open
/// reply or an overlong line ends framing. Too many reply lines produce
/// one error item at the matching final line. EOF in an assembly is
/// [`DecodeError::Incomplete`]. The legacy [`ReplyDecoder`] stays separate
/// to preserve its repeated errors and fatal first-line syntax errors.
#[derive(Clone, Debug)]
pub struct Replies {
    lines: ControlLines,
    builder: Builder,
    held: usize,
}
impl Replies {
    /// Creates a reply reader with a capacity of [`MAX_LINE`].
    pub fn new() -> Self {
        Self { lines: ControlLines::new(), builder: Builder::default(), held: 0 }
    }
}
impl Default for Replies {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for Replies {
    type Item = Result<Reply, ReplyError>;
    type Error = DecodeError;
    const NAME: &'static str = "FTP replies";

    fn capacity(&self) -> usize {
        MAX_LINE
    }
    fn held(&self) -> usize {
        self.held.saturating_add(self.lines.partial.len())
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, DecodeError> {
        match self.lines.decode(input, eof)? {
            Step::Item(Ok(line), n) => {
                let open = self.builder.open.is_some();
                let result = self.builder.take(&line);
                // Each line is visited once; do not rescan the assembly.
                self.held = match &self.builder.open {
                    Some((_, _, false)) => self.held.saturating_add(line.len()),
                    _ => 0,
                };
                match result {
                    Ok(Some(reply)) => Ok(Step::Item(Ok(reply), n)),
                    Ok(None) => Ok(Step::Skip(n)),
                    Err(e) if !open || e == ReplyError::TooManyLines => Ok(Step::Item(Err(e), n)),
                    Err(e) => Err(DecodeError::Reply(e)),
                }
            }
            Step::Item(Err(_), _) => Err(DecodeError::Reply(ReplyError::LineTooLong)),
            Step::Need if eof && self.builder.open.is_some() => Err(DecodeError::Incomplete),
            Step::Need => Ok(Step::Need),
            Step::Skip(n) => Ok(Step::Skip(n)),
            Step::End => Ok(Step::End),
        }
    }
}

impl Wire for Command {
    type ParseError = CommandParseError;
    type WriteError = WriteError;

    /// Reads exactly one control command, accepting CRLF or bare LF.
    /// Overlong lines are refused before checking for trailing bytes.
    fn parse(mut bytes: &[u8]) -> Result<Self, CommandParseError> {
        let mut decoder = Commands::new();
        loop {
            match decoder
                .decode(bytes, true)
                .map_err(|_| CommandParseError::Incomplete)?
            {
                Step::Item(Err(e), _) => return Err(CommandParseError::Command(e)),
                Step::Item(Ok(command), used) if used == bytes.len() => return Ok(command),
                Step::Item(_, _) => return Err(CommandParseError::Trailing),
                Step::Skip(used) => {
                    bytes = bytes.get(used..).ok_or(CommandParseError::Incomplete)?
                }
                Step::Need | Step::End => return Err(CommandParseError::Incomplete),
            }
        }
    }
    /// Appends a command with CRLF, leaving `out` unchanged on error.
    /// Refuses lowercase verbs that the parser would uppercase.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        if self.verb.bytes().any(|b| b.is_ascii_lowercase()) {
            return Err(WriteError::Verb);
        }
        let bytes = self.to_bytes()?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Reply {
    type ParseError = ReplyParseError;
    type WriteError = ReplyWriteError;

    /// Reads exactly one reply accepted by [`Replies`]. CRLF and bare LF
    /// are accepted; incomplete replies and trailing bytes are errors.
    fn parse(mut bytes: &[u8]) -> Result<Self, ReplyParseError> {
        let mut decoder = Replies::new();
        loop {
            match decoder.decode(bytes, true).map_err(|e| match e {
                DecodeError::Incomplete => ReplyParseError::Incomplete,
                DecodeError::Reply(e) => ReplyParseError::Reply(e),
            })? {
                Step::Item(Err(e), _) => return Err(ReplyParseError::Reply(e)),
                Step::Item(Ok(reply), used) if used == bytes.len() => return Ok(reply),
                Step::Item(_, _) => return Err(ReplyParseError::Trailing),
                Step::Skip(used) => bytes = bytes.get(used..).ok_or(ReplyParseError::Incomplete)?,
                Step::Need | Step::End => return Err(ReplyParseError::Incomplete),
            }
        }
    }

    /// Appends the reply's text verbatim, with code prefixes and CRLF.
    /// Refuses text that would not read back unchanged before touching
    /// `out`. The legacy [`Reply::to_bytes`] still clips and pads text.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), ReplyWriteError> {
        let count = self.lines.len();
        if count == 0 || count > MAX_REPLY_LINES {
            return Err(ReplyWriteError);
        }
        for (i, line) in self.lines.iter().enumerate() {
            let middle = i != 0 && i != count - 1;
            let limit = if middle { MAX_CONTENT } else { MAX_REPLY_TEXT };
            if line.len() > limit
                || line.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
                || (middle && ends(line, self.code))
            {
                return Err(ReplyWriteError);
            }
        }
        let code = self.code.get().to_string();
        for (i, line) in self.lines.iter().enumerate() {
            if i == 0 || i == count - 1 {
                out.extend_from_slice(code.as_bytes());
                out.push(if i == 0 && count > 1 { b'-' } else { b' ' });
            }
            push_line(out, line);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;

    /// Commands from `stream`, fed in pieces of at most `size` bytes and
    /// taken out after each feed.
    fn commands_in(stream: &[u8], size: usize) -> Vec<Result<Command, CommandError>> {
        let mut d = CommandDecoder::new();
        let mut out = Vec::new();
        for mut chunk in stream.chunks(size.max(1)) {
            while !chunk.is_empty() {
                let n = d.feed(chunk);
                chunk = &chunk[n..];
                assert!(d.buffered() <= MAX_BUFFERED);
                let before = out.len();
                out.extend(std::iter::from_fn(|| d.next_command()));
                assert!(n > 0 || out.len() > before, "no progress");
            }
        }
        out
    }

    fn commands(stream: &[u8]) -> Vec<Result<Command, CommandError>> {
        commands_in(stream, stream.len())
    }

    fn commands_bytewise(stream: &[u8]) -> Vec<Result<Command, CommandError>> {
        commands_in(stream, 1)
    }

    /// Replies up to and including the first error that stops the stream.
    fn replies(stream: &[u8], bytewise: bool) -> Vec<Result<Reply, ReplyError>> {
        let mut d = ReplyDecoder::new();
        let mut out = Vec::new();
        let size = if bytewise { 1 } else { stream.len().max(1) };
        for mut chunk in stream.chunks(size) {
            while !chunk.is_empty() {
                let n = d.feed(chunk);
                chunk = &chunk[n..];
                assert!(d.buffered() <= MAX_BUFFERED);
                let before = out.len();
                while let Some(r) = d.next_reply() {
                    let stop = matches!(r, Err(e) if e != ReplyError::TooManyLines);
                    out.push(r);
                    if stop {
                        return out;
                    }
                }
                assert!(n > 0 || out.len() > before, "no progress");
            }
        }
        out
    }

    fn request(line: &str) -> Result<Request, ArgumentError> {
        Request::from_command(&Command::parse(line.as_bytes()).unwrap())
    }

    fn reply_of(bytes: &[u8]) -> Reply {
        let (reply, used) = Reply::parse(bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        reply
    }

    // Examples from RFC 959, 2428, 2389 and 3659.

    #[test]
    fn rfc959_commands() {
        assert_eq!(request("USER anonymous"), Ok(Request::User("anonymous".into())));
        assert_eq!(request("user anonymous"), Ok(Request::User("anonymous".into())));
        assert_eq!(request("PASS guest@"), Ok(Request::Pass("guest@".into())));
        // RFC 959, section 4.1.2: a PORT argument, port 24 * 256 + 131.
        let to = SocketAddrV4::new(Ipv4Addr::new(132, 235, 1, 2), 6275);
        assert_eq!(request("PORT 132,235,1,2,24,131"), Ok(Request::Port(to)));
        assert_eq!(Request::Port(to).to_bytes().unwrap(), b"PORT 132,235,1,2,24,131\r\n");
        assert_eq!(request("TYPE A N"), Ok(Request::Type(DataType::Ascii(Some(Format::NonPrint)))));
        assert_eq!(request("TYPE i"), Ok(Request::Type(DataType::Image)));
        assert_eq!(request("TYPE L 8"), Ok(Request::Type(DataType::Local(NonZeroU8::new(8).unwrap()))));
        assert_eq!(request("STRU R"), Ok(Request::Stru(Structure::Record)));
        assert_eq!(request("MODE B"), Ok(Request::Mode(TransferMode::Block)));
        assert_eq!(request("RETR dir/file name.txt"), Ok(Request::Retr("dir/file name.txt".into())));
        assert_eq!(request("LIST"), Ok(Request::List(None)));
        assert_eq!(request("LIST -la"), Ok(Request::List(Some("-la".into()))));
        assert_eq!(request("XPWD"), Ok(Request::Pwd));
        assert_eq!(request("XMKD new"), Ok(Request::Mkd("new".into())));
        assert_eq!(request("SITE CHMOD 755 x"), Ok(Request::Site("CHMOD 755 x".into())));
        assert_eq!(request("AUTH TLS"), Ok(Request::Other(Command { verb: "AUTH".into(), arg: Some("TLS".into()) })));
    }

    #[test]
    fn rfc3659_and_rfc2389_commands() {
        assert_eq!(request("SIZE /pub/file"), Ok(Request::Size("/pub/file".into())));
        assert_eq!(request("MDTM file"), Ok(Request::Mdtm("file".into())));
        assert_eq!(request("REST 1024"), Ok(Request::Rest("1024".into())));
        assert_eq!(request("MLSD"), Ok(Request::Mlsd(None)));
        assert_eq!(request("MLST x"), Ok(Request::Mlst(Some("x".into()))));
        assert_eq!(request("FEAT"), Ok(Request::Feat));
        assert_eq!(request("OPTS UTF8 ON"), Ok(Request::Opts("UTF8 ON".into())));
    }

    #[test]
    fn rfc2428_addresses() {
        let v4: SocketAddr = "132.235.1.2:6275".parse().unwrap();
        assert_eq!(parse_eprt("|1|132.235.1.2|6275|"), Ok(v4));
        let v6: SocketAddr = "[1080::8:800:200c:417a]:5282".parse().unwrap();
        assert_eq!(parse_eprt("|2|1080::8:800:200C:417A|5282|"), Ok(v6));
        // Any printable delimiter.
        assert_eq!(parse_eprt("!1!132.235.1.2!6275!"), Ok(v4));
        assert_eq!(write_eprt(v4), "|1|132.235.1.2|6275|");
        assert_eq!(request("EPRT |2|1080::8:800:200C:417A|5282|"), Ok(Request::Eprt(v6)));
        assert_eq!(request("EPSV"), Ok(Request::Epsv(None)));
        assert_eq!(request("EPSV 2"), Ok(Request::Epsv(Some(EpsvArg::Protocol(2)))));
        assert_eq!(request("EPSV all"), Ok(Request::Epsv(Some(EpsvArg::All))));
        // RFC 2428, section 3: the reply to EPSV.
        let r = reply_of(b"229 Entering Extended Passive Mode (|||6446|)\r\n");
        assert_eq!(r.extended_passive_port(), Ok(6446));
        assert_eq!(Reply::extended_passive(6446), r);
        assert_eq!(reply_of(b"229 ok (!!!21!)\r\n").extended_passive_port(), Ok(21));
    }

    #[test]
    fn passive_replies() {
        let r = reply_of(b"227 Entering Passive Mode (192,168,1,2,19,137).\r\n");
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 19 * 256 + 137);
        assert_eq!(r.passive_address(), Ok(addr));
        assert_eq!(Reply::passive(addr), r);
        // Other wordings, as RFC 1123 warns.
        assert_eq!(reply_of(b"227 =192,168,1,2,19,137\n").passive_address(), Ok(addr));
        assert_eq!(reply_of(b"227 Passive 192,168,1,2,19,137 ok\r\n").passive_address(), Ok(addr));
        assert_eq!(reply_of(b"227 Passive\r\n").passive_address(), Err(AddressError::Syntax));
        assert_eq!(reply_of(b"227 (1,2,3)\r\n").passive_address(), Err(AddressError::Syntax));
        assert_eq!(reply_of(b"200 (1,2,3,4,5,6)\r\n").passive_address(), Err(AddressError::Code));
    }

    #[test]
    fn rfc959_multiline_reply() {
        // RFC 959, section 4.2.
        let bytes = b"123-First line\r\nSecond line\r\n  234 A line beginning with numbers\r\n123 The last line\r\n";
        let r = reply_of(bytes);
        assert_eq!(r.code.get(), 123);
        assert_eq!(r.lines, ["First line", "Second line", "  234 A line beginning with numbers", "The last line"]);
        assert_eq!(r.to_bytes(), bytes);
        assert_eq!(reply_of(b"220 Service ready\r\n"), Reply::new(code::READY, "Service ready"));
        // A code with no text, and a bare LF.
        assert_eq!(reply_of(b"200\n"), Reply::new(code::OK, ""));
        // A line in the middle with another code is text.
        let r = reply_of(b"211-a\r\n200 b\r\n211-c\r\n211 d\r\n");
        assert_eq!(r.lines, ["a", "200 b", "211-c", "d"]);
    }

    #[test]
    fn rfc2389_feat() {
        let bytes = b"211-Extensions supported:\r\n MLST size*;create;modify*;perm;media-type\r\n SIZE\r\n COMPRESSION\r\n MDTM\r\n211 END\r\n";
        let r = reply_of(bytes);
        let f = r.features().unwrap();
        let names: Vec<_> = f.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["MLST", "SIZE", "COMPRESSION", "MDTM"]);
        assert_eq!(f[0].params.as_deref(), Some("size*;create;modify*;perm;media-type"));
        assert_eq!(f[1].params, None);
        assert_eq!(Reply::feature_list(&f).features(), Ok(f));
        // No features.
        assert_eq!(reply_of(b"211 no-features\r\n").features(), Ok(vec![]));
        assert_eq!(Reply::feature_list(&[]).to_bytes(), b"211 No features.\r\n");
        // Errors.
        assert_eq!(reply_of(b"500 no\r\n").features(), Err(FeatureError::Code(code::SYNTAX_ERROR)));
        assert_eq!(reply_of(b"211-x\r\nSIZE\r\n211 e\r\n").features(), Err(FeatureError::Line));
        assert_eq!(reply_of(b"211-x\r\n  SIZE\r\n211 e\r\n").features(), Err(FeatureError::Line));
        assert_eq!(reply_of(b"211-x\r\n \x01\r\n211 e\r\n").features(), Err(FeatureError::Line));
        // Names keep their case, and a space with nothing after it is no
        // parameters.
        let f = reply_of(b"211-x\r\n mdtm \r\n211 e\r\n").features().unwrap();
        assert_eq!(f, [Feature { name: "mdtm".into(), params: None }]);
    }

    #[test]
    fn request_round_trips() {
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 2121);
        let all = vec![
            Request::User("u".into()),
            Request::Pass(String::new()),
            Request::Acct("a".into()),
            Request::Cwd("/x y".into()),
            Request::Cdup,
            Request::Smnt("m".into()),
            Request::Rein,
            Request::Quit,
            Request::Port(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 65535)),
            Request::Pasv,
            Request::Type(DataType::Ascii(None)),
            Request::Type(DataType::Ascii(Some(Format::Telnet))),
            Request::Type(DataType::Ebcdic(Some(Format::CarriageControl))),
            Request::Type(DataType::Ebcdic(None)),
            Request::Type(DataType::Image),
            Request::Type(DataType::Local(NonZeroU8::MIN)),
            Request::Type(DataType::Local(NonZeroU8::MAX)),
            Request::Stru(Structure::File),
            Request::Stru(Structure::Page),
            Request::Mode(TransferMode::Stream),
            Request::Mode(TransferMode::Compressed),
            Request::Retr("r".into()),
            Request::Stor("s".into()),
            Request::Stou,
            Request::Appe("a".into()),
            Request::Allo("100 R 10".into()),
            Request::Allo("5".into()),
            Request::Rest("0".into()),
            Request::Rnfr("a".into()),
            Request::Rnto("b".into()),
            Request::Abor,
            Request::Dele("d".into()),
            Request::Rmd("d".into()),
            Request::Mkd("d".into()),
            Request::Pwd,
            Request::List(None),
            Request::List(Some(String::new())),
            Request::Nlst(Some("*.txt".into())),
            Request::Site("HELP".into()),
            Request::Syst,
            Request::Stat(None),
            Request::Help(Some("RETR".into())),
            Request::Noop,
            Request::Eprt(v6),
            Request::Eprt("1.2.3.4:0".parse().unwrap()),
            Request::Epsv(None),
            Request::Epsv(Some(EpsvArg::Protocol(1))),
            Request::Epsv(Some(EpsvArg::All)),
            Request::Feat,
            Request::Opts("MLST type;".into()),
            Request::Mdtm("m".into()),
            Request::Size("s".into()),
            Request::Mlst(None),
            Request::Mlsd(Some("/".into())),
            Request::Other(Command::new("CCC", None)),
            // RFC 2640, section 3.1: CR in a pathname, and LF after it.
            Request::Dele("a\rb".into()),
            Request::Stor("foo\r\nboo.bar".into()),
            Request::Rnto("end\r".into()),
        ];
        let stream: Vec<u8> = all.iter().flat_map(|r| r.to_bytes().unwrap()).collect();
        let back: Vec<_> = commands(&stream).into_iter().map(|c| Request::from_command(&c.unwrap()).unwrap()).collect();
        assert_eq!(back, all);
    }

    #[test]
    fn command_errors() {
        assert_eq!(Command::parse(b""), Err(CommandError::Empty));
        assert_eq!(Command::parse(b" USER x"), Err(CommandError::Verb));
        assert_eq!(Command::parse(b"USERS x"), Err(CommandError::Verb));
        assert_eq!(Command::parse(b"US3R x"), Err(CommandError::Verb));
        assert_eq!(Command::parse(b"\xffABOR"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"ABOR\xff"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"ABOR\xff\xfb"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"RETR \xff\xff"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"RETR a\rb"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"RETR a\r"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"RETR a\0b"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"RETR a\nb"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"RETR \r\0\0"), Err(CommandError::Text));
        assert_eq!(Command::parse(&[b'A'; MAX_LINE - 1]), Err(CommandError::LineTooLong));
        // Empty and lowercase arguments are kept as sent.
        assert_eq!(Command::parse(b"retr "), Ok(Command::new("RETR", Some(""))));
    }

    #[test]
    fn argument_errors() {
        use ArgumentError as E;
        assert_eq!(request("USER"), Err(E::Missing));
        assert_eq!(request("RETR"), Err(E::Missing));
        assert_eq!(request("PORT"), Err(E::Missing));
        assert_eq!(request("EPRT"), Err(E::Missing));
        assert_eq!(request("TYPE"), Err(E::Missing));
        assert_eq!(request("PASV x"), Err(E::Unexpected));
        assert_eq!(request("QUIT "), Err(E::Unexpected));
        assert_eq!(request("TYPE X"), Err(E::Invalid));
        assert_eq!(request("TYPE A X"), Err(E::Invalid));
        assert_eq!(request("TYPE I N"), Err(E::Invalid));
        assert_eq!(request("TYPE L"), Err(E::Invalid));
        assert_eq!(request("TYPE L 256"), Err(E::Invalid));
        // RFC 959, section 5.3.2: a byte size is from 1 to 255.
        assert_eq!(request("TYPE L 0"), Err(E::Invalid));
        assert_eq!(request("TYPE A N X"), Err(E::Invalid));
        assert_eq!(request("STRU X"), Err(E::Invalid));
        assert_eq!(request("MODE X"), Err(E::Invalid));
        assert_eq!(request("EPSV 3x"), Err(E::Invalid));
        assert_eq!(request("EPSV 65536"), Err(E::Invalid));
        assert_eq!(request("PORT 1,2,3,4,5"), Err(E::Address(AddressError::Syntax)));
        // RFC 959, section 5.3.2, and RFC 2389, section 4.
        for bad in
            ["ALLO xyz", "ALLO ", "ALLO 1 R", "ALLO 1 X 2", "ALLO 1  R 2", "REST a b", "REST ", "OPTS ", "OPTS  x"]
        {
            assert_eq!(request(bad), Err(E::Invalid), "{bad:?}");
        }
        assert_eq!(request("ALLO 10 r 2"), Ok(Request::Allo("10 r 2".into())));
        assert_eq!(request("REST !x~"), Ok(Request::Rest("!x~".into())));
        assert_eq!(request("OPTS UTF8"), Ok(Request::Opts("UTF8".into())));
        assert_eq!(request("EPRT |3|1.2.3.4|5|"), Err(E::Address(AddressError::Family)));
    }

    #[test]
    fn address_errors() {
        use AddressError::*;
        for bad in ["", "1,2,3,4,5", "1,2,3,4,5,6,", "256,0,0,0,0,0", "1,2,3,4,5,0006", "1, 2,3,4,5,6", "+1,2,3,4,5,6"]
        {
            assert_eq!(parse_port(bad), Err(Syntax), "{bad:?}");
        }
        assert_eq!(parse_port("001,2,3,4,5,6"), Ok(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 0x0506)));
        for bad in [
            "",
            " 1 1.2.3.4 5 ",
            "|1|1.2.3.4|5",
            "|1|1.2.3.4|5|x",
            "|1|1.2.3.4|5||",
            "|1|::1|5|",
            "|2|1.2.3.4|5|",
            "|1|1.2.3.4|65536|",
            "|1|1.2.3.4||",
            "|x|1.2.3.4|5|",
            "|1|01.2.3.4|5|",
        ] {
            assert_eq!(parse_eprt(bad), Err(Syntax), "{bad:?}");
        }
        assert_eq!(parse_eprt("|0|1.2.3.4|5|"), Err(Family));
        assert_eq!(parse_eprt("|99999|1.2.3.4|5|"), Err(Family));
        // RFC 2428, section 2: an unknown family gets 522, whatever its
        // address and port look like.
        assert_eq!(parse_eprt("|123456|1.2.3.4|5|"), Err(Family));
        assert_eq!(parse_eprt("|3|zone:4|x|"), Err(Family));
        for bad in ["229 none", "229 ()", "229 (|||x|)", "229 (||1|5|)", "229 (|||5|", "229 (|||5)", "229 ( || 5|)"] {
            let r = reply_of(format!("{bad}\r\n").as_bytes());
            assert_eq!(r.extended_passive_port(), Err(Syntax), "{bad:?}");
        }
        assert_eq!(Reply::new(code::OK, "(|||5|)").extended_passive_port(), Err(Code));
        // A reply built by hand with no lines.
        let empty = Reply { code: code::PASSIVE, lines: vec![] };
        assert_eq!(empty.passive_address(), Err(Syntax));
        let empty = Reply { code: code::EXTENDED_PASSIVE, lines: vec![] };
        assert_eq!(empty.extended_passive_port(), Err(Syntax));
        // `)` as the delimiter (RFC 2428, section 3).
        let r = reply_of(b"229 Entering Extended Passive Mode ()))6446))\r\n");
        assert_eq!(r.extended_passive_port(), Ok(6446));
        // A scoped IPv6 address loses its scope.
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5, 7, 9));
        assert_eq!(parse_eprt(&write_eprt(scoped)), Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5)));
    }

    #[test]
    fn reply_errors() {
        assert_eq!(Reply::parse(b"600 x\r\n"), Err(ReplyError::Syntax));
        assert_eq!(Reply::parse(b"099 x\r\n"), Err(ReplyError::Syntax));
        assert_eq!(Reply::parse(b"20 x\r\n"), Err(ReplyError::Syntax));
        assert_eq!(Reply::parse(b"200x\r\n"), Err(ReplyError::Syntax));
        assert_eq!(Reply::parse(b"\r\n"), Err(ReplyError::Syntax));
        assert_eq!(Reply::parse(b"200 \xff\r\n"), Err(ReplyError::Text));
        assert_eq!(Reply::parse(b"200 a\rb\r\n"), Err(ReplyError::Text));
        assert_eq!(Reply::parse(b"200-a\r\nb\0\r\n"), Err(ReplyError::Text));
        let long = [vec![b'2', b'0', b'0', b' '], vec![b'x'; MAX_LINE], b"\r\n".to_vec()].concat();
        assert_eq!(Reply::parse(&long), Err(ReplyError::LineTooLong));
        // Too many lines.
        let mut many = b"200-first\r\n".to_vec();
        for _ in 0..MAX_REPLY_LINES {
            many.extend_from_slice(b"x\r\n");
        }
        many.extend_from_slice(b"200 last\r\n");
        assert_eq!(Reply::parse(&many), Err(ReplyError::TooManyLines));
        // The most lines allowed.
        let mut most = b"200-first\r\n".to_vec();
        for _ in 0..MAX_REPLY_LINES - 2 {
            most.extend_from_slice(b"x\r\n");
        }
        most.extend_from_slice(b"200 last\r\n");
        assert_eq!(reply_of(&most).lines.len(), MAX_REPLY_LINES);
        // The decoder stays broken.
        let mut d = ReplyDecoder::new();
        assert_eq!(d.feed(b"200 ok\r\nhello\r\n200 ok\r\n"), 23);
        assert_eq!(d.next_reply(), Some(Ok(Reply::new(code::OK, "ok"))));
        assert_eq!(d.next_reply(), Some(Err(ReplyError::Syntax)));
        assert_eq!(d.feed(b"200 ok\r\n"), 8);
        assert_eq!(d.next_reply(), Some(Err(ReplyError::Syntax)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn line_lengths() {
        // The longest line allowed, with CRLF and with LF alone.
        let verb = b"RETR ";
        let fits = [verb.to_vec(), vec![b'x'; MAX_LINE - 2 - verb.len()], b"\r\n".to_vec()].concat();
        assert_eq!(fits.len(), MAX_LINE);
        let fits_lf = [&fits[..fits.len() - 2], b"\n"].concat();
        let over_lf = [&fits[..fits.len() - 2], b"x\n"].concat();
        let over = [&fits[..fits.len() - 2], b"x\r\n"].concat();
        let far_over = [vec![b'x'; 3 * MAX_LINE], b"\r\n".to_vec()].concat();
        let next = b"NOOP\r\n";
        for (line, ok) in [(&fits, true), (&fits_lf, true), (&over_lf, false), (&over, false), (&far_over, false)] {
            let stream = [line.as_slice(), next].concat();
            for got in [commands(&stream), commands_bytewise(&stream)] {
                assert_eq!(got.len(), 2);
                assert_eq!(got[0].is_ok(), ok);
                if !ok {
                    assert_eq!(got[0], Err(CommandError::LineTooLong));
                }
                assert_eq!(got[1], Ok(Command::new("NOOP", None)));
            }
        }
        // A long line with no end yet holds no more than a line's bytes.
        let mut d = CommandDecoder::new();
        for _ in 0..3 * MAX_LINE {
            assert_eq!(d.feed(b"x"), 1);
            while d.next_command().is_some() {}
            assert!(d.buffered() <= MAX_LINE);
        }
    }

    #[test]
    fn truncated_prefixes() {
        let stream: &[u8] = b"USER anonymous\r\nPORT 1,2,3,4,5,6\r\nRETR a b\r\n";
        let all = commands(stream);
        assert_eq!(all.len(), 3);
        for n in 0..stream.len() {
            let got = commands(&stream[..n]);
            let lines = stream[..n].iter().filter(|&&c| c == b'\n').count();
            assert_eq!(got, all[..lines], "{n} bytes");
        }
        let reply: &[u8] = b"211-Extensions supported:\r\n SIZE\r\n MDTM\r\n211 End\r\n";
        reply_of(reply);
        for n in 0..reply.len() {
            assert_eq!(Reply::parse(&reply[..n]), Ok(None), "{n} bytes");
            assert_eq!(replies(&reply[..n], false), vec![], "{n} bytes");
            assert_eq!(replies(&reply[..n], true), vec![], "{n} bytes");
        }
    }

    #[test]
    fn writers_clean_and_cap() {
        // CR LF cannot start another command: it is sent as CR NUL LF.
        let c = Request::Retr("a\r\nDELE b".into());
        let got = commands(&c.to_bytes().unwrap());
        assert_eq!(got, [Ok(Command::new("RETR", Some("a\r\nDELE b")))]);
        // What cannot be sent is refused, not changed.
        assert_eq!(Request::Dele("a\nb".into()).to_bytes(), Err(WriteError::Text));
        assert_eq!(Request::Dele("a\0b".into()).to_bytes(), Err(WriteError::Text));
        assert_eq!(Command::new("x-y z", None).to_bytes(), Err(WriteError::Verb));
        assert_eq!(Command::new("12", Some("a")).to_bytes(), Err(WriteError::Verb));
        assert_eq!(Command::new("", None).to_bytes(), Err(WriteError::Verb));
        assert_eq!(Command::new("abcdef", None).to_bytes(), Err(WriteError::Verb));
        assert_eq!(Command::new("retr", Some("x")).to_bytes().unwrap(), b"RETR x\r\n");
        assert_eq!(Request::Allo("xyz".into()).to_bytes(), Err(WriteError::Argument(ArgumentError::Invalid)));
        assert_eq!(
            Request::Other(Command::new("RETR", None)).to_bytes(),
            Err(WriteError::Argument(ArgumentError::Missing))
        );
        // Long arguments are refused, the longest that fits is kept whole,
        // and a CR counts twice.
        assert_eq!(Request::Stor("é".repeat(MAX_LINE)).to_bytes(), Err(WriteError::LineTooLong));
        assert_eq!(Request::Stor("x".repeat(64 << 20)).to_bytes(), Err(WriteError::LineTooLong));
        let fits = "x".repeat(MAX_LINE - 7);
        assert_eq!(Request::Stor(fits.clone()).to_bytes().unwrap().len(), MAX_LINE);
        assert_eq!(commands(&Request::Stor(fits.clone()).to_bytes().unwrap()), [Ok(Command::new("STOR", Some(&fits)))]);
        let cr = format!("{}\r", &fits[1..]);
        assert_eq!(Request::Stor(cr).to_bytes(), Err(WriteError::LineTooLong));
        // Reply lines.
        let r = Reply {
            code: code::HELP,
            lines: vec!["a\r\n214 x".into(), "214 end".into(), "214".into(), "é".repeat(MAX_LINE), "z".into()],
        };
        let bytes = r.to_bytes();
        assert!(bytes.split(|&c| c == b'\n').all(|l| l.len() < MAX_LINE));
        let back = reply_of(&bytes);
        assert_eq!(back.lines[0], "a214 x");
        assert_eq!(back.lines[1], " 214 end");
        assert_eq!(back.lines[2], " 214");
        assert_eq!(back.lines.len(), 5);
        // RFC 959, section 4.2: any middle line starting with three digits
        // is padded, not only one with the reply's own code.
        let r =
            Reply { code: code::READY, lines: vec!["a".into(), "230 Logged in".into(), "999-x".into(), "end".into()] };
        assert_eq!(r.to_bytes(), b"220-a\r\n 230 Logged in\r\n 999-x\r\n220 end\r\n");
        let r = Reply { code: code::READY, lines: vec!["a".into(), "2\r30 x".into(), "end".into()] };
        assert_eq!(r.to_bytes(), b"220-a\r\n 230 x\r\n220 end\r\n");
        // Too many lines keep the first ones and the last.
        let r = Reply { code: code::HELP, lines: (0..MAX_REPLY_LINES + 5).map(|i| i.to_string()).collect() };
        let back = reply_of(&r.to_bytes());
        assert_eq!(back.lines.len(), MAX_REPLY_LINES);
        assert_eq!(back.lines.last().map(String::as_str), Some("1028"));
        // No lines, and one line too long.
        assert_eq!(Reply { code: code::OK, lines: vec![] }.to_bytes(), b"200 \r\n");
        let one = Reply::new(code::OK, &"x".repeat(2 * MAX_LINE));
        assert_eq!(one.to_bytes().len(), MAX_LINE);
        reply_of(&one.to_bytes());
        // Features: bad names and parameters are cleaned or left out, and
        // the list capped.
        let f = vec![
            Feature { name: "a b".into(), params: Some("p\r\nq\x01\té".into()) },
            Feature { name: " ".into(), params: None },
            Feature { name: "X".into(), params: Some(String::new()) },
            Feature { name: "Y".into(), params: Some("\x01".into()) },
            Feature { name: "x".repeat(2 * MAX_LINE), params: Some("p".repeat(2 * MAX_LINE)) },
        ];
        let r = Reply::feature_list(&f);
        assert!(r.lines.iter().all(|l| l.len() <= MAX_CONTENT));
        assert_eq!(r.to_bytes(), Reply::parse(&r.to_bytes()).unwrap().unwrap().0.to_bytes());
        let got = r.features().unwrap();
        assert_eq!(
            got[..3],
            [
                Feature { name: "ab".into(), params: Some("pq\t".into()) },
                Feature { name: "X".into(), params: None },
                Feature { name: "Y".into(), params: None },
            ]
        );
        assert_eq!(got[3].name.len(), MAX_CONTENT - 1);
        assert_eq!(got[3].params, None);
        let many: Vec<_> = (0..MAX_REPLY_LINES).map(|i| Feature { name: format!("F{i}"), params: None }).collect();
        let r = Reply::feature_list(&many);
        assert_eq!(r.features().unwrap().len(), MAX_FEATURES);
        assert_eq!(reply_of(&r.to_bytes()), r);
    }

    #[test]
    fn reply_codes() {
        assert_eq!(ReplyCode::new(99), None);
        assert_eq!(ReplyCode::new(600), None);
        assert_eq!(ReplyCode::new(100).map(ReplyCode::get), Some(100));
        assert!(code::OPENING_DATA.is_preliminary());
        assert!(code::OK.is_completion());
        assert!(code::NEED_PASSWORD.is_intermediate());
        assert!(code::CANT_OPEN_DATA.is_transient_failure());
        assert!(code::FILE_UNAVAILABLE.is_permanent_failure());
        assert_eq!(code::READY.to_string(), "220");
    }

    #[test]
    fn decoders_split_streams() {
        let stream = b"USER a\r\n\r\nPASV\nbad1\r\nQUIT\r\n";
        let want = vec![
            Ok(Command::new("USER", Some("a"))),
            Err(CommandError::Empty),
            Ok(Command::new("PASV", None)),
            Err(CommandError::Verb),
            Ok(Command::new("QUIT", None)),
        ];
        assert_eq!(commands(stream), want);
        assert_eq!(commands_bytewise(stream), want);
        let stream = b"220 hi\r\n150-a\r\n b\r\n150 c\r\n226 done\n";
        let got = replies(stream, true);
        assert_eq!(got, replies(stream, false));
        assert_eq!(got.len(), 3);
        assert_eq!(got[1].as_ref().unwrap().lines, ["a", " b", "c"]);
    }

    #[test]
    fn decoders_take_many_short_lines_in_linear_time() {
        let started = std::time::Instant::now();
        let stream = b"NOOP\r\n".repeat(500_000);
        let got = commands(&stream);
        assert_eq!(got.len(), 500_000);
        assert!(got.iter().all(|c| *c == Ok(Command::new("NOOP", None))));
        let stream = b"200 ok\r\n".repeat(500_000);
        let got = replies(&stream, false);
        assert_eq!(got.len(), 500_000);
        assert!(got.iter().all(|r| *r == Ok(Reply::new(code::OK, "ok"))));
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn decoders_skip_long_lines_after_short_ones() {
        // Lines taken out leave room for a long line to be noticed and
        // skipped, fed whole or in pieces.
        let long = [b"NOOP\r\n".repeat(10), vec![b'x'; 2 * MAX_LINE], b"\r\nQUIT\r\n".to_vec()].concat();
        let mut want = vec![Ok(Command::new("NOOP", None)); 10];
        want.push(Err(CommandError::LineTooLong));
        want.push(Ok(Command::new("QUIT", None)));
        assert_eq!(commands(&long), want);
        assert_eq!(commands_bytewise(&long), want);
        for size in [7, 100, MAX_LINE - 1, MAX_LINE + 3] {
            assert_eq!(commands_in(&long, size), want, "chunks of {size}");
        }
    }

    /// A small deterministic generator, so the fuzz loop needs no crates.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }

        fn buffer(&mut self) -> Vec<u8> {
            const PIECES: &[&[u8]] = &[
                b"USER ",
                b"PORT ",
                b"EPRT ",
                b"EPSV",
                b"TYPE ",
                b"PASV",
                b"LIST",
                b"FEAT",
                b"QUIT",
                b"RETR ",
                b"211-",
                b"211 ",
                b"227 ",
                b"229 ",
                b"200",
                b"123-",
                b"123 ",
                b"\r\n",
                b"\n",
                b"\r",
                b" ",
                b"|",
                b",",
                b"(",
                b")",
                b"1",
                b"2",
                b"255",
                b"::1",
                b"1.2.3.4",
                b"A N",
                b"ALL",
                b"\0",
                b"\xff",
                b"\xc3\xa9",
                b"\xff\xf4\xff\xf2",
                b"\xff\xfb",
                b"\r\0",
                b"230 ",
                b"ALLO ",
                b"REST ",
            ];
            let n = self.below(40);
            let mut out = Vec::new();
            for _ in 0..n {
                match self.below(24) {
                    0 | 1 => out.push(self.next() as u8),
                    2 => out.extend(std::iter::repeat_n(b'x', self.below(3) * MAX_LINE / 2)),
                    _ => out.extend_from_slice(PIECES[self.below(PIECES.len())]),
                }
            }
            out
        }
    }

    /// `r` written and read back: the same but for a space in front of
    /// middle lines that start with three digits, and written the same
    /// again.
    fn same_reply(r: &Reply) {
        let bytes = r.to_bytes();
        let back = reply_of(&bytes);
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.code, r.code);
        assert_eq!(back.lines.len(), r.lines.len());
        for (i, (a, b)) in r.lines.iter().zip(&back.lines).enumerate() {
            let padded =
                i > 0 && i + 1 < r.lines.len() && a.bytes().take(3).all(|c| c.is_ascii_digit()) && a.len() >= 3;
            assert_eq!(*b, if padded { format!(" {a}") } else { a.clone() });
        }
    }

    // One test for each finding of the October 2026 review.

    #[test]
    fn feed_holds_at_most_max_buffered() {
        // One long line fed at once keeps only a line's bytes.
        let mut d = CommandDecoder::new();
        let big = vec![b'x'; 1 << 20];
        assert_eq!(d.feed(&big), big.len());
        assert!(d.buffered() <= MAX_LINE, "held {}", d.buffered());
        assert_eq!(d.next_command(), Some(Err(CommandError::LineTooLong)));
        assert_eq!(d.feed(b"yy\r\nNOOP\r\n"), 10);
        assert_eq!(d.next_command(), Some(Ok(Command::new("NOOP", None))));
        // Many lines fed without taking any out stop at MAX_BUFFERED.
        let mut d = CommandDecoder::new();
        let mut taken = 0;
        for _ in 0..100_000 {
            taken += d.feed(b"NOOP\r\n");
        }
        assert!(d.buffered() <= MAX_BUFFERED);
        assert_eq!(taken, d.buffered());
        // The same for replies, and a long line among short ones.
        let mut d = ReplyDecoder::new();
        let stream = [b"200 ok\r\n".repeat(MAX_BUFFERED), vec![b'x'; 3 * MAX_BUFFERED]].concat();
        let n = d.feed(&stream);
        assert!(n < stream.len());
        assert!(d.buffered() <= MAX_BUFFERED);
        assert_eq!(replies(&[b"200 a\r\n".as_slice(), &vec![b'x'; 1 << 20], b"\r\n"].concat(), false).len(), 2);
    }

    #[test]
    fn crnul_pathnames_round_trip() {
        // RFC 2640, section 3.1, its own example.
        assert_eq!(commands(b"STOR foo\r\0\nboo.bar\r\n"), [Ok(Command::new("STOR", Some("foo\r\nboo.bar")))]);
        assert_eq!(commands_bytewise(b"STOR foo\r\0\nboo.bar\r\n"), commands(b"STOR foo\r\0\nboo.bar\r\n"));
        assert_eq!(Request::Stor("foo\r\nboo.bar".into()).to_bytes().unwrap(), b"STOR foo\r\0\nboo.bar\r\n");
        let got = commands(&Request::Dele("a\rb".into()).to_bytes().unwrap());
        assert_eq!(got, [Ok(Command::new("DELE", Some("a\rb")))]);
        // A bare LF still ends a line.
        assert_eq!(commands(b"STOR a\nNOOP\r\n").len(), 2);
    }

    #[test]
    fn telnet_commands_are_dropped() {
        // RFC 959, section 4.1.3: IP and Synch before ABOR.
        assert_eq!(commands(b"\xff\xf4\xff\xf2ABOR\r\n"), [Ok(Command::new("ABOR", None))]);
        assert_eq!(commands(b"NO\xff\xfb\x01OP\r\n"), [Ok(Command::new("NOOP", None))]);
    }

    #[test]
    fn passive_helpers_read_multiline_replies() {
        let r = reply_of(b"227-Preparing\r\n227 Entering Passive Mode (127,0,0,1,19,137)\r\n");
        assert_eq!(r.passive_address(), Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 19 * 256 + 137)));
        let r = reply_of(b"229-Preparing (soon)\r\n229 Entering Extended Passive Mode (|||6446|)\r\n");
        assert_eq!(r.extended_passive_port(), Ok(6446));
    }

    #[test]
    fn too_many_lines_is_recoverable() {
        // RFC 1123, section 4.1.2.11.
        let mut s = b"200-first\r\n".to_vec();
        for _ in 0..2 * MAX_REPLY_LINES {
            s.extend_from_slice(b"x\r\n");
        }
        s.extend_from_slice(b"200 last\r\n220 next\r\n");
        let want = vec![Err(ReplyError::TooManyLines), Ok(Reply::new(code::READY, "next"))];
        assert_eq!(replies(&s, false), want);
        assert_eq!(replies(&s, true), want);
    }

    #[test]
    fn feature_names_keep_their_case() {
        let r = reply_of(b"211-x\r\n x-Custom a\tb\r\n211 End\r\n");
        let f = r.features().unwrap();
        assert_eq!(f, [Feature { name: "x-Custom".into(), params: Some("a\tb".into()) }]);
        assert_eq!(Reply::feature_list(&f).features(), Ok(f));
        // RFC 2389, section 2.1: parameters are TCHAR.
        assert_eq!(reply_of(b"211-x\r\n X \x01\r\n211 End\r\n").features(), Err(FeatureError::Line));
        assert_eq!(reply_of("211-x\r\n X é\r\n211 End\r\n".as_bytes()).features(), Err(FeatureError::Line));
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x5eed);
        for _ in 0..4000 {
            let data = rng.buffer();
            let whole = commands(&data);
            assert_eq!(whole, commands_bytewise(&data));
            // Chunks of random sizes, taking commands out after each.
            let mut d = CommandDecoder::new();
            let mut chunked = Vec::new();
            let mut rest = data.as_slice();
            while !rest.is_empty() {
                let (chunk, tail) = rest.split_at(1 + rng.below(rest.len().min(MAX_LINE + 9)));
                let mut chunk = chunk;
                while !chunk.is_empty() {
                    let n = d.feed(chunk);
                    chunk = &chunk[n..];
                    assert!(d.buffered() <= MAX_BUFFERED);
                    chunked.extend(std::iter::from_fn(|| d.next_command()));
                }
                rest = tail;
            }
            assert_eq!(chunked, whole);
            for c in whole.iter().flatten() {
                assert_eq!(commands(&c.to_bytes().unwrap()), [Ok(c.clone())]);
                if let Ok(r) = Request::from_command(c) {
                    let again = commands(&r.to_bytes().unwrap());
                    assert_eq!(again.len(), 1);
                    assert_eq!(Request::from_command(again[0].as_ref().unwrap()), Ok(r));
                }
            }
            // Commands built from any text are written so they read back,
            // or refused.
            let text = String::from_utf8_lossy(&data);
            let (verb, arg) = text.split_once(' ').unwrap_or((&text, ""));
            let built = Command::new(verb, Some(arg));
            if let Ok(bytes) = built.to_bytes() {
                let mut want = built.clone();
                want.verb.make_ascii_uppercase();
                assert_eq!(commands(&bytes), [Ok(want)]);
            }
            let got = replies(&data, false);
            assert_eq!(got, replies(&data, true));
            for r in got.iter().flatten() {
                same_reply(r);
                if let Ok(f) = r.features() {
                    assert_eq!(Reply::feature_list(&f).features(), Ok(f));
                }
                if let Ok(a) = r.passive_address() {
                    assert_eq!(Reply::passive(a).passive_address(), Ok(a));
                }
                if let Ok(p) = r.extended_passive_port() {
                    assert_eq!(Reply::extended_passive(p).extended_passive_port(), Ok(p));
                }
            }
            let _ = Reply::parse(&data);
            let _ = Command::parse(&data);
            let s = String::from_utf8_lossy(&data);
            if let Ok(a) = parse_port(&s) {
                assert_eq!(parse_port(&write_port(a)), Ok(a));
            }
            if let Ok(a) = parse_eprt(&s) {
                assert_eq!(parse_eprt(&write_eprt(a)), Ok(a));
            }
        }
    }
}
