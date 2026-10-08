//! FTP: reading and writing the control connection's commands and replies,
//! with no I/O.
//!
//! `Command`, `Request`, and `Reply` implement `Wire`. `Commands` and `Replies`
//! decode the two control directions. There is no login or transfer session,
//! `Service`, data-connection transport, or TLS handling.
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
//! A world that plays an FTP server pushes control bytes into
//! [`Stream<Commands>`](fictionet::stdlib::codec::Stream), reads each [`Request`], and
//! writes a [`Reply`] back. A client reads replies with
//! [`Stream<Replies>`](fictionet::stdlib::codec::Stream). Both accept CRLF and bare LF.
//! Which files exist, who may log in, and what commands do belong to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A line longer than [`MAX_LINE`] is an error, and a server's
//! decoder skips it and goes on to the next line, as real servers do. The
//! error says which reply a server sends: a bad line (an error item from
//! [`Commands`]) is answered with [`code::SYNTAX_ERROR`] (500), and a bad
//! argument (an error from [`Request::from_command`]) with
//! [`code::ARGUMENT_ERROR`] (501). Each input
//! buffer holds at most [`MAX_LINE`] bytes. Replies retain at most
//! [`MAX_REPLY_BYTES`] of text while assembling their lines.
//!
//! A command writer refuses ([`Error`]) rather than send a line that
//! would read back as a different command. A pathname may hold a carriage
//! return: RFC 2640 sends it as CR NUL, and a reader turns CR NUL back into
//! CR. A command reader also drops Telnet commands, such as the interrupt
//! and synch that clients send before `ABOR`.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::ftp::{code, Commands, Reply, Replies, Request};
//! use std::net::{Ipv4Addr, SocketAddrV4};
//!
//! // A server answers three commands.
//! let mut commands = Stream::new(Commands::new());
//! let stream = b"USER anonymous\r\nPASV\r\nEPRT |1|10.0.0.5|6275|\r\n";
//! assert_eq!(commands.push(stream), stream.len());
//! let mut out = Vec::new();
//! while let Some(line) = commands.next() {
//!     let reply = match line.unwrap().map(|c| Request::from_command(&c)) {
//!         Ok(Ok(Request::User(name))) => Reply::new(code::NEED_PASSWORD, &format!("Password for {name}, please.")),
//!         Ok(Ok(Request::Pasv)) => Reply::passive(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 50000)),
//!         Ok(Ok(Request::Eprt(to))) if to.port() == 6275 => Reply::new(code::OK, "EPRT command successful."),
//!         Ok(Ok(_)) => Reply::new(code::NOT_IMPLEMENTED, "Not implemented."),
//!         Ok(Err(_)) => Reply::new(code::ARGUMENT_ERROR, "Syntax error in parameters."),
//!         Err(_) => Reply::new(code::SYNTAX_ERROR, "Syntax error."),
//!     };
//!     reply.write(&mut out).unwrap();
//! }
//! assert_eq!(
//!     out,
//!     b"331 Password for anonymous, please.\r\n\
//!       227 Entering Passive Mode (10,0,0,1,195,80).\r\n\
//!       200 EPRT command successful.\r\n"
//! );
//!
//! // A client reads a multi-line reply to FEAT.
//! let mut replies = Stream::new(Replies::new());
//! let stream = b"211-Extensions supported:\r\n EPSV\r\n MLST size*;modify*;\r\n211 End\r\n";
//! assert_eq!(replies.push(stream), stream.len());
//! let reply = replies.next().unwrap().unwrap().unwrap();
//! let features = reply.features().unwrap();
//! assert_eq!(features.len(), 2);
//! assert_eq!(features[1].name, "MLST");
//! assert_eq!(features[1].params.as_deref(), Some("size*;modify*;"));
//! ```

use fictionet::stdlib::codec::ascii;
use fictionet::stdlib::codec::{self, Decode, Step, Wire};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU8;

/// A validated three-digit reply code.
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

/// Why bytes are not an FTP command or reply, why a command does not
/// say what a request needs, or why a value cannot be written. A server
/// answers an error item from [`Commands`] with [`code::SYNTAX_ERROR`],
/// and an error from [`Request::from_command`] with
/// [`code::ARGUMENT_ERROR`], except [`Error::Family`] in `EPRT`, which
/// RFC 2428 answers with [`code::UNKNOWN_NETWORK_PROTOCOL`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A command or reply line was longer than [`MAX_LINE`], or would be
    /// with its prefix, escaping and CRLF. The decoder dropped all of it.
    LineTooLong,
    /// The command line was empty.
    Empty,
    /// The command line did not start with one to four letters followed
    /// by a space or the end of the line.
    Verb,
    /// A command line was not UTF-8 once Telnet commands were dropped,
    /// held a NUL or a carriage return other than as CR NUL, or ended
    /// inside a Telnet command. Or a reply line was not UTF-8, or held a
    /// carriage return or a NUL byte.
    Text,
    /// A reply did not start with a code from 100 to 599 followed by a
    /// space, a hyphen or the end of the line.
    Syntax,
    /// A reply ran to more than [`MAX_REPLY_LINES`] lines. A
    /// [`Replies`] drops the reply's lines up to its last one, as RFC
    /// 1123 (section 4.1.2.11) asks, and goes on to the next reply.
    TooManyLines,
    /// The verb needs an argument and the command had none.
    MissingArgument,
    /// The verb takes no argument and the command had one.
    UnexpectedArgument,
    /// The argument was not one the verb accepts.
    InvalidArgument,
    /// An address in `PORT`, `EPRT` or a passive reply did not have the
    /// form the command or reply needs.
    Address,
    /// `EPRT` named an address family other than 1 (IPv4) or 2 (IPv6).
    Family,
    /// The reply's code does not carry what was asked of it: 211 for a
    /// list of features, 227 for a passive address, 229 for an extended
    /// passive port.
    Code(ReplyCode),
    /// A feature line did not start with a space and a name of printable
    /// ASCII characters, or its parameters held other characters than
    /// printable ASCII, spaces and tabs.
    Feature,
    /// The value would be refused or change when read back: a verb other
    /// than one to four uppercase ASCII letters, a command argument with
    /// NUL or LF without a preceding CR, a request whose argument does
    /// not fit its verb, a known verb in
    /// [`Request::Other`], or an IPv6 EPRT address with scope or flow info.
    /// Also returned for empty reply line lists, more than [`MAX_REPLY_LINES`]
    /// lines, CR, LF or NUL in reply text, or a middle line that ends the reply.
    /// [`Reply::feature_list`] returns this for invalid names or parameters,
    /// empty parameter values, or more than [`MAX_FEATURES`] features.
    Unwritable,
    /// The command or reply ended early.
    Incomplete,
    /// Bytes followed the command or reply.
    Trailing,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::LineTooLong => f.write_str("line too long"),
            Error::Empty => f.write_str("empty command line"),
            Error::Verb => f.write_str("command verb is not one to four letters"),
            Error::Text => f.write_str("line is not UTF-8 text without a bare CR or NUL"),
            Error::Syntax => f.write_str("reply does not start with a code from 100 to 599"),
            Error::TooManyLines => f.write_str("reply has too many lines"),
            Error::MissingArgument => f.write_str("missing argument"),
            Error::UnexpectedArgument => f.write_str("unexpected argument"),
            Error::InvalidArgument => f.write_str("invalid argument"),
            Error::Address => f.write_str("malformed address"),
            Error::Family => f.write_str("address family is not 1 (IPv4) or 2 (IPv6)"),
            Error::Code(c) => write!(f, "reply code {c} does not carry what was asked of it"),
            Error::Feature => f.write_str("malformed feature line"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Incomplete => f.write_str("incomplete FTP command or reply"),
            Error::Trailing => f.write_str("bytes after FTP command or reply"),
        }
    }
}

impl std::error::Error for Error {}

impl Command {
    /// A command with `verb` and `arg`.
    pub fn new(verb: &str, arg: Option<&str>) -> Command {
        Command {
            verb: verb.to_string(),
            arg: arg.map(str::to_string),
        }
    }

    /// Reads one command line, without its line ending. Telnet commands in
    /// it, such as `IAC IP` and `IAC DM`, are dropped, and CR NUL is read
    /// as CR.
    fn parse_line(line: &[u8]) -> Result<Command, Error> {
        if line.len() > MAX_CONTENT {
            return Err(Error::LineTooLong);
        }
        let line = command_text(line).ok_or(Error::Text)?;
        let line = line.as_str();
        if line.is_empty() {
            return Err(Error::Empty);
        }
        let (verb, arg) = match line.split_once(' ') {
            Some((verb, arg)) => (verb, Some(arg)),
            None => (line, None),
        };
        if verb.is_empty()
            || verb.len() > MAX_VERB
            || !verb.bytes().all(|b| b.is_ascii_alphabetic())
        {
            return Err(Error::Verb);
        }
        Ok(Command {
            verb: verb.to_ascii_uppercase(),
            arg: arg.map(str::to_string),
        })
    }
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

impl Request {
    /// Reads what `command` asks for. Verbs are known in upper case, as
    /// [`Wire::parse`] leaves them.
    pub fn from_command(command: &Command) -> Result<Request, Error> {
        use Error as E;
        let arg = command.arg.as_deref();
        let need = || arg.map(str::to_string).ok_or(E::MissingArgument);
        let none = |r: Request| {
            if arg.is_some() {
                Err(E::UnexpectedArgument)
            } else {
                Ok(r)
            }
        };
        let maybe = || arg.map(str::to_string);
        let upper = || arg.map(str::to_ascii_uppercase).ok_or(E::MissingArgument);
        Ok(match command.verb.as_str() {
            "USER" => Request::User(need()?),
            "PASS" => Request::Pass(need()?),
            "ACCT" => Request::Acct(need()?),
            "CWD" | "XCWD" => Request::Cwd(need()?),
            "CDUP" | "XCUP" => none(Request::Cdup)?,
            "SMNT" => Request::Smnt(need()?),
            "REIN" => none(Request::Rein)?,
            "QUIT" => none(Request::Quit)?,
            "PORT" => Request::Port(parse_port(arg.ok_or(E::MissingArgument)?)?),
            "PASV" => none(Request::Pasv)?,
            "TYPE" => Request::Type(parse_type(&upper()?).ok_or(E::InvalidArgument)?),
            "STRU" => Request::Stru(match upper()?.as_str() {
                "F" => Structure::File,
                "R" => Structure::Record,
                "P" => Structure::Page,
                _ => return Err(E::InvalidArgument),
            }),
            "MODE" => Request::Mode(match upper()?.as_str() {
                "S" => TransferMode::Stream,
                "B" => TransferMode::Block,
                "C" => TransferMode::Compressed,
                _ => return Err(E::InvalidArgument),
            }),
            "RETR" => Request::Retr(need()?),
            "STOR" => Request::Stor(need()?),
            "STOU" => none(Request::Stou)?,
            "APPE" => Request::Appe(need()?),
            "ALLO" => Request::Allo(need().and_then(|a| {
                if allo_ok(&a) {
                    Ok(a)
                } else {
                    Err(E::InvalidArgument)
                }
            })?),
            "REST" => Request::Rest(need().and_then(|a| {
                if rest_ok(&a) {
                    Ok(a)
                } else {
                    Err(E::InvalidArgument)
                }
            })?),
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
            "EPRT" => Request::Eprt(parse_eprt(arg.ok_or(E::MissingArgument)?)?),
            "EPSV" => Request::Epsv(match arg {
                None => None,
                Some(a) if a.eq_ignore_ascii_case("ALL") => Some(EpsvArg::All),
                Some(a) => Some(EpsvArg::Protocol(
                    decimal(a, 5)
                        .and_then(|n| u16::try_from(n).ok())
                        .ok_or(E::InvalidArgument)?,
                )),
            }),
            "FEAT" => none(Request::Feat)?,
            "OPTS" => Request::Opts(need().and_then(|a| {
                if opts_ok(&a) {
                    Ok(a)
                } else {
                    Err(E::InvalidArgument)
                }
            })?),
            "MDTM" => Request::Mdtm(need()?),
            "SIZE" => Request::Size(need()?),
            "MLST" => Request::Mlst(maybe()),
            "MLSD" => Request::Mlsd(maybe()),
            _ => Request::Other(command.clone()),
        })
    }

    /// The verb and argument for writing, without copying string arguments.
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
            Request::Port(addr) => ("PORT", Some(Cow::Owned(port_text(*addr)))),
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
            Request::Eprt(addr) => ("EPRT", Some(Cow::Owned(eprt_text(*addr)))),
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

/// The six-number IPv4 address token in `PORT` and `PASV`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortAddress {
    /// The address and port represented by this token.
    pub address: SocketAddrV4,
}
impl Wire for PortAddress {
    type ParseError = Error;
    type WriteError = core::convert::Infallible;

    /// Reads six decimal bytes separated by commas: four IPv4 octets,
    /// then the port's high and low bytes (RFC 959, section 4.1.2).
    /// Refuses missing or extra numbers, signs, spaces, invalid UTF-8,
    /// values above 255, and numbers longer than three digits.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Address)?;
        parse_port(text).map(|address| Self { address })
    }

    /// Appends the six decimal bytes. Every IPv4 address and port fits;
    /// no values are refused.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        out.extend_from_slice(port_text(self.address).as_bytes());
        Ok(())
    }
}

/// An IPv4 or IPv6 address token in `EPRT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EprtAddress {
    /// The address and port. Writing refuses IPv6 scope and flow values.
    pub address: SocketAddr,
}
impl Wire for EprtAddress {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an RFC 2428 token with a printable ASCII delimiter. Refuses
    /// invalid addresses, ports, trailing fields, and families other than
    /// 1 or 2. An unknown numeric family returns [`Error::Family`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Address)?;
        parse_eprt(text).map(|address| Self { address })
    }

    /// Appends an RFC 2428 token with `|` delimiters. Refuses nonzero IPv6
    /// scope or flow values because the token has no fields for them.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if let SocketAddr::V6(address) = self.address
            && (address.flowinfo() != 0 || address.scope_id() != 0)
        {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(eprt_text(self.address).as_bytes());
        Ok(())
    }
}

/// Reads the argument of `PORT`: six decimal numbers from 0 to 255 joined
/// by commas, `h1,h2,h3,h4,p1,p2`. The first four are the IPv4 address and
/// the last two the port, high byte first (RFC 959, section 4.1.2).
fn parse_port(arg: &str) -> Result<SocketAddrV4, Error> {
    match scan_host_port(arg) {
        Some((addr, used)) if used == arg.len() => Ok(addr),
        _ => Err(Error::Address),
    }
}

/// Writes an address as the argument of `PORT`, or the numbers in a reply
/// to `PASV`.
fn port_text(addr: SocketAddrV4) -> String {
    let [a, b, c, d] = addr.ip().octets();
    let [p1, p2] = addr.port().to_be_bytes();
    format!("{a},{b},{c},{d},{p1},{p2}")
}

/// Reads the argument of `EPRT`, such as `|1|132.235.1.2|6275|` or
/// `|2|1080::8:800:200C:417A|5282|` (RFC 2428, section 2). The first
/// character is the delimiter, which may be any printable ASCII character.
/// A family given as digits but not 1 or 2 is [`Error::Family`],
/// whatever the address and port after it look like.
fn parse_eprt(arg: &str) -> Result<SocketAddr, Error> {
    let d = arg.chars().next().ok_or(Error::Address)?;
    if !d.is_ascii_graphic() {
        return Err(Error::Address);
    }
    let mut fields = arg[1..].split(d);
    let (Some(family), Some(host), Some(port), Some(""), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(Error::Address);
    };
    if family.is_empty() || !family.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::Address);
    }
    // Leading zeros aside, the family must be 1 or 2.
    let ip = match family.trim_start_matches('0') {
        "1" => IpAddr::V4(host.parse::<Ipv4Addr>().map_err(|_| Error::Address)?),
        "2" => IpAddr::V6(host.parse::<Ipv6Addr>().map_err(|_| Error::Address)?),
        _ => return Err(Error::Family),
    };
    let port = decimal(port, 5)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(Error::Address)?;
    Ok(SocketAddr::new(ip, port))
}

/// Writes an address as the argument of `EPRT`, with `|` as the delimiter.
/// Callers must first refuse a nonzero IPv6 flow label or scope, as
/// [`EprtAddress::write`] and [`Request::write`] do. RFC 2428 has no fields
/// for them.
fn eprt_text(addr: SocketAddr) -> String {
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
        let digits = b
            .get(at..)?
            .iter()
            .take(4)
            .take_while(|c| c.is_ascii_digit())
            .count();
        *slot = u8::try_from(decimal(s.get(at..at + digits)?, 3)?).ok()?;
        at += digits;
    }
    let addr = SocketAddrV4::new(
        Ipv4Addr::new(n[0], n[1], n[2], n[3]),
        u16::from_be_bytes([n[4], n[5]]),
    );
    Some((addr, at))
}

/// A string of one to `max` ASCII digits, read as a number. Leading zeros
/// are allowed. Signs and spaces are not.
fn decimal(s: &str, max: usize) -> Option<u32> {
    ascii::decimal(s.as_bytes(), max, u64::from(u32::MAX)).map(|n| n as u32)
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
            if n >= 100 && n <= 599 {
                Some(ReplyCode(n))
            } else {
                None
            }
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
/// the last. [`Wire::write`] writes text as given and refuses a middle
/// line that would end the reply. [`Reply::from_lines`] pads any middle
/// line that starts with three digits for server code, as required by
/// [RFC 959, section 4.2](https://www.rfc-editor.org/rfc/rfc959#section-4.2):
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

impl Reply {
    /// A reply of one line. Writing refuses text longer than `MAX_REPLY_TEXT`
    /// bytes, so the line with its code, separator and CRLF fits in [`MAX_LINE`].
    pub fn new(code: ReplyCode, text: &str) -> Reply {
        Reply {
            code,
            lines: vec![text.to_string()],
        }
    }

    /// Builds a reply, adding a space before each middle line that starts
    /// with three ASCII digits (RFC 959, section 4.2). First and last lines
    /// are unchanged. The returned value includes the padding.
    /// Refuses empty or oversized line lists, CR, LF or NUL in text, and
    /// lines that exceed [`MAX_LINE`] after padding and code prefixes.
    pub fn from_lines(code: ReplyCode, mut lines: Vec<String>) -> Result<Reply, Error> {
        let count = lines.len();
        if count == 0 || count > MAX_REPLY_LINES {
            return Err(Error::Unwritable);
        }
        for line in lines.iter_mut().take(count - 1).skip(1) {
            if line
                .as_bytes()
                .get(..3)
                .is_some_and(|start| start.iter().all(u8::is_ascii_digit))
            {
                if line.len() >= MAX_CONTENT {
                    return Err(Error::LineTooLong);
                }
                line.insert(0, ' ');
            }
        }
        let reply = Reply { code, lines };
        reply.validate()?;
        Ok(reply)
    }

    /// Checks line limits and text without producing wire bytes.
    fn validate(&self) -> Result<(), Error> {
        let count = self.lines.len();
        if count == 0 || count > MAX_REPLY_LINES {
            return Err(Error::Unwritable);
        }
        for (i, line) in self.lines.iter().enumerate() {
            let middle = i != 0 && i != count - 1;
            let limit = if middle { MAX_CONTENT } else { MAX_REPLY_TEXT };
            if line.len() > limit {
                return Err(Error::LineTooLong);
            }
            if line.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
                || (middle && ends(line, self.code))
            {
                return Err(Error::Unwritable);
            }
        }
        Ok(())
    }

    /// The reply to `PASV`: code 227 and the address in the form RFC 959
    /// gives, `Entering Passive Mode (h1,h2,h3,h4,p1,p2).`
    pub fn passive(addr: SocketAddrV4) -> Reply {
        Reply::new(
            code::PASSIVE,
            &format!("Entering Passive Mode ({}).", port_text(addr)),
        )
    }

    /// The address in a reply to `PASV`. Servers word the reply in
    /// different ways, so this reads the six numbers from the first digit
    /// of a line on, as RFC 1123 (section 4.1.2.6) advises. In a reply of
    /// several lines it takes the first line that holds them.
    pub fn passive_address(&self) -> Result<SocketAddrV4, Error> {
        if self.code != code::PASSIVE {
            return Err(Error::Code(self.code));
        }
        self.lines
            .iter()
            .find_map(|line| {
                let start = line.find(|c: char| c.is_ascii_digit())?;
                scan_host_port(&line[start..]).map(|(addr, _)| addr)
            })
            .ok_or(Error::Address)
    }

    /// The reply to `EPSV`: code 229 and the port in the form RFC 2428
    /// gives, `Entering Extended Passive Mode (|||port|)`.
    pub fn extended_passive(port: u16) -> Reply {
        Reply::new(
            code::EXTENDED_PASSIVE,
            &format!("Entering Extended Passive Mode (|||{port}|)"),
        )
    }

    /// The port in a reply to `EPSV`: the number in `(|||port|)`, where `|`
    /// may be any printable ASCII character, `)` included. In a reply of
    /// several lines it takes the first line that holds one.
    pub fn extended_passive_port(&self) -> Result<u16, Error> {
        if self.code != code::EXTENDED_PASSIVE {
            return Err(Error::Code(self.code));
        }
        self.lines
            .iter()
            .find_map(|line| epsv_port(line))
            .ok_or(Error::Address)
    }

    /// Builds a `FEAT` reply (RFC 2389, section 3.2). With no features,
    /// returns `211 No features.`. Refuses invalid names or parameters,
    /// empty parameter values, and lists or lines beyond the named limits.
    /// Every accepted feature is preserved, including its case.
    pub fn feature_list(features: &[Feature]) -> Result<Reply, Error> {
        if features.len() > MAX_FEATURES {
            return Err(Error::Unwritable);
        }
        if features.is_empty() {
            return Ok(Reply::new(code::SYSTEM_STATUS, "No features."));
        }
        let mut lines = vec!["Extensions supported:".to_string()];
        for feature in features {
            let size = feature
                .name
                .len()
                .checked_add(1)
                .and_then(|n| {
                    feature
                        .params
                        .as_ref()
                        .map_or(Some(n), |p| n.checked_add(1)?.checked_add(p.len()))
                })
                .ok_or(Error::LineTooLong)?;
            if size > MAX_CONTENT {
                return Err(Error::LineTooLong);
            }
            if feature.name.is_empty()
                || !feature.name.bytes().all(|b| b.is_ascii_graphic())
                || feature
                    .params
                    .as_ref()
                    .is_some_and(|p| p.is_empty() || !p.chars().all(feature_char))
            {
                return Err(Error::Unwritable);
            }
            let mut line = format!(" {}", feature.name);
            if let Some(params) = &feature.params {
                line.push(' ');
                line.push_str(params);
            }
            lines.push(line);
        }
        lines.push("End".to_string());
        Ok(Reply {
            code: code::SYSTEM_STATUS,
            lines,
        })
    }

    /// The features a reply to `FEAT` lists. A reply of one line lists
    /// none.
    pub fn features(&self) -> Result<Vec<Feature>, Error> {
        if self.code != code::SYSTEM_STATUS {
            return Err(Error::Code(self.code));
        }
        let middle = if self.lines.len() > 2 {
            &self.lines[1..self.lines.len() - 1]
        } else {
            &[]
        };
        middle
            .iter()
            .map(|line| {
                let rest = line.strip_prefix(' ').ok_or(Error::Feature)?;
                let (name, params) = match rest.split_once(' ') {
                    // A space with nothing after it is read as no parameters.
                    Some((name, "")) => (name, None),
                    Some((name, params)) => (name, Some(params)),
                    None => (rest, None),
                };
                if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(Error::Feature);
                }
                if params.is_some_and(|p| !p.chars().all(feature_char)) {
                    return Err(Error::Feature);
                }
                Ok(Feature {
                    name: name.to_string(),
                    params: params.map(str::to_string),
                })
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
    let (Some(""), Some(""), Some(port), Some(rest)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
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
    fn take(&mut self, line: &[u8]) -> Result<Option<Reply>, Error> {
        let line = text(line).ok_or(Error::Text)?;
        if let Some((code, lines, over)) = &mut self.open {
            if ends(line, *code) {
                let code = *code;
                let over = *over;
                let mut lines = std::mem::take(lines);
                self.open = None;
                if over {
                    return Err(Error::TooManyLines);
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
            Some(&[a, x, y])
                if (b'1'..=b'5').contains(&a) && x.is_ascii_digit() && y.is_ascii_digit() =>
            {
                let n = u16::from(a - b'0') * 100 + u16::from(x - b'0') * 10 + u16::from(y - b'0');
                ReplyCode::new(n).ok_or(Error::Syntax)?
            }
            _ => return Err(Error::Syntax),
        };
        let rest = line.get(4..).unwrap_or("").to_string();
        match b.get(3) {
            None | Some(b' ') => Ok(Some(Reply {
                code,
                lines: vec![rest],
            })),
            Some(b'-') => {
                self.open = Some((code, vec![rest], false));
                Ok(None)
            }
            Some(_) => Err(Error::Syntax),
        }
    }
}

/// Whether `line` is the last line of a multi-line reply with `code`: the
/// code, then a space or the end of the line.
fn ends(line: &str, code: ReplyCode) -> bool {
    let b = line.as_bytes();
    b.len() >= 3
        && b[..3] == *code.get().to_string().as_bytes()
        && matches!(b.get(3), None | Some(b' '))
}

/// The two bytes taken to come before the bytes a reader holds: the end
/// of a line, or of nothing.
const LINE_START: [u8; 2] = *b"\n\n";

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

fn push_line(out: &mut Vec<u8>, line: &str) {
    out.extend_from_slice(line.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Maximum text bytes retained while assembling one reply.
pub const MAX_REPLY_BYTES: usize = MAX_REPLY_LINES * MAX_CONTENT;

/// A terminal fault in [`Commands`] or [`Replies`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// EOF interrupted a line or a multi-line reply.
    Incomplete,
    /// A reply's framing can no longer be followed.
    Reply(Error),
}
impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Incomplete => f.write_str("incomplete FTP control unit"),
            Self::Reply(_) => f.write_str("malformed FTP reply"),
        }
    }
}
impl core::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Incomplete => None,
            Self::Reply(e) => Some(e),
        }
    }
}

// Lines frames physical lines. RFC 2640's CR NUL LF is joined here into
// one logical line. Only consumed pieces are retained, under MAX_CONTENT.
struct ControlLines {
    lines: codec::Lines,
    partial: Vec<u8>,
    dropping: bool,
    prev: [u8; 2],
}
impl core::fmt::Debug for ControlLines {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControlLines")
            .field("partial", &self.partial)
            .field("dropping", &self.dropping)
            .field("prev", &self.prev)
            .finish_non_exhaustive()
    }
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
        self.lines = codec::Lines::new(
            MAX_CONTENT.saturating_sub(self.partial.len()),
            codec::Ending::LfOrCrlf,
        );
    }

    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
    ) -> Result<Step<Result<Vec<u8>, Error>>, FrameError> {
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
        let step = self
            .lines
            .decode(input, eof)
            .unwrap_or_else(|never| match never {});
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
                        return Ok(Step::Item(Err(Error::LineTooLong), n));
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
                Ok(Step::Item(Err(Error::LineTooLong), n))
            }
            Step::Item(Err(_), _) => Err(FrameError::Incomplete),
            Step::Need if eof && !self.partial.is_empty() => Err(FrameError::Incomplete),
            Step::Need => Ok(Step::Need),
            Step::Skip(n) => Ok(Step::Skip(n)),
            Step::End => Ok(Step::End),
        }
    }
}

/// Reads control commands through [`fictionet::stdlib::codec::Lines`].
///
/// CRLF and bare LF are accepted. RFC 2640's CR NUL escaping stays in
/// this module. Lines are bounded by [`MAX_LINE`], including CRLF.
/// Malformed and overlong commands are error items. EOF inside a command
/// is terminal.
pub struct Commands {
    lines: ControlLines,
}
impl core::fmt::Debug for Commands {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Commands").finish_non_exhaustive()
    }
}
impl Commands {
    /// Creates a command reader with a capacity of [`MAX_LINE`].
    pub fn new() -> Self {
        Self {
            lines: ControlLines::new(),
        }
    }
}
impl Default for Commands {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for Commands {
    type Item = Result<Command, Error>;
    type Error = FrameError;
    const NAME: &'static str = "FTP commands";

    fn capacity(&self) -> usize {
        MAX_LINE
    }
    fn held(&self) -> usize {
        self.lines.partial.len()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, FrameError> {
        Ok(match self.lines.decode(input, eof)? {
            Step::Item(line, n) => Step::Item(line.and_then(|line| Command::parse_line(&line)), n),
            Step::Skip(n) => Step::Skip(n),
            Step::Need => Step::Need,
            Step::End => Step::End,
        })
    }
}

/// Reads and assembles control replies through [`fictionet::stdlib::codec::Lines`].
///
/// CRLF and bare LF are accepted under [`MAX_LINE`]. Assemblies retain
/// at most [`MAX_REPLY_LINES`] lines and [`MAX_REPLY_BYTES`] text bytes.
/// A malformed first line is an error item. Invalid text inside an open
/// reply or an overlong line ends framing. Too many reply lines produce
/// one error item at the matching final line. EOF in an assembly is
/// [`FrameError::Incomplete`].
pub struct Replies {
    lines: ControlLines,
    builder: Builder,
    held: usize,
}
impl core::fmt::Debug for Replies {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Replies")
            .field("builder", &self.builder)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}
impl Replies {
    /// Creates a reply reader with a capacity of [`MAX_LINE`].
    pub fn new() -> Self {
        Self {
            lines: ControlLines::new(),
            builder: Builder::default(),
            held: 0,
        }
    }
}
impl Default for Replies {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for Replies {
    type Item = Result<Reply, Error>;
    type Error = FrameError;
    const NAME: &'static str = "FTP replies";

    fn capacity(&self) -> usize {
        MAX_LINE
    }
    fn held(&self) -> usize {
        self.held.saturating_add(self.lines.partial.len())
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, FrameError> {
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
                    Err(e) if !open || e == Error::TooManyLines => Ok(Step::Item(Err(e), n)),
                    Err(e) => Err(FrameError::Reply(e)),
                }
            }
            Step::Item(Err(_), _) => Err(FrameError::Reply(Error::LineTooLong)),
            Step::Need if eof && self.builder.open.is_some() => Err(FrameError::Incomplete),
            Step::Need => Ok(Step::Need),
            Step::Skip(n) => Ok(Step::Skip(n)),
            Step::End => Ok(Step::End),
        }
    }
}

/// Reads one unit, preserving item errors before checking trailing bytes.
fn exact<D, T, E, P>(
    mut decoder: D,
    mut bytes: &[u8],
    item_error: impl Fn(E) -> P,
    framing_error: impl Fn(D::Error) -> P,
    incomplete: P,
    trailing: P,
) -> Result<T, P>
where
    D: Decode<Item = Result<T, E>>,
{
    loop {
        match decoder.decode(bytes, true).map_err(&framing_error)? {
            Step::Item(Err(e), _) => return Err(item_error(e)),
            Step::Item(Ok(item), used) if used == bytes.len() => return Ok(item),
            Step::Item(_, _) => return Err(trailing),
            Step::Skip(used) => match bytes.get(used..) {
                Some(rest) => bytes = rest,
                None => return Err(incomplete),
            },
            Step::Need | Step::End => return Err(incomplete),
        }
    }
}

impl Wire for Command {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one command with CRLF or bare LF. Drops Telnet commands,
    /// decodes CR NUL as CR, and makes the verb uppercase. Refuses invalid
    /// verbs, UTF-8, Telnet sequences, or argument text, incomplete lines,
    /// and trailing bytes. Checks [`MAX_LINE`] before trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(
            Commands::new(),
            bytes,
            |e| e,
            |_| Error::Incomplete,
            Error::Incomplete,
            Error::Trailing,
        )
    }
    /// Appends a command with CRLF, leaving `out` unchanged on error.
    /// Refuses verbs other than one to four uppercase ASCII letters,
    /// NUL, LF without a preceding CR, and lines over [`MAX_LINE`].
    /// Each argument CR is sent as CR NUL (RFC 2640).
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let (verb, arg) = (self.verb.as_str(), self.arg.as_deref());
        if verb.is_empty() || verb.len() > MAX_VERB || !verb.bytes().all(|b| b.is_ascii_uppercase())
        {
            return Err(Error::Unwritable);
        }
        let mut len = verb.len() + 2;
        if let Some(arg) = arg {
            let b = arg.as_bytes();
            if b.len() > MAX_LINE {
                return Err(Error::LineTooLong);
            }
            for (i, &c) in b.iter().enumerate() {
                match c {
                    0 => return Err(Error::Unwritable),
                    b'\n' if i == 0 || b[i - 1] != b'\r' => return Err(Error::Unwritable),
                    b'\r' => len += 1,
                    _ => {}
                }
            }
            len += 1 + b.len();
        }
        if len > MAX_LINE {
            return Err(Error::LineTooLong);
        }
        out.extend_from_slice(verb.as_bytes());
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
        Ok(())
    }
}

impl Wire for Request {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one terminated command and its meaning. Refuses incomplete
    /// or trailing bytes and arguments that do not fit the verb.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let command = Command::parse(bytes)?;
        Self::from_command(&command)
    }

    /// Appends one command with CRLF. Refuses invalid command text,
    /// oversized lines, and requests that would read back differently,
    /// including known verbs in `Other` and IPv6 EPRT flow labels or scope.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if let Request::Eprt(SocketAddr::V6(address)) = self
            && (address.flowinfo() != 0 || address.scope_id() != 0)
        {
            return Err(Error::Unwritable);
        }
        let (verb, arg) = self.parts();
        // Check lengths before copying a caller's argument.
        if arg.as_ref().is_some_and(|a| a.len() > MAX_LINE) {
            return Err(Error::LineTooLong);
        }
        let command = Command {
            verb: verb.to_string(),
            arg: arg.map(Cow::into_owned),
        };
        let bytes = command.to_bytes()?;
        if Self::parse(&bytes).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Reply {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one reply with CRLF or bare LF. A multiline reply ends at
    /// its matching code followed by a space, or the code alone. Refuses
    /// invalid codes or UTF-8, CR or NUL in text, lines above [`MAX_LINE`],
    /// more than [`MAX_REPLY_LINES`], incomplete input, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(
            Replies::new(),
            bytes,
            |e| e,
            |e| match e {
                FrameError::Incomplete => Error::Incomplete,
                FrameError::Reply(e) => e,
            },
            Error::Incomplete,
            Error::Trailing,
        )
    }

    /// Appends the reply's text verbatim, with code prefixes and CRLF.
    /// Refuses text that would not read back unchanged before touching
    /// `out`: empty or oversized line lists, CR, LF, NUL, oversized text,
    /// and middle lines that would end the reply.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        let count = self.lines.len();
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
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use std::net::SocketAddrV6;

    use codec::{Fail, Lcg, Stream};
    use fictionet::stdlib::test_support::contract;

    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn commands(bytes: &[u8]) -> Vec<Result<Command, Error>> {
        decode_all(Commands::new, bytes).0
    }

    fn replies(bytes: &[u8]) -> Vec<Result<Reply, Error>> {
        decode_all(Replies::new, bytes).0
    }

    fn request(line: &str) -> Result<Request, Error> {
        Request::from_command(&Command::parse(format!("{line}\r\n").as_bytes()).unwrap())
    }

    fn reply_of(bytes: &[u8]) -> Reply {
        Reply::parse(bytes).unwrap()
    }

    // Examples from RFC 959, 2428, 2389 and 3659.

    #[test]
    fn rfc959_commands() {
        assert_eq!(
            request("USER anonymous"),
            Ok(Request::User("anonymous".into()))
        );
        assert_eq!(
            request("user anonymous"),
            Ok(Request::User("anonymous".into()))
        );
        assert_eq!(request("PASS guest@"), Ok(Request::Pass("guest@".into())));
        // RFC 959, section 4.1.2: a PORT argument, port 24 * 256 + 131.
        let to = SocketAddrV4::new(Ipv4Addr::new(132, 235, 1, 2), 6275);
        assert_eq!(request("PORT 132,235,1,2,24,131"), Ok(Request::Port(to)));
        assert_eq!(
            Request::Port(to).to_bytes().unwrap(),
            b"PORT 132,235,1,2,24,131\r\n"
        );
        assert_eq!(
            request("TYPE A N"),
            Ok(Request::Type(DataType::Ascii(Some(Format::NonPrint))))
        );
        assert_eq!(request("TYPE i"), Ok(Request::Type(DataType::Image)));
        assert_eq!(
            request("TYPE L 8"),
            Ok(Request::Type(DataType::Local(NonZeroU8::new(8).unwrap())))
        );
        assert_eq!(request("STRU R"), Ok(Request::Stru(Structure::Record)));
        assert_eq!(request("MODE B"), Ok(Request::Mode(TransferMode::Block)));
        assert_eq!(
            request("RETR dir/file name.txt"),
            Ok(Request::Retr("dir/file name.txt".into()))
        );
        assert_eq!(request("LIST"), Ok(Request::List(None)));
        assert_eq!(request("LIST -la"), Ok(Request::List(Some("-la".into()))));
        assert_eq!(request("XPWD"), Ok(Request::Pwd));
        assert_eq!(request("XMKD new"), Ok(Request::Mkd("new".into())));
        assert_eq!(
            request("SITE CHMOD 755 x"),
            Ok(Request::Site("CHMOD 755 x".into()))
        );
        assert_eq!(
            request("AUTH TLS"),
            Ok(Request::Other(Command {
                verb: "AUTH".into(),
                arg: Some("TLS".into())
            }))
        );
    }

    #[test]
    fn rfc3659_and_rfc2389_commands() {
        assert_eq!(
            request("SIZE /pub/file"),
            Ok(Request::Size("/pub/file".into()))
        );
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
        assert_eq!(
            EprtAddress::parse("|1|132.235.1.2|6275|".as_bytes()).map(|token| token.address),
            Ok(v4)
        );
        let v6: SocketAddr = "[1080::8:800:200c:417a]:5282".parse().unwrap();
        assert_eq!(
            EprtAddress::parse("|2|1080::8:800:200C:417A|5282|".as_bytes())
                .map(|token| token.address),
            Ok(v6)
        );
        // Any printable delimiter.
        assert_eq!(
            EprtAddress::parse("!1!132.235.1.2!6275!".as_bytes()).map(|token| token.address),
            Ok(v4)
        );
        assert_eq!(
            EprtAddress { address: v4 }.to_bytes().unwrap(),
            b"|1|132.235.1.2|6275|"
        );
        assert_eq!(
            request("EPRT |2|1080::8:800:200C:417A|5282|"),
            Ok(Request::Eprt(v6))
        );
        assert_eq!(request("EPSV"), Ok(Request::Epsv(None)));
        assert_eq!(
            request("EPSV 2"),
            Ok(Request::Epsv(Some(EpsvArg::Protocol(2))))
        );
        assert_eq!(request("EPSV all"), Ok(Request::Epsv(Some(EpsvArg::All))));
        // RFC 2428, section 3: the reply to EPSV.
        let r = reply_of(b"229 Entering Extended Passive Mode (|||6446|)\r\n");
        assert_eq!(r.extended_passive_port(), Ok(6446));
        assert_eq!(Reply::extended_passive(6446), r);
        assert_eq!(
            reply_of(b"229 ok (!!!21!)\r\n").extended_passive_port(),
            Ok(21)
        );
    }

    #[test]
    fn passive_replies() {
        let r = reply_of(b"227 Entering Passive Mode (192,168,1,2,19,137).\r\n");
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 19 * 256 + 137);
        assert_eq!(r.passive_address(), Ok(addr));
        assert_eq!(Reply::passive(addr), r);
        // Other wordings, as RFC 1123 warns.
        assert_eq!(
            reply_of(b"227 =192,168,1,2,19,137\n").passive_address(),
            Ok(addr)
        );
        assert_eq!(
            reply_of(b"227 Passive 192,168,1,2,19,137 ok\r\n").passive_address(),
            Ok(addr)
        );
        assert_eq!(
            reply_of(b"227 Passive\r\n").passive_address(),
            Err(Error::Address)
        );
        assert_eq!(
            reply_of(b"227 (1,2,3)\r\n").passive_address(),
            Err(Error::Address)
        );
        assert_eq!(
            reply_of(b"200 (1,2,3,4,5,6)\r\n").passive_address(),
            Err(Error::Code(code::OK))
        );
    }

    #[test]
    fn rfc959_multiline_reply() {
        // RFC 959, section 4.2.
        let bytes = b"123-First line\r\nSecond line\r\n  234 A line beginning with numbers\r\n123 The last line\r\n";
        let r = reply_of(bytes);
        assert_eq!(r.code.get(), 123);
        assert_eq!(
            r.lines,
            [
                "First line",
                "Second line",
                "  234 A line beginning with numbers",
                "The last line"
            ]
        );
        assert_eq!(r.to_bytes().unwrap(), bytes);
        assert_eq!(
            reply_of(b"220 Service ready\r\n"),
            Reply::new(code::READY, "Service ready")
        );
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
        assert_eq!(
            f[0].params.as_deref(),
            Some("size*;create;modify*;perm;media-type")
        );
        assert_eq!(f[1].params, None);
        assert_eq!(Reply::feature_list(&f).unwrap().features(), Ok(f));
        // No features.
        assert_eq!(reply_of(b"211 no-features\r\n").features(), Ok(vec![]));
        assert_eq!(
            Reply::feature_list(&[]).unwrap().to_bytes().unwrap(),
            b"211 No features.\r\n"
        );
        // Errors.
        assert_eq!(
            reply_of(b"500 no\r\n").features(),
            Err(Error::Code(code::SYNTAX_ERROR))
        );
        assert_eq!(
            reply_of(b"211-x\r\nSIZE\r\n211 e\r\n").features(),
            Err(Error::Feature)
        );
        assert_eq!(
            reply_of(b"211-x\r\n  SIZE\r\n211 e\r\n").features(),
            Err(Error::Feature)
        );
        assert_eq!(
            reply_of(b"211-x\r\n \x01\r\n211 e\r\n").features(),
            Err(Error::Feature)
        );
        // Names keep their case, and a space with nothing after it is no
        // parameters.
        let f = reply_of(b"211-x\r\n mdtm \r\n211 e\r\n")
            .features()
            .unwrap();
        assert_eq!(
            f,
            [Feature {
                name: "mdtm".into(),
                params: None
            }]
        );
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
        let back: Vec<_> = commands(&stream)
            .into_iter()
            .map(|c| Request::from_command(&c.unwrap()).unwrap())
            .collect();
        assert_eq!(back, all);
    }

    #[test]
    fn command_errors() {
        for (line, error) in [
            (b"\r\n".as_slice(), Error::Empty),
            (b" USER x\r\n", Error::Verb),
            (b"USERS x\r\n", Error::Verb),
            (b"US3R x\r\n", Error::Verb),
            (b"\xffABOR\r\n", Error::Text),
            (b"ABOR\xff\r\n", Error::Text),
            (b"ABOR\xff\xfb\r\n", Error::Text),
            (b"RETR \xff\xff\r\n", Error::Text),
            (b"RETR a\rb\r\n", Error::Text),
            (b"RETR a\r\r\n", Error::Text),
            (b"RETR a\0b\r\n", Error::Text),
            (b"RETR \r\0\0\r\n", Error::Text),
        ] {
            assert_eq!(Command::parse(line), Err(error));
            contract::check_decode_with_alloc_limit(Commands::new, line, 2 * MAX_LINE);
        }
        assert_eq!(Command::parse(b"RETR a\nb\r\n"), Err(Error::Trailing));
        assert_eq!(Command::parse(&[b'A'; MAX_LINE]), Err(Error::LineTooLong));
        assert_eq!(
            Command::parse(b"retr \r\n"),
            Ok(Command::new("RETR", Some("")))
        );
    }

    #[test]
    fn argument_errors() {
        use Error as E;
        assert_eq!(request("USER"), Err(E::MissingArgument));
        assert_eq!(request("RETR"), Err(E::MissingArgument));
        assert_eq!(request("PORT"), Err(E::MissingArgument));
        assert_eq!(request("EPRT"), Err(E::MissingArgument));
        assert_eq!(request("TYPE"), Err(E::MissingArgument));
        assert_eq!(request("PASV x"), Err(E::UnexpectedArgument));
        assert_eq!(request("QUIT "), Err(E::UnexpectedArgument));
        assert_eq!(request("TYPE X"), Err(E::InvalidArgument));
        assert_eq!(request("TYPE A X"), Err(E::InvalidArgument));
        assert_eq!(request("TYPE I N"), Err(E::InvalidArgument));
        assert_eq!(request("TYPE L"), Err(E::InvalidArgument));
        assert_eq!(request("TYPE L 256"), Err(E::InvalidArgument));
        // RFC 959, section 5.3.2: a byte size is from 1 to 255.
        assert_eq!(request("TYPE L 0"), Err(E::InvalidArgument));
        assert_eq!(request("TYPE A N X"), Err(E::InvalidArgument));
        assert_eq!(request("STRU X"), Err(E::InvalidArgument));
        assert_eq!(request("MODE X"), Err(E::InvalidArgument));
        assert_eq!(request("EPSV 3x"), Err(E::InvalidArgument));
        assert_eq!(request("EPSV 65536"), Err(E::InvalidArgument));
        assert_eq!(request("PORT 1,2,3,4,5"), Err(Error::Address));
        // RFC 959, section 5.3.2, and RFC 2389, section 4.
        for bad in [
            "ALLO xyz",
            "ALLO ",
            "ALLO 1 R",
            "ALLO 1 X 2",
            "ALLO 1  R 2",
            "REST a b",
            "REST ",
            "OPTS ",
            "OPTS  x",
        ] {
            assert_eq!(request(bad), Err(E::InvalidArgument), "{bad:?}");
        }
        assert_eq!(request("ALLO 10 r 2"), Ok(Request::Allo("10 r 2".into())));
        assert_eq!(request("REST !x~"), Ok(Request::Rest("!x~".into())));
        assert_eq!(request("OPTS UTF8"), Ok(Request::Opts("UTF8".into())));
        assert_eq!(request("EPRT |3|1.2.3.4|5|"), Err(Error::Family));
    }

    #[test]
    fn address_errors() {
        use Error::*;
        for bad in [
            "",
            "1,2,3,4,5",
            "1,2,3,4,5,6,",
            "256,0,0,0,0,0",
            "1,2,3,4,5,0006",
            "1, 2,3,4,5,6",
            "+1,2,3,4,5,6",
        ] {
            assert_eq!(
                PortAddress::parse(bad.as_bytes()).map(|token| token.address),
                Err(Address),
                "{bad:?}"
            );
        }
        assert_eq!(
            PortAddress::parse("001,2,3,4,5,6".as_bytes()).map(|token| token.address),
            Ok(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 0x0506))
        );
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
            assert_eq!(
                EprtAddress::parse(bad.as_bytes()).map(|token| token.address),
                Err(Address),
                "{bad:?}"
            );
        }
        assert_eq!(
            EprtAddress::parse("|0|1.2.3.4|5|".as_bytes()).map(|token| token.address),
            Err(Family)
        );
        assert_eq!(
            EprtAddress::parse("|99999|1.2.3.4|5|".as_bytes()).map(|token| token.address),
            Err(Family)
        );
        // RFC 2428, section 2: an unknown family gets 522, whatever its
        // address and port look like.
        assert_eq!(
            EprtAddress::parse("|123456|1.2.3.4|5|".as_bytes()).map(|token| token.address),
            Err(Family)
        );
        assert_eq!(
            EprtAddress::parse("|3|zone:4|x|".as_bytes()).map(|token| token.address),
            Err(Family)
        );
        for bad in [
            "229 none",
            "229 ()",
            "229 (|||x|)",
            "229 (||1|5|)",
            "229 (|||5|",
            "229 (|||5)",
            "229 ( || 5|)",
        ] {
            let r = reply_of(format!("{bad}\r\n").as_bytes());
            assert_eq!(r.extended_passive_port(), Err(Address), "{bad:?}");
        }
        assert_eq!(
            Reply::new(code::OK, "(|||5|)").extended_passive_port(),
            Err(Code(code::OK))
        );
        // A reply built by hand with no lines.
        let empty = Reply {
            code: code::PASSIVE,
            lines: vec![],
        };
        assert_eq!(empty.passive_address(), Err(Address));
        let empty = Reply {
            code: code::EXTENDED_PASSIVE,
            lines: vec![],
        };
        assert_eq!(empty.extended_passive_port(), Err(Address));
        // `)` as the delimiter (RFC 2428, section 3).
        let r = reply_of(b"229 Entering Extended Passive Mode ()))6446))\r\n");
        assert_eq!(r.extended_passive_port(), Ok(6446));
        for (flow, scope) in [(7, 0), (0, 9), (7, 9)] {
            let address = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5, flow, scope));
            assert_eq!(EprtAddress { address }.to_bytes(), Err(Error::Unwritable));
            assert_eq!(Request::Eprt(address).to_bytes(), Err(Error::Unwritable));
        }
    }

    #[test]
    fn request_write_refuses_ipv6_metadata() {
        for (flow, scope) in [(7, 0), (0, 9), (7, 9)] {
            let address = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5, flow, scope));
            let request = Request::Eprt(address);
            let mut out = b"prefix".to_vec();
            assert_eq!(request.write(&mut out), Err(Error::Unwritable));
            assert_eq!(out, b"prefix");
        }
    }

    #[test]
    fn request_write_refuses_known_verb_in_other() {
        let request = Request::Other(Command::new("RETR", Some("x")));
        let mut out = b"prefix".to_vec();
        assert_eq!(request.write(&mut out), Err(Error::Unwritable));
        assert_eq!(out, b"prefix");
    }

    #[test]
    fn reply_errors() {
        assert_eq!(Reply::parse(b"600 x\r\n"), Err(Error::Syntax));
        assert_eq!(Reply::parse(b"099 x\r\n"), Err(Error::Syntax));
        assert_eq!(Reply::parse(b"20 x\r\n"), Err(Error::Syntax));
        assert_eq!(Reply::parse(b"200x\r\n"), Err(Error::Syntax));
        assert_eq!(Reply::parse(b"\r\n"), Err(Error::Syntax));
        assert_eq!(Reply::parse(b"200 \xff\r\n"), Err(Error::Text));
        assert_eq!(Reply::parse(b"200 a\rb\r\n"), Err(Error::Text));
        assert_eq!(Reply::parse(b"200-a\r\nb\0\r\n"), Err(Error::Text));
        let long = [
            vec![b'2', b'0', b'0', b' '],
            vec![b'x'; MAX_LINE],
            b"\r\n".to_vec(),
        ]
        .concat();
        assert_eq!(Reply::parse(&long), Err(Error::LineTooLong));
        // Too many lines.
        let mut many = b"200-first\r\n".to_vec();
        for _ in 0..MAX_REPLY_LINES {
            many.extend_from_slice(b"x\r\n");
        }
        many.extend_from_slice(b"200 last\r\n");
        assert_eq!(Reply::parse(&many), Err(Error::TooManyLines));
        // The most lines allowed.
        let mut most = b"200-first\r\n".to_vec();
        for _ in 0..MAX_REPLY_LINES - 2 {
            most.extend_from_slice(b"x\r\n");
        }
        most.extend_from_slice(b"200 last\r\n");
        assert_eq!(reply_of(&most).lines.len(), MAX_REPLY_LINES);
        // A malformed first line is recoverable; invalid text in an open reply is terminal.
        assert_eq!(
            replies(b"200 ok\r\nhello\r\n200 ok\r\n"),
            [
                Ok(Reply::new(code::OK, "ok")),
                Err(Error::Syntax),
                Ok(Reply::new(code::OK, "ok"))
            ]
        );
        let mut stream = Stream::new(Replies::new());
        assert_eq!(stream.push(b"200-a\r\nb\0\r\n"), 11);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(FrameError::Reply(Error::Text))))
        );
        assert!(stream.next().is_none());
        assert_eq!(
            stream.failed(),
            Some(&Fail::Protocol(FrameError::Reply(Error::Text)))
        );
    }

    #[test]
    fn line_lengths() {
        // The longest line allowed, with CRLF and with LF alone.
        let verb = b"RETR ";
        let fits = [
            verb.to_vec(),
            vec![b'x'; MAX_LINE - 2 - verb.len()],
            b"\r\n".to_vec(),
        ]
        .concat();
        assert_eq!(fits.len(), MAX_LINE);
        let fits_lf = [&fits[..fits.len() - 2], b"\n"].concat();
        let over_lf = [&fits[..fits.len() - 2], b"x\n"].concat();
        let over = [&fits[..fits.len() - 2], b"x\r\n"].concat();
        let far_over = [vec![b'x'; 3 * MAX_LINE], b"\r\n".to_vec()].concat();
        let next = b"NOOP\r\n";
        for (line, ok) in [
            (&fits, true),
            (&fits_lf, true),
            (&over_lf, false),
            (&over, false),
            (&far_over, false),
        ] {
            let stream = [line.as_slice(), next].concat();
            let got = commands(&stream);
            assert_eq!(got.len(), 2);
            assert_eq!(got[0].is_ok(), ok);
            if !ok {
                assert_eq!(got[0], Err(Error::LineTooLong));
            }
            assert_eq!(got[1], Ok(Command::new("NOOP", None)));
            contract::check_decode_with_alloc_limit(Commands::new, &stream, 2 * MAX_LINE);
        }
        contract::check_decode_with_alloc_limit(
            Commands::new,
            &vec![b'x'; 3 * MAX_LINE],
            2 * MAX_LINE,
        );
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
            assert_eq!(
                Reply::parse(&reply[..n]),
                Err(Error::Incomplete),
                "{n} bytes"
            );
            assert_eq!(replies(&reply[..n]), vec![], "{n} bytes");
        }
    }

    #[test]
    fn reply_constructor_pads_numeric_middle_lines() {
        let lines = [
            "123 first",
            "220",
            "220 done",
            "230 Logged in",
            "999-x",
            "12",
            "é23",
            "end",
        ];
        let reply = Reply::from_lines(code::READY, lines.map(str::to_string).to_vec()).unwrap();
        assert_eq!(
            reply.lines,
            [
                "123 first",
                " 220",
                " 220 done",
                " 230 Logged in",
                " 999-x",
                "12",
                "é23",
                "end"
            ]
        );
        assert_eq!(
            reply.to_bytes().unwrap(),
            "220-123 first\r\n 220\r\n 220 done\r\n 230 Logged in\r\n 999-x\r\n12\r\né23\r\n220 end\r\n".as_bytes()
        );
        contract::check_wire_value(&reply);
        let one = Reply::from_lines(code::READY, vec!["220 text".into()]).unwrap();
        assert_eq!(one, Reply::new(code::READY, "220 text"));
        for lines in [
            vec![],
            vec![String::new(); MAX_REPLY_LINES + 1],
            vec!["a\rb".into()],
            vec!["a\nb".into()],
            vec!["a\0b".into()],
        ] {
            assert_eq!(
                Reply::from_lines(code::READY, lines),
                Err(Error::Unwritable)
            );
        }
        for (size, fits) in [(MAX_CONTENT - 1, true), (MAX_CONTENT, false)] {
            let middle = format!("123{}", "x".repeat(size - 3));
            let reply = Reply::from_lines(code::READY, vec!["start".into(), middle, "end".into()]);
            if fits {
                let reply = reply.unwrap();
                assert_eq!(reply.lines[1].len(), MAX_CONTENT);
                contract::check_wire_value(&reply);
            } else {
                assert_eq!(reply, Err(Error::LineTooLong));
            }
        }
    }

    #[test]
    fn writers_preserve_values_or_refuse() {
        let c = Request::Retr("a\r\nDELE b".into());
        assert_eq!(
            commands(&c.to_bytes().unwrap()),
            [Ok(Command::new("RETR", Some("a\r\nDELE b")))]
        );
        for (request, error) in [
            (Request::Dele("a\nb".into()), Error::Unwritable),
            (Request::Dele("a\0b".into()), Error::Unwritable),
            (Request::Allo("xyz".into()), Error::Unwritable),
            (
                Request::Other(Command::new("RETR", None)),
                Error::Unwritable,
            ),
            (
                Request::Other(Command::new("NOOP", None)),
                Error::Unwritable,
            ),
            (
                Request::Other(Command::new("noop", None)),
                Error::Unwritable,
            ),
            (
                Request::Other(Command::new("abcd", None)),
                Error::Unwritable,
            ),
            (Request::Stor("é".repeat(MAX_LINE)), Error::LineTooLong),
            (
                Request::Stor("x".repeat(rounds(64 << 20))),
                Error::LineTooLong,
            ),
        ] {
            let mut out = b"prefix".to_vec();
            assert_eq!(request.write(&mut out), Err(error));
            assert_eq!(out, b"prefix");
        }
        for verb in ["x-y z", "12", "", "abcdef"] {
            assert_eq!(Command::new(verb, None).to_bytes(), Err(Error::Unwritable));
        }
        assert_eq!(
            Command::new("retr", Some("x")).to_bytes(),
            Err(Error::Unwritable)
        );
        let fits = "x".repeat(MAX_LINE - 7);
        let request = Request::Stor(fits.clone());
        assert_eq!(request.to_bytes().unwrap().len(), MAX_LINE);
        contract::check_wire_value(&request);
        assert_eq!(
            Request::Stor(format!("{}\r", &fits[1..])).to_bytes(),
            Err(Error::LineTooLong)
        );
        for lines in [
            vec![
                "a\r\n214 x".into(),
                "214 end".into(),
                "214".into(),
                "é".repeat(MAX_LINE),
                "z".into(),
            ],
            vec!["a".into(), "214 end".into(), "z".into()],
            vec!["a".into(), "214".into(), "z".into()],
            vec!["a".into(), "2\r30 x".into(), "end".into()],
            (0..MAX_REPLY_LINES + 5).map(|i| i.to_string()).collect(),
            vec![],
        ] {
            let reply = Reply {
                code: code::HELP,
                lines,
            };
            let mut out = b"prefix".to_vec();
            assert_eq!(reply.write(&mut out), Err(Error::Unwritable));
            assert_eq!(out, b"prefix");
        }
        let reply = Reply {
            code: code::READY,
            lines: vec![
                "a".into(),
                "230 Logged in".into(),
                "999-x".into(),
                "end".into(),
            ],
        };
        assert_eq!(
            reply.to_bytes().unwrap(),
            b"220-a\r\n230 Logged in\r\n999-x\r\n220 end\r\n"
        );
        let one = Reply::new(code::OK, &"x".repeat(2 * MAX_LINE));
        assert_eq!(one.to_bytes(), Err(Error::LineTooLong));
        for feature in [
            Feature {
                name: "a b".into(),
                params: Some("p\r\nq\x01\té".into()),
            },
            Feature {
                name: " ".into(),
                params: None,
            },
            Feature {
                name: "X".into(),
                params: Some(String::new()),
            },
            Feature {
                name: "Y".into(),
                params: Some("\x01".into()),
            },
        ] {
            assert_eq!(Reply::feature_list(&[feature]), Err(Error::Unwritable));
        }
        let many: Vec<_> = (0..MAX_REPLY_LINES)
            .map(|i| Feature {
                name: format!("F{i}"),
                params: None,
            })
            .collect();
        assert_eq!(Reply::feature_list(&many), Err(Error::Unwritable));
        let reply = Reply::feature_list(&many[..MAX_FEATURES]).unwrap();
        assert_eq!(reply.features().unwrap().len(), MAX_FEATURES);
        contract::check_wire_value(&reply);
    }

    #[test]
    fn reply_and_feature_line_limits() {
        for at in 0..3 {
            let limit = if at == 1 { MAX_CONTENT } else { MAX_REPLY_TEXT };
            let mut reply = Reply {
                code: code::HELP,
                lines: vec!["start".into(), "middle".into(), "end".into()],
            };
            reply.lines[at] = "x".repeat(limit);
            let bytes = reply.to_bytes().unwrap();
            assert_eq!(Reply::parse(&bytes), Ok(reply.clone()));
            reply.lines[at].push('x');
            let mut out = b"prefix".to_vec();
            assert_eq!(reply.write(&mut out), Err(Error::LineTooLong));
            assert_eq!(out, b"prefix");
        }
        for mut feature in [
            Feature {
                name: "x".repeat(MAX_CONTENT - 1),
                params: None,
            },
            Feature {
                name: "X".into(),
                params: Some("p".repeat(MAX_CONTENT - 3)),
            },
        ] {
            let reply = Reply::feature_list(std::slice::from_ref(&feature)).unwrap();
            assert_eq!(Reply::parse(&reply.to_bytes().unwrap()), Ok(reply));
            if let Some(params) = &mut feature.params {
                params.push('p');
            } else {
                feature.name.push('x');
            }
            assert_eq!(Reply::feature_list(&[feature]), Err(Error::LineTooLong));
        }
        let reply = Reply::new(code::OK, &"x".repeat(MAX_REPLY_TEXT));
        assert_eq!(reply.to_bytes().unwrap().len(), MAX_LINE);
        let reply = Reply::new(code::OK, &"x".repeat(MAX_REPLY_TEXT + 1));
        assert_eq!(reply.lines[0].len(), MAX_REPLY_TEXT + 1);
        assert_eq!(reply.to_bytes(), Err(Error::LineTooLong));
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
    fn streams_read_commands_and_replies() {
        let stream = b"USER a\r\n\r\nPASV\nbad1\r\nQUIT\r\n";
        let want = vec![
            Ok(Command::new("USER", Some("a"))),
            Err(Error::Empty),
            Ok(Command::new("PASV", None)),
            Err(Error::Verb),
            Ok(Command::new("QUIT", None)),
        ];
        assert_eq!(commands(stream), want);
        contract::check_decode_with_alloc_limit(Commands::new, stream, 2 * MAX_LINE);
        let stream = b"220 hi\r\n150-a\r\n b\r\n150 c\r\n226 done\n";
        let got = replies(stream);
        contract::check_decode_with_alloc_limit(Replies::new, stream, 2 * MAX_LINE);
        assert_eq!(got.len(), 3);
        assert_eq!(got[1].as_ref().unwrap().lines, ["a", " b", "c"]);
    }

    #[test]
    fn decoders_take_many_short_lines_in_linear_time() {
        assert_linear(
            "decoders_take_many_short_lines_in_linear_time",
            rounds(125_000),
            |size| {
                let stream = b"NOOP\r\n".repeat(size);
                let got = commands(&stream);
                assert_eq!(got.len(), size);
                assert!(got.iter().all(|c| *c == Ok(Command::new("NOOP", None))));
                let stream = b"200 ok\r\n".repeat(size);
                let got = replies(&stream);
                assert_eq!(got.len(), size);
                assert!(got.iter().all(|r| *r == Ok(Reply::new(code::OK, "ok"))));
            },
        );
    }

    #[test]
    fn decoders_skip_long_lines_after_short_ones() {
        // Lines taken out leave room for a long line to be noticed and
        // skipped, pushed whole or in pieces.
        let long = [
            b"NOOP\r\n".repeat(10),
            vec![b'x'; 2 * MAX_LINE],
            b"\r\nQUIT\r\n".to_vec(),
        ]
        .concat();
        let mut want = vec![Ok(Command::new("NOOP", None)); 10];
        want.push(Err(Error::LineTooLong));
        want.push(Ok(Command::new("QUIT", None)));
        assert_eq!(commands(&long), want);
        contract::check_decode_with_alloc_limit(Commands::new, &long, 2 * MAX_LINE);
    }

    // One test for each finding of the October 2026 review.

    #[test]
    fn streams_bound_input_allocation() {
        let big = [vec![b'x'; 1 << 20], b"yy\r\nNOOP\r\n".to_vec()].concat();
        assert_eq!(
            commands(&big),
            [Err(Error::LineTooLong), Ok(Command::new("NOOP", None))]
        );
        contract::check_decode_with_alloc_limit(Commands::new, &big, 2 * MAX_LINE);
        let mut stream = Stream::new(Commands::new());
        let many = b"NOOP\r\n".repeat(MAX_LINE);
        assert_eq!(stream.push(&many), MAX_LINE);
        assert_eq!(stream.buffered(), MAX_LINE);
        assert_eq!(stream.push(b"NOOP\r\n"), 0);
        let big = [b"200 a\r\n".as_slice(), &vec![b'x'; 1 << 20], b"\r\n"].concat();
        let (items, failure) = decode_all(Replies::new, &big);
        assert_eq!(items, [Ok(Reply::new(code::OK, "a"))]);
        assert_eq!(
            failure,
            Some(Fail::Protocol(FrameError::Reply(Error::LineTooLong)))
        );
        contract::check_decode_with_alloc_limit(Replies::new, &big, 2 * MAX_LINE);
    }

    #[test]
    fn crnul_pathnames_round_trip() {
        // RFC 2640, section 3.1, its own example.
        assert_eq!(
            commands(b"STOR foo\r\0\nboo.bar\r\n"),
            [Ok(Command::new("STOR", Some("foo\r\nboo.bar")))]
        );
        contract::check_decode_with_alloc_limit(
            Commands::new,
            b"STOR foo\r\0\nboo.bar\r\n",
            2 * MAX_LINE,
        );
        assert_eq!(
            Request::Stor("foo\r\nboo.bar".into()).to_bytes().unwrap(),
            b"STOR foo\r\0\nboo.bar\r\n"
        );
        let got = commands(&Request::Dele("a\rb".into()).to_bytes().unwrap());
        assert_eq!(got, [Ok(Command::new("DELE", Some("a\rb")))]);
        // A bare LF still ends a line.
        assert_eq!(commands(b"STOR a\nNOOP\r\n").len(), 2);
    }

    #[test]
    fn telnet_commands_are_dropped() {
        // RFC 959, section 4.1.3: IP and Synch before ABOR.
        assert_eq!(
            commands(b"\xff\xf4\xff\xf2ABOR\r\n"),
            [Ok(Command::new("ABOR", None))]
        );
        assert_eq!(
            commands(b"NO\xff\xfb\x01OP\r\n"),
            [Ok(Command::new("NOOP", None))]
        );
    }

    #[test]
    fn passive_helpers_read_multiline_replies() {
        let r = reply_of(b"227-Preparing\r\n227 Entering Passive Mode (127,0,0,1,19,137)\r\n");
        assert_eq!(
            r.passive_address(),
            Ok(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 19 * 256 + 137))
        );
        let r =
            reply_of(b"229-Preparing (soon)\r\n229 Entering Extended Passive Mode (|||6446|)\r\n");
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
        let want = vec![
            Err(Error::TooManyLines),
            Ok(Reply::new(code::READY, "next")),
        ];
        assert_eq!(replies(&s), want);
        contract::check_decode_with_alloc_limit(Replies::new, &s, 2 * MAX_LINE);
    }

    #[test]
    fn feature_names_keep_their_case() {
        let r = reply_of(b"211-x\r\n x-Custom a\tb\r\n211 End\r\n");
        let f = r.features().unwrap();
        assert_eq!(
            f,
            [Feature {
                name: "x-Custom".into(),
                params: Some("a\tb".into())
            }]
        );
        assert_eq!(Reply::feature_list(&f).unwrap().features(), Ok(f));
        // RFC 2389, section 2.1: parameters are TCHAR.
        assert_eq!(
            reply_of(b"211-x\r\n X \x01\r\n211 End\r\n").features(),
            Err(Error::Feature)
        );
        assert_eq!(
            reply_of("211-x\r\n X é\r\n211 End\r\n".as_bytes()).features(),
            Err(Error::Feature)
        );
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5eed);
        let seeds: &[&[u8]] = &[
            b"USER a\r\nRETR a\r\0\nb\r\nNOOP\r\n",
            b"\xff\xf4\xff\xf2ABOR\r\n",
            b"211-a\r\n123 b\r\n211 c\r\n",
            b"227 (1,2,3,4,5,6)\r\n",
            b"229 (|||123|)\r\n",
            b"211-a\r\n x-Custom a\tb\r\n211 End\r\n",
            b"PORT 1,2,3,4,5,6\r\nEPRT |2|::1|21|\r\nTYPE A N\r\n",
            b"ALLO 1 R 2\r\nREST 10\r\nEPSV ALL\r\n",
        ];
        for _ in 0..4000 {
            let mut data = if rng.coin() {
                seeds[rng.index(seeds.len())].to_vec()
            } else {
                rng.bytes(256)
            };
            if rng.index(16) == 0 {
                data.extend(std::iter::repeat_n(b'x', rng.index(3 * MAX_LINE / 2 + 1)));
                data.extend_from_slice(b"\r\nNOOP\r\n");
            }
            mutate(&mut rng, &mut data);
            contract::check_decode_with_alloc_limit(Commands::new, &data, 2 * MAX_LINE);
            contract::check_decode_with_alloc_limit(Replies::new, &data, 2 * MAX_LINE);
            contract::check_wire::<Command>(&data);
            contract::check_wire::<Reply>(&data);
            contract::check_wire::<Request>(&data);
            contract::check_wire::<PortAddress>(&data);
            contract::check_wire::<EprtAddress>(&data);
            let address = SocketAddrV4::new(Ipv4Addr::from(rng.next() as u32), rng.next() as u16);
            contract::check_wire_value(&PortAddress { address });
            contract::check_wire_value(&EprtAddress {
                address: address.into(),
            });
            for command in commands(&data).iter().flatten() {
                contract::check_wire_value(command);
                command.to_bytes().unwrap();
                if let Ok(request) = Request::from_command(command) {
                    contract::check_wire_value(&request);
                    request.to_bytes().unwrap();
                }
            }
            for reply in replies(&data).iter().flatten() {
                contract::check_wire_value(reply);
                if let Ok(features) = reply.features() {
                    assert_eq!(
                        Reply::feature_list(&features).unwrap().features(),
                        Ok(features)
                    );
                }
                if let Ok(address) = reply.passive_address() {
                    assert_eq!(Reply::passive(address).passive_address(), Ok(address));
                }
                if let Ok(port) = reply.extended_passive_port() {
                    assert_eq!(
                        Reply::extended_passive(port).extended_passive_port(),
                        Ok(port)
                    );
                }
            }
            let bytes = rng.bytes(128);
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let (verb, arg) = text.split_once(' ').unwrap_or((&text, ""));
            contract::check_wire_value(&Command::new(verb, Some(arg)));
            contract::check_wire_value(&Command::new("RETR", Some(&text)));
            for request in [
                Request::Allo(text.clone()),
                Request::Rest(text.clone()),
                Request::Opts(text.clone()),
            ] {
                contract::check_wire_value(&request);
            }
            let lines: Vec<String> = text
                .split('\n')
                .map(|line| match rng.index(8) {
                    0 => format!("{}{}", rng.index(1000), line),
                    1 => format!("123{}", "x".repeat(MAX_CONTENT - 4 + rng.index(3))),
                    _ => line.to_string(),
                })
                .collect();
            if let Some(code) = ReplyCode::new(100 + rng.index(500) as u16)
                && let Ok(reply) = Reply::from_lines(code, lines.clone())
            {
                contract::check_wire_value(&reply);
                assert_eq!(
                    Reply::parse(&reply.to_bytes().unwrap()).as_ref(),
                    Ok(&reply)
                );
                for (i, (line, padded)) in lines.iter().zip(&reply.lines).enumerate() {
                    let middle = i != 0 && i + 1 != lines.len();
                    let numeric = line
                        .as_bytes()
                        .get(..3)
                        .is_some_and(|start| start.iter().all(u8::is_ascii_digit));
                    if middle && numeric {
                        assert_eq!(padded.strip_prefix(' '), Some(line.as_str()));
                    } else {
                        assert_eq!(padded, line);
                    }
                }
            }
        }
    }
}
