//! FTP: reading and writing the control connection's commands and replies,
//! with no I/O.
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
//! ([`ArgumentError`]) with [`code::ARGUMENT_ERROR`] (501).
//!
//! ```
//! use fictionet::stdlib::ftp::{code, CommandDecoder, Reply, ReplyDecoder, Request};
//! use std::net::{Ipv4Addr, SocketAddrV4};
//!
//! // A server answers three commands.
//! let mut commands = CommandDecoder::new();
//! commands.feed(b"USER anonymous\r\nPASV\r\nEPRT |1|10.0.0.5|6275|\r\n");
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
//! replies.feed(b"211-Extensions supported:\r\n EPSV\r\n MLST size*;modify*;\r\n211 End\r\n");
//! let reply = replies.next_reply().unwrap().unwrap();
//! let features = reply.features().unwrap();
//! assert_eq!(features.len(), 2);
//! assert_eq!(features[1].name, "MLST");
//! assert_eq!(features[1].params.as_deref(), Some("size*;modify*;"));
//! ```

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
    /// one.
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
    /// The line was not UTF-8, or held a carriage return or a NUL byte.
    Text,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CommandError::LineTooLong => "command line too long",
            CommandError::Empty => "empty command line",
            CommandError::Verb => "command verb is not one to four letters",
            CommandError::Text => "command line is not UTF-8 text without CR or NUL",
        })
    }
}

impl std::error::Error for CommandError {}

impl Command {
    /// A command with `verb` and `arg`.
    pub fn new(verb: &str, arg: Option<&str>) -> Command {
        Command { verb: verb.to_string(), arg: arg.map(str::to_string) }
    }

    /// Reads one command line, without its line ending.
    pub fn parse(line: &[u8]) -> Result<Command, CommandError> {
        if line.len() > MAX_CONTENT {
            return Err(CommandError::LineTooLong);
        }
        let line = text(line).ok_or(CommandError::Text)?;
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

    /// The command line's bytes, ending in CRLF. The verb keeps only its
    /// first four letters, in upper case, and a verb with none becomes
    /// `NOOP`. The argument loses any CR, LF and NUL, and is cut so the
    /// line fits in [`MAX_LINE`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut verb: String = self
            .verb
            .chars()
            .filter(char::is_ascii_alphabetic)
            .take(MAX_VERB)
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if verb.is_empty() {
            verb.push_str("NOOP");
        }
        let mut out = verb.into_bytes();
        if let Some(arg) = &self.arg {
            let arg = clean(arg);
            let room = MAX_CONTENT - out.len() - 1;
            out.push(b' ');
            out.extend_from_slice(cut(&arg, room).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
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
    /// `ALLO`: set aside this much space, as written.
    Allo(String),
    /// `REST`: start the next transfer at this marker. In stream mode it
    /// is a byte offset (RFC 3659, section 5).
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
    /// `OPTS`: set options for a command, as written.
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
            "ALLO" => Request::Allo(need()?),
            "REST" => Request::Rest(need()?),
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
            "OPTS" => Request::Opts(need()?),
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
        let (verb, arg): (&str, Option<String>) = match self {
            Request::User(a) => ("USER", Some(a.clone())),
            Request::Pass(a) => ("PASS", Some(a.clone())),
            Request::Acct(a) => ("ACCT", Some(a.clone())),
            Request::Cwd(a) => ("CWD", Some(a.clone())),
            Request::Cdup => ("CDUP", None),
            Request::Smnt(a) => ("SMNT", Some(a.clone())),
            Request::Rein => ("REIN", None),
            Request::Quit => ("QUIT", None),
            Request::Port(addr) => ("PORT", Some(write_port(*addr))),
            Request::Pasv => ("PASV", None),
            Request::Type(t) => ("TYPE", Some(write_type(*t))),
            Request::Stru(s) => {
                let s = match s {
                    Structure::File => "F",
                    Structure::Record => "R",
                    Structure::Page => "P",
                };
                ("STRU", Some(s.to_string()))
            }
            Request::Mode(m) => {
                let m = match m {
                    TransferMode::Stream => "S",
                    TransferMode::Block => "B",
                    TransferMode::Compressed => "C",
                };
                ("MODE", Some(m.to_string()))
            }
            Request::Retr(a) => ("RETR", Some(a.clone())),
            Request::Stor(a) => ("STOR", Some(a.clone())),
            Request::Stou => ("STOU", None),
            Request::Appe(a) => ("APPE", Some(a.clone())),
            Request::Allo(a) => ("ALLO", Some(a.clone())),
            Request::Rest(a) => ("REST", Some(a.clone())),
            Request::Rnfr(a) => ("RNFR", Some(a.clone())),
            Request::Rnto(a) => ("RNTO", Some(a.clone())),
            Request::Abor => ("ABOR", None),
            Request::Dele(a) => ("DELE", Some(a.clone())),
            Request::Rmd(a) => ("RMD", Some(a.clone())),
            Request::Mkd(a) => ("MKD", Some(a.clone())),
            Request::Pwd => ("PWD", None),
            Request::List(a) => ("LIST", a.clone()),
            Request::Nlst(a) => ("NLST", a.clone()),
            Request::Site(a) => ("SITE", Some(a.clone())),
            Request::Syst => ("SYST", None),
            Request::Stat(a) => ("STAT", a.clone()),
            Request::Help(a) => ("HELP", a.clone()),
            Request::Noop => ("NOOP", None),
            Request::Eprt(addr) => ("EPRT", Some(write_eprt(*addr))),
            Request::Epsv(a) => (
                "EPSV",
                a.map(|a| match a {
                    EpsvArg::Protocol(n) => n.to_string(),
                    EpsvArg::All => "ALL".to_string(),
                }),
            ),
            Request::Feat => ("FEAT", None),
            Request::Opts(a) => ("OPTS", Some(a.clone())),
            Request::Mdtm(a) => ("MDTM", Some(a.clone())),
            Request::Size(a) => ("SIZE", Some(a.clone())),
            Request::Mlst(a) => ("MLST", a.clone()),
            Request::Mlsd(a) => ("MLSD", a.clone()),
            Request::Other(c) => return c.clone(),
        };
        Command { verb: verb.to_string(), arg }
    }

    /// The request's command line, ending in CRLF.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_command().to_bytes()
    }
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
/// the last, and the lines between are text as it is (RFC 959, section
/// 4.2):
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

/// Why bytes are not an FTP reply. The stream holds no more replies a
/// reader can find, and a client closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// A line was longer than [`MAX_LINE`].
    LineTooLong,
    /// A line was not UTF-8, or held a carriage return or a NUL byte.
    Text,
    /// A reply did not start with a code from 100 to 599 followed by a
    /// space, a hyphen or the end of the line.
    Syntax,
    /// A reply ran to more than [`MAX_REPLY_LINES`] lines.
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
    /// The feature's name, such as `MDTM`, in upper case. Names are
    /// case-insensitive, and a reader turns them to upper case.
    pub name: String,
    /// Everything after the space that follows the name, or `None` if no
    /// space follows it.
    pub params: Option<String>,
}

/// Why a reply is not a list of features.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureError {
    /// The reply's code was not 211.
    Code(ReplyCode),
    /// A feature line did not start with a space and a name of printable
    /// ASCII characters.
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
    /// A reply of one line.
    pub fn new(code: ReplyCode, text: &str) -> Reply {
        Reply { code, lines: vec![text.to_string()] }
    }

    /// Reads the reply at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the reply and how many bytes
    /// of `b` it took. Lines end in CRLF, or in LF alone.
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
    /// first and the last that would read as the last gets a space in
    /// front, as RFC 959 asks. A reply with more than [`MAX_REPLY_LINES`]
    /// lines keeps the first ones and the last. A reply with no lines is
    /// written with empty text.
    pub fn to_bytes(&self) -> Vec<u8> {
        let code = self.code.get().to_string();
        let mut out = Vec::new();
        let n = self.lines.len();
        if n <= 1 {
            let text = self.lines.first().map(|t| clean(t)).unwrap_or_default();
            push_line(&mut out, &format!("{code} {}", cut(&text, MAX_REPLY_TEXT)));
            return out;
        }
        let keep = n.min(MAX_REPLY_LINES);
        push_line(&mut out, &format!("{code}-{}", cut(&clean(&self.lines[0]), MAX_REPLY_TEXT)));
        for line in &self.lines[1..keep - 1] {
            let line = clean(line);
            if ends(&line, self.code) {
                push_line(&mut out, &format!(" {}", cut(&line, MAX_CONTENT - 1)));
            } else {
                push_line(&mut out, cut(&line, MAX_CONTENT));
            }
        }
        push_line(&mut out, &format!("{code} {}", cut(&clean(&self.lines[n - 1]), MAX_REPLY_TEXT)));
        out
    }

    /// The reply to `PASV`: code 227 and the address in the form RFC 959
    /// gives, `Entering Passive Mode (h1,h2,h3,h4,p1,p2).`
    pub fn passive(addr: SocketAddrV4) -> Reply {
        Reply::new(code::PASSIVE, &format!("Entering Passive Mode ({}).", write_port(addr)))
    }

    /// The address in a reply to `PASV`. Servers word the reply in
    /// different ways, so this reads the six numbers from the first digit
    /// of the first line on, as RFC 1123 (section 4.1.2.6) advises.
    pub fn passive_address(&self) -> Result<SocketAddrV4, AddressError> {
        if self.code != code::PASSIVE {
            return Err(AddressError::Code);
        }
        let line = self.lines.first().ok_or(AddressError::Syntax)?;
        let start = line.find(|c: char| c.is_ascii_digit()).ok_or(AddressError::Syntax)?;
        scan_host_port(&line[start..]).map(|(addr, _)| addr).ok_or(AddressError::Syntax)
    }

    /// The reply to `EPSV`: code 229 and the port in the form RFC 2428
    /// gives, `Entering Extended Passive Mode (|||port|)`.
    pub fn extended_passive(port: u16) -> Reply {
        Reply::new(code::EXTENDED_PASSIVE, &format!("Entering Extended Passive Mode (|||{port}|)"))
    }

    /// The port in a reply to `EPSV`: the number in `(|||port|)` on the
    /// first line, where `|` may be any printable ASCII character.
    pub fn extended_passive_port(&self) -> Result<u16, AddressError> {
        if self.code != code::EXTENDED_PASSIVE {
            return Err(AddressError::Code);
        }
        let line = self.lines.first().ok_or(AddressError::Syntax)?;
        let open = line.find('(').ok_or(AddressError::Syntax)?;
        let inside = &line[open + 1..];
        let d = inside.chars().next().filter(|c| c.is_ascii_graphic()).ok_or(AddressError::Syntax)?;
        let mut fields = inside[1..].split(d);
        let (Some(""), Some(""), Some(port), Some(rest)) = (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(AddressError::Syntax);
        };
        if !rest.starts_with(')') {
            return Err(AddressError::Syntax);
        }
        decimal(port, 5).and_then(|n| u16::try_from(n).ok()).ok_or(AddressError::Syntax)
    }

    /// The reply to `FEAT` that lists `features` (RFC 2389, section 3.2).
    /// With none it is the one line `211 No features.`. A name keeps only
    /// its printable ASCII characters, in upper case, and a feature whose
    /// name has none is left out. At most [`MAX_FEATURES`] are listed.
    pub fn feature_list(features: &[Feature]) -> Reply {
        let mut lines = vec!["Extensions supported:".to_string()];
        for f in features {
            if lines.len() > MAX_FEATURES {
                break;
            }
            let name: String = f.name.chars().filter(char::is_ascii_graphic).map(|c| c.to_ascii_uppercase()).collect();
            if name.is_empty() {
                continue;
            }
            match &f.params {
                Some(p) => lines.push(format!(" {name} {}", clean(p))),
                None => lines.push(format!(" {name}")),
            }
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
                    Some((name, params)) => (name, Some(params.to_string())),
                    None => (rest, None),
                };
                if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(FeatureError::Line);
                }
                Ok(Feature { name: name.to_ascii_uppercase(), params })
            })
            .collect()
    }
}

/// Builds a reply from its lines, one at a time.
#[derive(Clone, Debug, Default)]
struct Builder {
    /// The code and lines so far of a multi-line reply.
    open: Option<(ReplyCode, Vec<String>)>,
}

impl Builder {
    /// Takes one line's content. It returns the reply that line finishes,
    /// if it finishes one.
    fn take(&mut self, line: &[u8]) -> Result<Option<Reply>, ReplyError> {
        let line = text(line).ok_or(ReplyError::Text)?;
        if let Some((code, lines)) = &mut self.open {
            if ends(line, *code) {
                let code = *code;
                let mut lines = std::mem::take(lines);
                lines.push(line.get(4..).unwrap_or("").to_string());
                self.open = None;
                return Ok(Some(Reply { code, lines }));
            }
            // Leave room for the last line.
            if lines.len() + 1 >= MAX_REPLY_LINES {
                return Err(ReplyError::TooManyLines);
            }
            lines.push(line.to_string());
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
                self.open = Some((code, vec![rest]));
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

/// Finds the first line in `b`. A line ends at LF, and a CR right before
/// the LF is not part of its content. A line's content may be at most
/// [`MAX_LINE`] less 2 bytes.
fn split_line(b: &[u8]) -> Split {
    let window = &b[..b.len().min(MAX_LINE)];
    match window.iter().position(|&c| c == b'\n') {
        Some(i) => {
            let end = if i > 0 && b[i - 1] == b'\r' { i - 1 } else { i };
            if end > MAX_CONTENT { Split::TooLong(Some(i + 1)) } else { Split::Line { end, used: i + 1 } }
        }
        None if b.len() >= MAX_LINE => Split::TooLong(None),
        None => Split::Partial,
    }
}

/// Splits a byte stream into lines, and skips lines that are too long.
#[derive(Clone, Debug, Default)]
struct Lines {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped when they make up half of `buf`, so taking many short lines
    /// out of one large feed takes linear time.
    start: usize,
    /// Whether the bytes up to the next LF belong to a line too long to
    /// keep.
    skipping: bool,
    /// How many bytes after `start` are known to hold no LF.
    scanned: usize,
}

impl Lines {
    fn feed(&mut self, mut bytes: &[u8]) {
        if self.skipping {
            match bytes.iter().position(|&c| c == b'\n') {
                Some(i) => {
                    self.skipping = false;
                    bytes = &bytes[i + 1..];
                }
                None => return,
            }
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
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
        if held.len() < MAX_LINE && !held[from..].contains(&b'\n') {
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
                match held.iter().position(|&c| c == b'\n') {
                    Some(i) => self.take(i + 1),
                    None => {
                        self.clear();
                        self.skipping = true;
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

    /// Adds bytes read from the connection.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.lines.feed(bytes);
    }

    /// The next whole line, read as a command. It returns `None` when it
    /// needs more bytes. An error covers one line only, and the next call
    /// reads the line after it. A decoder never holds more than one line's
    /// bytes beyond what has been taken out, plus what one `feed` added.
    pub fn next_command(&mut self) -> Option<Result<Command, CommandError>> {
        Some(match self.lines.next_line()? {
            Ok(line) => Command::parse(&line),
            Err(()) => Err(CommandError::LineTooLong),
        })
    }

    /// How many bytes are held, waiting for the rest of a line.
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

    /// Adds bytes read from the connection. After a [`ReplyError`] the
    /// stream cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            self.lines.feed(bytes);
        }
    }

    /// The next whole reply, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A decoder holds at most [`MAX_REPLY_LINES`] lines
    /// of one reply, plus what one `feed` added.
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
                Err(e) => {
                    self.failed = Some(e);
                    self.lines = Lines::default();
                    self.builder = Builder::default();
                    return Some(Err(e));
                }
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a line.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;

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
            while let Some(c) = d.next_command() {
                out.push(c);
            }
        }
        out
    }

    /// Replies up to and including the first error.
    fn replies(stream: &[u8], bytewise: bool) -> Vec<Result<Reply, ReplyError>> {
        let mut d = ReplyDecoder::new();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = if bytewise { stream.chunks(1).collect() } else { vec![stream] };
        for chunk in chunks {
            d.feed(chunk);
            while let Some(r) = d.next_reply() {
                let stop = r.is_err();
                out.push(r);
                if stop {
                    return out;
                }
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
        assert_eq!(Request::Port(to).to_bytes(), b"PORT 132,235,1,2,24,131\r\n");
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
        // Names in lower case are read in upper case.
        let f = reply_of(b"211-x\r\n mdtm \r\n211 e\r\n").features().unwrap();
        assert_eq!(f, [Feature { name: "MDTM".into(), params: Some(String::new()) }]);
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
        ];
        let stream: Vec<u8> = all.iter().flat_map(Request::to_bytes).collect();
        let back: Vec<_> = commands(&stream).into_iter().map(|c| Request::from_command(&c.unwrap()).unwrap()).collect();
        assert_eq!(back, all);
    }

    #[test]
    fn command_errors() {
        assert_eq!(Command::parse(b""), Err(CommandError::Empty));
        assert_eq!(Command::parse(b" USER x"), Err(CommandError::Verb));
        assert_eq!(Command::parse(b"USERS x"), Err(CommandError::Verb));
        assert_eq!(Command::parse(b"US3R x"), Err(CommandError::Verb));
        assert_eq!(Command::parse(b"\xff\xf4ABOR"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"RETR a\rb"), Err(CommandError::Text));
        assert_eq!(Command::parse(b"RETR a\0b"), Err(CommandError::Text));
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
        d.feed(b"200 ok\r\nhello\r\n200 ok\r\n");
        assert_eq!(d.next_reply(), Some(Ok(Reply::new(code::OK, "ok"))));
        assert_eq!(d.next_reply(), Some(Err(ReplyError::Syntax)));
        d.feed(b"200 ok\r\n");
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
            d.feed(b"x");
            while d.next_command().is_some() {}
            assert!(d.buffered() < MAX_LINE);
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
        // CR and LF cannot start another command.
        let c = Request::Retr("a\r\nDELE b".into());
        let got = commands(&c.to_bytes());
        assert_eq!(got, [Ok(Command::new("RETR", Some("aDELE b")))]);
        // Bad verbs are cleaned.
        assert_eq!(Command::new("x-y z", None).to_bytes(), b"XYZ\r\n");
        assert_eq!(Command::new("12", Some("a")).to_bytes(), b"NOOP a\r\n");
        assert_eq!(Command::new("abcdef", None).to_bytes(), b"ABCD\r\n");
        // Long arguments are cut on a character boundary.
        let long = Request::Stor("é".repeat(MAX_LINE));
        let bytes = long.to_bytes();
        assert!(bytes.len() <= MAX_LINE);
        let Ok(Request::Stor(name)) = Request::from_command(&commands(&bytes)[0].clone().unwrap()) else { panic!() };
        assert!(name.len() >= MAX_LINE - 8);
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
        // Features: bad names are cleaned or left out, and the list capped.
        let f = vec![
            Feature { name: "a b".into(), params: Some("p\r\nq".into()) },
            Feature { name: " ".into(), params: None },
        ];
        let got = Reply::feature_list(&f).features().unwrap();
        assert_eq!(got, [Feature { name: "AB".into(), params: Some("pq".into()) }]);
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
        let mut d = CommandDecoder::new();
        d.feed(&stream);
        let mut n = 0;
        while let Some(c) = d.next_command() {
            assert_eq!(c, Ok(Command::new("NOOP", None)));
            n += 1;
        }
        assert_eq!(n, 500_000);
        assert_eq!(d.buffered(), 0);
        let stream = b"200 ok\r\n".repeat(500_000);
        let mut d = ReplyDecoder::new();
        d.feed(&stream);
        let mut n = 0;
        while let Some(r) = d.next_reply() {
            assert_eq!(r, Ok(Reply::new(code::OK, "ok")));
            n += 1;
        }
        assert_eq!(n, 500_000);
        assert_eq!(d.buffered(), 0);
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
            let mut d = CommandDecoder::new();
            let mut got = Vec::new();
            for chunk in long.chunks(size) {
                d.feed(chunk);
                got.extend(std::iter::from_fn(|| d.next_command()));
                assert!(d.buffered() < MAX_LINE + size);
            }
            assert_eq!(got, want, "chunks of {size}");
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
                    assert_eq!(Request::from_command(again[0].as_ref().unwrap()), Ok(r));
                }
            }
            let got = replies(&data, false);
            assert_eq!(got, replies(&data, true));
            for r in got.iter().flatten() {
                assert_eq!(reply_of(&r.to_bytes()), *r);
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
