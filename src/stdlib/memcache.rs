//! memcached: reading and writing the text protocol, the binary protocol
//! and UDP frames, with no I/O.
//!
//! memcached is a cache that keeps values under keys in memory. Web
//! applications put it in front of slow databases, and many other servers
//! speak its protocol. Clients reach it over TCP or UDP, usually on port
//! 11211. The text protocol is lines of words, each ended by CR LF. A
//! command that stores a value, and a reply that returns one, follows its
//! line with a data block whose length the line states. The meta commands
//! (`mg`, `ms`, `md`, `ma`, `mn` and `me`) are the newer part of the text
//! protocol, with one-letter flags. The binary protocol puts each message
//! behind a 24-byte header. Over UDP, each datagram starts with an 8-byte
//! frame header. This module follows `protocol.txt` in the memcached
//! repository and the binary protocol pages of the memcached wiki.
//!
//! Nothing here reads a socket. A world that plays a memcached server feeds
//! the bytes it reads from a TCP connection to a [`CommandDecoder`], takes
//! [`Command`]s out, and writes each reply's bytes, made with
//! [`Response::to_bytes`], back to the connection. A world that plays a
//! client does the reverse with a [`ResponseDecoder`]. A [`BinaryDecoder`]
//! splits a binary protocol stream into [`Packet`]s, and [`UdpFrame`] reads
//! and writes the header on each datagram. What the cache holds, and when
//! entries expire, is up to world code.
//!
//! Every reader checks keys, line lengths, numbers and data lengths,
//! because the agent can send any bytes it likes. A command that breaks the
//! protocol becomes an [`Error`], and [`Error::reply`] is what memcached
//! answers it with. Only a line longer than [`MAX_LINE`] breaks the stream
//! for good, since memcached closes the connection then. Writers check the
//! same rules and refuse what a reader would refuse.
//!
//! ```
//! use std::collections::HashMap;
//! use fictionet::stdlib::memcache::{Command, CommandDecoder, Response};
//!
//! let mut cache: HashMap<Vec<u8>, (u32, Vec<u8>)> = HashMap::new();
//! let mut decoder = CommandDecoder::new();
//! decoder.feed(b"set greeting 5 0 5\r\nhello\r\nget greeting other\r\nfrob\r\n");
//! let mut out = Vec::new();
//! while let Some(command) = decoder.next_command() {
//!     let replies = match command {
//!         Ok(Command::Store { key, flags, data, .. }) => {
//!             cache.insert(key, (flags, data));
//!             vec![Response::Stored]
//!         }
//!         Ok(Command::Get { keys, .. }) => {
//!             let mut replies = Vec::new();
//!             for key in keys {
//!                 if let Some((flags, data)) = cache.get(&key) {
//!                     replies.push(Response::Value { key, flags: *flags, cas: None, data: data.clone() });
//!                 }
//!             }
//!             replies.push(Response::End);
//!             replies
//!         }
//!         Ok(_) => vec![Response::Error],
//!         Err(e) => vec![e.reply()],
//!     };
//!     for reply in replies {
//!         out.extend(reply.to_bytes().unwrap());
//!     }
//! }
//! assert_eq!(out, b"STORED\r\nVALUE greeting 5 5\r\nhello\r\nEND\r\nERROR\r\n");
//! ```

/// The port memcached listens on, for both TCP and UDP.
pub const PORT: u16 = 11211;
/// The longest key, in bytes.
pub const MAX_KEY: usize = 250;
/// The longest text protocol line, counting its CR LF. A longer line
/// breaks the stream.
pub const MAX_LINE: usize = 8192;
/// The longest data block a reader takes in, and a writer writes. It is
/// memcached's default item size limit, 1 MiB.
pub const MAX_VALUE: usize = 1024 * 1024;
/// The largest data length a line may state. A larger one is a format
/// error, as in memcached, which reads it into a 32-bit signed number.
pub const MAX_DECLARED: usize = i32::MAX as usize - 2;
/// The most flags one meta command or meta reply may carry.
pub const MAX_META_FLAGS: usize = 24;

/// Why a text protocol line, or a data block after it, cannot be read or
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The line was longer than [`MAX_LINE`]. The stream cannot be read
    /// any further, and a real server closes the connection.
    LineTooLong,
    /// The first word was not a command, or not a reply, this module
    /// knows. An empty line is one too. A command with too few or too many
    /// words is one as well, since memcached answers both with `ERROR`.
    UnknownCommand,
    /// A number was not a number or out of range, a word held a space or
    /// control byte, or a meta command, `delete`, `gat` or a reply had the
    /// wrong words.
    Format,
    /// The delta of `incr` or `decr` was not a number from 0 to
    /// `u64::MAX`.
    Delta,
    /// The expiration time of `touch`, `gat` or `gats` was not a number
    /// that fits in 32 signed bits.
    Exptime,
    /// A key was longer than [`MAX_KEY`], or held a space or control byte.
    Key,
    /// The data block was longer than [`MAX_VALUE`], by the length the
    /// line stated. A decoder skips the block, as memcached does.
    TooLarge(usize),
    /// The data block did not end with CR LF. A decoder has skipped it.
    BadDataChunk,
}

impl Error {
    /// Whether the stream is broken for good. Only [`Error::LineTooLong`]
    /// is. After any other error a decoder goes on with the next line.
    pub fn is_fatal(self) -> bool {
        self == Error::LineTooLong
    }

    /// The reply memcached sends a client for this error.
    pub fn reply(self) -> Response {
        match self {
            Error::LineTooLong => Response::ClientError(b"line too long".to_vec()),
            Error::UnknownCommand => Response::Error,
            Error::Format | Error::Key => Response::ClientError(b"bad command line format".to_vec()),
            Error::Delta => Response::ClientError(b"invalid numeric delta argument".to_vec()),
            Error::Exptime => Response::ClientError(b"invalid exptime argument".to_vec()),
            Error::TooLarge(_) => Response::ServerError(b"object too large for cache".to_vec()),
            Error::BadDataChunk => Response::ClientError(b"bad data chunk".to_vec()),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::LineTooLong => write!(f, "line longer than {MAX_LINE} bytes"),
            Error::UnknownCommand => f.write_str("unknown command"),
            Error::Format => f.write_str("bad command line format"),
            Error::Delta => f.write_str("delta not a number from 0 to 2^64 - 1"),
            Error::Exptime => f.write_str("expiration time not a 32-bit signed number"),
            Error::Key => write!(f, "key empty, over {MAX_KEY} bytes, or holding a space or control byte"),
            Error::TooLarge(n) => write!(f, "data block of {n} bytes, over {MAX_VALUE}"),
            Error::BadDataChunk => f.write_str("data block not ended by CR LF"),
        }
    }
}

impl std::error::Error for Error {}

/// The storage commands that differ only in when they store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreVerb {
    /// `set`: store the value.
    Set,
    /// `add`: store it only if the key holds nothing.
    Add,
    /// `replace`: store it only if the key holds something.
    Replace,
    /// `append`: add the data after what the key holds.
    Append,
    /// `prepend`: add the data before what the key holds.
    Prepend,
}

impl StoreVerb {
    /// The command's name, as written on the line.
    pub fn name(self) -> &'static str {
        match self {
            StoreVerb::Set => "set",
            StoreVerb::Add => "add",
            StoreVerb::Replace => "replace",
            StoreVerb::Append => "append",
            StoreVerb::Prepend => "prepend",
        }
    }

    fn from_name(name: &[u8]) -> Option<StoreVerb> {
        Some(match name {
            b"set" => StoreVerb::Set,
            b"add" => StoreVerb::Add,
            b"replace" => StoreVerb::Replace,
            b"append" => StoreVerb::Append,
            b"prepend" => StoreVerb::Prepend,
            _ => return None,
        })
    }
}

/// One flag of a meta command or meta reply: a single byte, then a token
/// that may be empty. In `T90`, the flag is `T` and the token is `90`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaFlag {
    /// The flag's letter.
    pub flag: u8,
    /// What follows the letter, up to the next space.
    pub token: Vec<u8>,
}

impl MetaFlag {
    /// A flag with its token.
    pub fn new(flag: u8, token: &[u8]) -> MetaFlag {
        MetaFlag { flag, token: token.to_vec() }
    }
}

/// The token of the first flag in `flags` with the letter `flag`, if
/// there is one.
pub fn meta_token(flags: &[MetaFlag], flag: u8) -> Option<&[u8]> {
    flags.iter().find(|f| f.flag == flag).map(|f| &f.token[..])
}

/// A text protocol command: what a client asks a server to do. Keys are
/// kept as bytes. Expiration times are seconds from now, or a Unix time
/// if over 30 days. A negative one expires the item at once. They are 32-bit
/// signed numbers, as in memcached.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Command {
    /// `set`, `add`, `replace`, `append` or `prepend`: store `data` under
    /// `key` with the client's `flags` and expiration time `exptime`. With
    /// `noreply` the server sends nothing back.
    Store { verb: StoreVerb, key: Vec<u8>, flags: u32, exptime: i32, data: Vec<u8>, noreply: bool },
    /// `cas`: store as `set` does, only if the item's CAS value is still
    /// `unique`.
    Cas { key: Vec<u8>, flags: u32, exptime: i32, unique: u64, data: Vec<u8>, noreply: bool },
    /// `get`, or `gets` when `cas` is set: the values of `keys`.
    Get { keys: Vec<Vec<u8>>, cas: bool },
    /// `gat`, or `gats` when `cas` is set: the values of `keys`, also
    /// setting their expiration time to `exptime`.
    Gat { exptime: i32, keys: Vec<Vec<u8>>, cas: bool },
    /// `delete`: remove `key`.
    Delete { key: Vec<u8>, noreply: bool },
    /// `incr`: add `delta` to the number `key` holds.
    Incr { key: Vec<u8>, delta: u64, noreply: bool },
    /// `decr`: subtract `delta` from the number `key` holds, stopping at 0.
    Decr { key: Vec<u8>, delta: u64, noreply: bool },
    /// `touch`: set the expiration time of `key`.
    Touch { key: Vec<u8>, exptime: i32, noreply: bool },
    /// `stats`, with any words after it, such as `items` or `slabs`.
    Stats { args: Vec<Vec<u8>> },
    /// `version`: the server's version.
    Version,
    /// `verbosity`: set how much the server logs.
    Verbosity { level: u32, noreply: bool },
    /// `flush_all`: drop every item, now or after `delay` seconds.
    FlushAll { delay: Option<i32>, noreply: bool },
    /// `quit`: the client is done. The server closes the connection.
    Quit,
    /// `mg`: read `key`, returning what `flags` ask for.
    MetaGet { key: Vec<u8>, flags: Vec<MetaFlag> },
    /// `ms`: store `data` under `key`, as `flags` say.
    MetaSet { key: Vec<u8>, flags: Vec<MetaFlag>, data: Vec<u8> },
    /// `md`: delete `key`, as `flags` say.
    MetaDelete { key: Vec<u8>, flags: Vec<MetaFlag> },
    /// `ma`: add to or subtract from the number `key` holds, as `flags` say.
    MetaArithmetic { key: Vec<u8>, flags: Vec<MetaFlag> },
    /// `me`: what the server knows about the item under `key`.
    MetaDebug { key: Vec<u8>, flags: Vec<MetaFlag> },
    /// `mn`: nothing. The server answers `MN`, which marks the end of a
    /// batch of quiet commands.
    MetaNoop,
}

impl Command {
    /// The command's bytes: its line, then its data block if it has one.
    /// It refuses what a reader would refuse: a bad key, an empty key list,
    /// a word with a space or control byte, more than [`MAX_META_FLAGS`]
    /// flags, a line over [`MAX_LINE`] or data over [`MAX_VALUE`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut line = Vec::new();
        let mut data = None;
        match self {
            Command::Store { verb, key, flags, exptime, data: d, noreply } => {
                word(&mut line, verb.name().as_bytes());
                put_key(&mut line, key)?;
                number(&mut line, flags);
                number(&mut line, exptime);
                number(&mut line, d.len());
                put_noreply(&mut line, *noreply);
                data = Some(d);
            }
            Command::Cas { key, flags, exptime, unique, data: d, noreply } => {
                word(&mut line, b"cas");
                put_key(&mut line, key)?;
                number(&mut line, flags);
                number(&mut line, exptime);
                number(&mut line, d.len());
                number(&mut line, unique);
                put_noreply(&mut line, *noreply);
                data = Some(d);
            }
            Command::Get { keys, cas } => {
                word(&mut line, if *cas { b"gets" } else { b"get" });
                put_keys(&mut line, keys)?;
            }
            Command::Gat { exptime, keys, cas } => {
                word(&mut line, if *cas { b"gats" } else { b"gat" });
                number(&mut line, exptime);
                put_keys(&mut line, keys)?;
            }
            Command::Delete { key, noreply } => {
                word(&mut line, b"delete");
                put_key(&mut line, key)?;
                put_noreply(&mut line, *noreply);
            }
            Command::Incr { key, delta, noreply } | Command::Decr { key, delta, noreply } => {
                word(&mut line, if matches!(self, Command::Incr { .. }) { b"incr" } else { b"decr" });
                put_key(&mut line, key)?;
                number(&mut line, delta);
                put_noreply(&mut line, *noreply);
            }
            Command::Touch { key, exptime, noreply } => {
                word(&mut line, b"touch");
                put_key(&mut line, key)?;
                number(&mut line, exptime);
                put_noreply(&mut line, *noreply);
            }
            Command::Stats { args } => {
                word(&mut line, b"stats");
                for a in args {
                    put_token(&mut line, a)?;
                }
            }
            Command::Version => word(&mut line, b"version"),
            Command::Verbosity { level, noreply } => {
                word(&mut line, b"verbosity");
                number(&mut line, level);
                put_noreply(&mut line, *noreply);
            }
            Command::FlushAll { delay, noreply } => {
                word(&mut line, b"flush_all");
                if let Some(d) = delay {
                    number(&mut line, d);
                }
                put_noreply(&mut line, *noreply);
            }
            Command::Quit => word(&mut line, b"quit"),
            Command::MetaGet { key, flags } => meta_line(&mut line, b"mg", key, None, flags)?,
            Command::MetaSet { key, flags, data: d } => {
                meta_line(&mut line, b"ms", key, Some(d.len()), flags)?;
                data = Some(d);
            }
            Command::MetaDelete { key, flags } => meta_line(&mut line, b"md", key, None, flags)?,
            Command::MetaArithmetic { key, flags } => meta_line(&mut line, b"ma", key, None, flags)?,
            Command::MetaDebug { key, flags } => meta_line(&mut line, b"me", key, None, flags)?,
            Command::MetaNoop => word(&mut line, b"mn"),
        }
        finish(line, data.map(|d| &d[..]))
    }

    /// Whether the client asked for no reply: `noreply` on the classic
    /// commands, or the `q` flag on a meta command. A quiet meta command
    /// still gets a reply when it fails.
    pub fn is_quiet(&self) -> bool {
        match self {
            Command::Store { noreply, .. }
            | Command::Cas { noreply, .. }
            | Command::Delete { noreply, .. }
            | Command::Incr { noreply, .. }
            | Command::Decr { noreply, .. }
            | Command::Touch { noreply, .. }
            | Command::Verbosity { noreply, .. }
            | Command::FlushAll { noreply, .. } => *noreply,
            Command::MetaGet { flags, .. }
            | Command::MetaSet { flags, .. }
            | Command::MetaDelete { flags, .. }
            | Command::MetaArithmetic { flags, .. } => meta_token(flags, b'q').is_some(),
            _ => false,
        }
    }
}

/// The status a meta reply starts with, other than `VA` and `ME`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaStatus {
    /// `HD`: done, with no value.
    Header,
    /// `EN`: the key held nothing.
    Miss,
    /// `NS`: not stored.
    NotStored,
    /// `EX`: the CAS value did not match.
    Exists,
    /// `NF`: not found.
    NotFound,
    /// `MN`: the answer to `mn`.
    Noop,
}

impl MetaStatus {
    /// The status's two letters.
    pub fn code(self) -> &'static str {
        match self {
            MetaStatus::Header => "HD",
            MetaStatus::Miss => "EN",
            MetaStatus::NotStored => "NS",
            MetaStatus::Exists => "EX",
            MetaStatus::NotFound => "NF",
            MetaStatus::Noop => "MN",
        }
    }

    fn from_code(code: &[u8]) -> Option<MetaStatus> {
        Some(match code {
            b"HD" => MetaStatus::Header,
            b"EN" => MetaStatus::Miss,
            b"NS" => MetaStatus::NotStored,
            b"EX" => MetaStatus::Exists,
            b"NF" => MetaStatus::NotFound,
            b"MN" => MetaStatus::Noop,
            _ => return None,
        })
    }
}

/// A text protocol reply: one line a server sends, with its data block if
/// it has one. A `get` is answered by a [`Response::Value`] per item found,
/// then [`Response::End`]; `stats` by a [`Response::Stat`] per number, then
/// [`Response::End`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Response {
    /// `STORED`.
    Stored,
    /// `NOT_STORED`: an `add` or `replace` whose condition failed.
    NotStored,
    /// `EXISTS`: a `cas` whose value had changed.
    Exists,
    /// `NOT_FOUND`.
    NotFound,
    /// `DELETED`.
    Deleted,
    /// `TOUCHED`.
    Touched,
    /// `END`: the last line of a `get` or `stats` answer.
    End,
    /// `OK`: the answer to `flush_all` and `verbosity`.
    Ok,
    /// `ERROR`: the command was not one the server knows.
    Error,
    /// `CLIENT_ERROR`, with a message: the command broke the protocol.
    ClientError(Vec<u8>),
    /// `SERVER_ERROR`, with a message: the server failed.
    ServerError(Vec<u8>),
    /// `VALUE`: one item, with its CAS value if asked with `gets`.
    Value { key: Vec<u8>, flags: u32, cas: Option<u64>, data: Vec<u8> },
    /// `STAT`: one statistic's `name` and `value`.
    Stat { name: Vec<u8>, value: Vec<u8> },
    /// `VERSION`, with the version text.
    Version(Vec<u8>),
    /// The new value after `incr` or `decr`.
    Number(u64),
    /// A meta reply without a value, with the flags it returns.
    Meta { status: MetaStatus, flags: Vec<MetaFlag> },
    /// `VA`: a meta reply with a value.
    MetaValue { flags: Vec<MetaFlag>, data: Vec<u8> },
    /// `ME`: what the server knows about `key`, as `name=value` words.
    MetaDebug { key: Vec<u8>, info: Vec<u8> },
}

impl Response {
    /// The reply's bytes: its line, then its data block if it has one. It
    /// refuses what a reader would refuse, as [`Command::to_bytes`] does.
    /// Message and version text may not hold CR or LF.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut line = Vec::new();
        let mut data = None;
        let fixed: &[u8] = match self {
            Response::Stored => b"STORED",
            Response::NotStored => b"NOT_STORED",
            Response::Exists => b"EXISTS",
            Response::NotFound => b"NOT_FOUND",
            Response::Deleted => b"DELETED",
            Response::Touched => b"TOUCHED",
            Response::End => b"END",
            Response::Ok => b"OK",
            Response::Error => b"ERROR",
            _ => b"",
        };
        match self {
            Response::ClientError(m) => text_line(&mut line, b"CLIENT_ERROR", m)?,
            Response::ServerError(m) => text_line(&mut line, b"SERVER_ERROR", m)?,
            Response::Version(v) => text_line(&mut line, b"VERSION", v)?,
            Response::Value { key, flags, cas, data: d } => {
                word(&mut line, b"VALUE");
                put_key(&mut line, key)?;
                number(&mut line, flags);
                number(&mut line, d.len());
                if let Some(c) = cas {
                    number(&mut line, c);
                }
                data = Some(d);
            }
            Response::Stat { name, value } => {
                word(&mut line, b"STAT");
                put_token(&mut line, name)?;
                check_text(value)?;
                line.push(b' ');
                line.extend_from_slice(value);
            }
            Response::Number(n) => number(&mut line, n),
            Response::Meta { status, flags } => {
                word(&mut line, status.code().as_bytes());
                put_meta_flags(&mut line, flags)?;
            }
            Response::MetaValue { flags, data: d } => {
                word(&mut line, b"VA");
                number(&mut line, d.len());
                put_meta_flags(&mut line, flags)?;
                data = Some(d);
            }
            Response::MetaDebug { key, info } => {
                word(&mut line, b"ME");
                put_key(&mut line, key)?;
                check_text(info)?;
                if !info.is_empty() {
                    line.push(b' ');
                    line.extend_from_slice(info);
                }
            }
            _ => word(&mut line, fixed),
        }
        finish(line, data.map(|d| &d[..]))
    }
}

/// Reads text protocol commands from a client's byte stream, for a world
/// that plays a server. Feed it the bytes a connection reads, in order,
/// and take commands out until it has none.
#[derive(Clone, Debug)]
pub struct CommandDecoder {
    stream: Stream<Command>,
}

impl Default for CommandDecoder {
    fn default() -> CommandDecoder {
        CommandDecoder::new()
    }
}

impl CommandDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> CommandDecoder {
        CommandDecoder { stream: Stream::new() }
    }

    /// Adds bytes read from the connection. After a fatal error they are
    /// dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.stream.feed(bytes);
    }

    /// The next command, if a whole one has come. It returns `None` when it
    /// needs more bytes. A bad line gives an [`Error`] and the decoder goes
    /// on with the next line, as memcached does. After a bad storage line
    /// that means the data block is read as a command too. The exceptions,
    /// also as in memcached, are a block too large to take and an `ms` line
    /// that failed after its length was read: their blocks are dropped.
    /// A fatal error repeats on every call. A decoder holds at most one
    /// line and one data block beyond what has been taken out, plus what
    /// one `feed` added.
    pub fn next_command(&mut self) -> Option<Result<Command, Error>> {
        self.stream.next(parse_command, attach_command)
    }

    /// How many bytes are held, waiting for the rest of a command.
    pub fn buffered(&self) -> usize {
        self.stream.buffered()
    }
}

/// Reads text protocol replies from a server's byte stream, for a world
/// that plays a client. It works as [`CommandDecoder`] does.
#[derive(Clone, Debug)]
pub struct ResponseDecoder {
    stream: Stream<Response>,
}

impl Default for ResponseDecoder {
    fn default() -> ResponseDecoder {
        ResponseDecoder::new()
    }
}

impl ResponseDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> ResponseDecoder {
        ResponseDecoder { stream: Stream::new() }
    }

    /// Adds bytes read from the connection. After a fatal error they are
    /// dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.stream.feed(bytes);
    }

    /// The next reply, if a whole one has come, with the same rules as
    /// [`CommandDecoder::next_command`]. A line it does not know is
    /// [`Error::UnknownCommand`].
    pub fn next_response(&mut self) -> Option<Result<Response, Error>> {
        self.stream.next(parse_response, attach_response)
    }

    /// How many bytes are held, waiting for the rest of a reply.
    pub fn buffered(&self) -> usize {
        self.stream.buffered()
    }
}

/// What reads a line: the message, and the length of the data block that
/// follows it, if one does.
type Head<T> = fn(&[u8]) -> Result<(T, Option<usize>), Fail>;

/// A line that could not be read, and how many bytes after it to drop: the
/// data block the line stated, with its CR LF, or 0.
#[derive(Debug)]
struct Fail {
    error: Error,
    skip: u64,
}

impl From<Error> for Fail {
    fn from(error: Error) -> Fail {
        // A block too large to take is dropped, as memcached does.
        let skip = if let Error::TooLarge(n) = error { n as u64 + 2 } else { 0 };
        Fail { error, skip }
    }
}

/// The line and data block splitter both text decoders share.
#[derive(Clone, Debug)]
struct Stream<T> {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are dropped
    /// in `feed` once they are half the buffer.
    start: usize,
    /// How many bytes from `start` are known to hold no LF, so a line that
    /// comes a byte at a time is searched once.
    scanned: usize,
    /// Bytes still to drop, from a data block that was too large.
    skip: u64,
    /// A line read, waiting for its data block of the given length.
    pending: Option<(T, usize)>,
    broken: bool,
}

impl<T> Stream<T> {
    fn new() -> Stream<T> {
        Stream { buf: Vec::new(), start: 0, scanned: 0, skip: 0, pending: None, broken: false }
    }

    fn feed(&mut self, bytes: &[u8]) {
        if self.broken {
            return;
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    fn next(&mut self, head: Head<T>, attach: fn(&mut T, Vec<u8>)) -> Option<Result<T, Error>> {
        if self.broken {
            return Some(Err(Error::LineTooLong));
        }
        if self.skip > 0 {
            let n = usize::try_from(self.skip).unwrap_or(usize::MAX).min(self.buffered());
            self.start += n;
            self.skip -= n as u64;
            if self.skip > 0 {
                return None;
            }
        }
        if let Some((_, n)) = &self.pending {
            // n is at most MAX_VALUE, so n + 2 cannot overflow.
            let need = *n + 2;
            if self.buffered() < need {
                return None;
            }
            let block = &self.buf[self.start..self.start + need];
            let ended = block.ends_with(b"\r\n");
            let data = block[..need - 2].to_vec();
            self.start += need;
            self.scanned = 0;
            let (mut message, _) = self.pending.take()?;
            if !ended {
                return Some(Err(Error::BadDataChunk));
            }
            attach(&mut message, data);
            return Some(Ok(message));
        }
        let rest = &self.buf[self.start..];
        let window = &rest[..rest.len().min(MAX_LINE)];
        let from = self.scanned.min(window.len());
        let Some(end) = window[from..].iter().position(|&b| b == b'\n').map(|p| p + from) else {
            if rest.len() >= MAX_LINE {
                return Some(Err(self.break_stream()));
            }
            self.scanned = window.len();
            return None;
        };
        let line = &rest[..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        // Written back with CR LF, the line must still fit.
        if line.len() + 2 > MAX_LINE {
            return Some(Err(self.break_stream()));
        }
        let result = head(line);
        self.start += end + 1;
        self.scanned = 0;
        match result {
            Ok((message, None)) => Some(Ok(message)),
            Ok((message, Some(n))) => {
                self.pending = Some((message, n));
                // Takes the block if it has come; this cannot reach here again.
                self.next(head, attach)
            }
            Err(Fail { error, skip }) => {
                self.skip = skip;
                Some(Err(error))
            }
        }
    }

    fn break_stream(&mut self) -> Error {
        self.broken = true;
        self.buf = Vec::new();
        self.start = 0;
        self.scanned = 0;
        self.pending = None;
        Error::LineTooLong
    }
}

fn parse_command(line: &[u8]) -> Result<(Command, Option<usize>), Fail> {
    let mut skip = 0;
    parse_command_line(line, &mut skip).map_err(|error| match Fail::from(error) {
        Fail { skip: 0, .. } => Fail { error, skip },
        fail => fail,
    })
}

/// Reads a command line. When an error comes after the line's data length
/// is known, and the data block should be dropped with it, `skip` says how
/// many bytes that is.
fn parse_command_line(line: &[u8], skip: &mut u64) -> Result<(Command, Option<usize>), Error> {
    let t = tokens(line);
    let Some((&verb, args)) = t.split_first() else { return Err(Error::UnknownCommand) };
    if let Some(verb) = StoreVerb::from_name(verb) {
        let (args, noreply) = optional_noreply(args, 4)?;
        let [key, flags, exptime, bytes] = args else { return Err(Error::UnknownCommand) };
        let (key, flags, exptime, n) = (key_of(key)?, small(flags)?, signed(exptime)?, length(bytes)?);
        return block(Command::Store { verb, key, flags, exptime, data: Vec::new(), noreply }, n);
    }
    let command = match verb {
        b"cas" => {
            let (args, noreply) = optional_noreply(args, 5)?;
            let [key, flags, exptime, bytes, unique] = args else { return Err(Error::UnknownCommand) };
            let (key, flags, exptime, n) = (key_of(key)?, small(flags)?, signed(exptime)?, length(bytes)?);
            let unique = unsigned(unique)?;
            return block(Command::Cas { key, flags, exptime, unique, data: Vec::new(), noreply }, n);
        }
        b"get" | b"gets" => {
            if args.is_empty() {
                return Err(Error::UnknownCommand);
            }
            Command::Get { keys: keys_of(args)?, cas: verb == b"gets" }
        }
        b"gat" | b"gats" => {
            let (exptime, keys) = args.split_first().ok_or(Error::UnknownCommand)?;
            let exptime = signed(exptime).map_err(|_| Error::Exptime)?;
            Command::Gat { exptime, keys: keys_of(keys)?, cas: verb == b"gats" }
        }
        b"delete" => {
            if args.is_empty() || args.len() > 3 {
                return Err(Error::UnknownCommand);
            }
            let (args, noreply) = strip_noreply(args, 1);
            // memcached still takes an old time argument, if it is 0.
            match args {
                [key] => Command::Delete { key: key_of(key)?, noreply },
                [key, time] if *time == b"0" => Command::Delete { key: key_of(key)?, noreply },
                _ => return Err(Error::Format),
            }
        }
        b"incr" | b"decr" => {
            let (args, noreply) = optional_noreply(args, 2)?;
            let [key, delta] = args else { return Err(Error::UnknownCommand) };
            let (key, delta) = (key_of(key)?, unsigned(delta).map_err(|_| Error::Delta)?);
            if verb == b"incr" { Command::Incr { key, delta, noreply } } else { Command::Decr { key, delta, noreply } }
        }
        b"touch" => {
            let (args, noreply) = optional_noreply(args, 2)?;
            let [key, exptime] = args else { return Err(Error::UnknownCommand) };
            let key = key_of(key)?;
            Command::Touch { key, exptime: signed(exptime).map_err(|_| Error::Exptime)?, noreply }
        }
        b"stats" => {
            let args = args.iter().map(|a| token_of(a)).collect::<Result<_, _>>()?;
            Command::Stats { args }
        }
        // memcached ignores any words after these.
        b"version" => Command::Version,
        b"quit" => Command::Quit,
        b"mn" => Command::MetaNoop,
        b"verbosity" => {
            let (args, noreply) = optional_noreply(args, 1)?;
            let [level] = args else { return Err(Error::UnknownCommand) };
            Command::Verbosity { level: small(level)?, noreply }
        }
        b"flush_all" => {
            if args.len() > 2 {
                return Err(Error::UnknownCommand);
            }
            // A final noreply is taken off, and a word after the delay is
            // ignored, as memcached does.
            let (args, noreply) = strip_noreply(args, 0);
            match args.first() {
                None => Command::FlushAll { delay: None, noreply },
                Some(delay) => Command::FlushAll { delay: Some(signed(delay)?), noreply },
            }
        }
        b"ms" => {
            let [key, bytes, flags @ ..] = args else { return Err(Error::Format) };
            // As in memcached, a line with too many flags is refused before
            // its length is read. Once the length is known, a bad flag drops
            // the data block too, so its bytes are not read as commands.
            let key = key_of(key)?;
            if flags.len() > MAX_META_FLAGS {
                return Err(Error::Format);
            }
            let n = length(bytes)?;
            *skip = n as u64 + 2;
            let flags = meta_flags(flags)?;
            return block(Command::MetaSet { key, flags, data: Vec::new() }, n);
        }
        b"mg" | b"md" | b"ma" | b"me" => {
            let [key, flags @ ..] = args else { return Err(Error::Format) };
            let (key, flags) = (key_of(key)?, meta_flags(flags)?);
            match verb {
                b"mg" => Command::MetaGet { key, flags },
                b"md" => Command::MetaDelete { key, flags },
                b"ma" => Command::MetaArithmetic { key, flags },
                _ => Command::MetaDebug { key, flags },
            }
        }
        _ => return Err(Error::UnknownCommand),
    };
    Ok((command, None))
}

fn attach_command(command: &mut Command, block: Vec<u8>) {
    if let Command::Store { data, .. } | Command::Cas { data, .. } | Command::MetaSet { data, .. } = command {
        *data = block;
    }
}

fn parse_response(line: &[u8]) -> Result<(Response, Option<usize>), Fail> {
    parse_response_line(line).map_err(Fail::from)
}

fn parse_response_line(line: &[u8]) -> Result<(Response, Option<usize>), Error> {
    let (first, rest) = match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], Some(&line[i + 1..])),
        None => (line, None),
    };
    let fixed = match first {
        b"STORED" => Some(Response::Stored),
        b"NOT_STORED" => Some(Response::NotStored),
        b"EXISTS" => Some(Response::Exists),
        b"NOT_FOUND" => Some(Response::NotFound),
        b"DELETED" => Some(Response::Deleted),
        b"TOUCHED" => Some(Response::Touched),
        b"END" => Some(Response::End),
        b"OK" => Some(Response::Ok),
        b"ERROR" => Some(Response::Error),
        _ if !first.is_empty() && first.iter().all(u8::is_ascii_digit) => Some(Response::Number(unsigned(first)?)),
        _ => None,
    };
    if let Some(r) = fixed {
        return if rest.is_none() { Ok((r, None)) } else { Err(Error::Format) };
    }
    let text = |t: Option<&[u8]>| -> Result<Vec<u8>, Error> {
        let t = t.unwrap_or(b"");
        check_text(t)?;
        Ok(t.to_vec())
    };
    let response = match first {
        b"CLIENT_ERROR" => Response::ClientError(text(rest)?),
        b"SERVER_ERROR" => Response::ServerError(text(rest)?),
        b"VERSION" => Response::Version(text(rest)?),
        b"STAT" => {
            let rest = rest.ok_or(Error::Format)?;
            let i = rest.iter().position(|&b| b == b' ').ok_or(Error::Format)?;
            Response::Stat { name: token_of(&rest[..i])?, value: text(Some(&rest[i + 1..]))? }
        }
        b"ME" => {
            let rest = rest.ok_or(Error::Format)?;
            let (key, info) = match rest.iter().position(|&b| b == b' ') {
                Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                None => (rest, None),
            };
            Response::MetaDebug { key: key_of(key)?, info: text(info)? }
        }
        b"VALUE" => {
            let t = tokens(rest.unwrap_or(b""));
            let (key, flags, bytes, cas) = match t[..] {
                [key, flags, bytes] => (key, flags, bytes, None),
                [key, flags, bytes, cas] => (key, flags, bytes, Some(unsigned(cas)?)),
                _ => return Err(Error::Format),
            };
            let (key, flags, n) = (key_of(key)?, small(flags)?, length(bytes)?);
            return block(Response::Value { key, flags, cas, data: Vec::new() }, n);
        }
        b"VA" => {
            let t = tokens(rest.unwrap_or(b""));
            let [bytes, flags @ ..] = &t[..] else { return Err(Error::Format) };
            let (n, flags) = (length(bytes)?, meta_flags(flags)?);
            return block(Response::MetaValue { flags, data: Vec::new() }, n);
        }
        code => match MetaStatus::from_code(code) {
            Some(status) => Response::Meta { status, flags: meta_flags(&tokens(rest.unwrap_or(b"")))? },
            None => return Err(Error::UnknownCommand),
        },
    };
    Ok((response, None))
}

fn attach_response(response: &mut Response, block: Vec<u8>) {
    if let Response::Value { data, .. } | Response::MetaValue { data, .. } = response {
        *data = block;
    }
}

/// The words of a line: the runs of bytes between spaces. memcached skips
/// empty words, so two spaces count as one.
fn tokens(line: &[u8]) -> Vec<&[u8]> {
    line.split(|&b| b == b' ').filter(|t| !t.is_empty()).collect()
}

/// The words before a final `noreply`, and whether it was there. It is a
/// `noreply` only if there are more than `required` words, so a key named
/// `noreply` stays a key.
fn strip_noreply<'a, 'b>(args: &'a [&'b [u8]], required: usize) -> (&'a [&'b [u8]], bool) {
    match args.split_last() {
        Some((&last, rest)) if args.len() > required && last == b"noreply" => (rest, true),
        _ => (args, false),
    }
}

/// The `required` words of a command that may end in one more, and whether
/// that word was `noreply`. memcached ignores any other word in that place.
/// Fewer or more words are [`Error::UnknownCommand`], since memcached
/// answers them with `ERROR`.
fn optional_noreply<'a, 'b>(args: &'a [&'b [u8]], required: usize) -> Result<(&'a [&'b [u8]], bool), Error> {
    if args.len() == required {
        Ok((args, false))
    } else if args.len() == required + 1 {
        Ok((&args[..required], args[required] == b"noreply"))
    } else {
        Err(Error::UnknownCommand)
    }
}

/// Whether a byte may be part of a word: anything but a space or a
/// control byte.
fn is_token_byte(b: u8) -> bool {
    b > b' ' && b != 0x7f
}

fn key_of(t: &[u8]) -> Result<Vec<u8>, Error> {
    if t.is_empty() || t.len() > MAX_KEY || !t.iter().all(|&b| is_token_byte(b)) {
        return Err(Error::Key);
    }
    Ok(t.to_vec())
}

fn keys_of(ts: &[&[u8]]) -> Result<Vec<Vec<u8>>, Error> {
    if ts.is_empty() {
        return Err(Error::Format);
    }
    ts.iter().map(|k| key_of(k)).collect()
}

fn token_of(t: &[u8]) -> Result<Vec<u8>, Error> {
    if t.is_empty() || !t.iter().all(|&b| is_token_byte(b)) {
        return Err(Error::Format);
    }
    Ok(t.to_vec())
}

fn meta_flags(ts: &[&[u8]]) -> Result<Vec<MetaFlag>, Error> {
    if ts.len() > MAX_META_FLAGS {
        return Err(Error::Format);
    }
    ts.iter()
        .map(|t| {
            let t = token_of(t)?;
            Ok(MetaFlag { flag: t[0], token: t[1..].to_vec() })
        })
        .collect()
}

/// Message text: anything but CR and LF.
fn check_text(t: &[u8]) -> Result<(), Error> {
    if t.iter().any(|&b| b == b'\r' || b == b'\n') { Err(Error::Format) } else { Ok(()) }
}

fn unsigned(t: &[u8]) -> Result<u64, Error> {
    if t.is_empty() || !t.iter().all(u8::is_ascii_digit) {
        return Err(Error::Format);
    }
    t.iter().try_fold(0u64, |n, &d| n.checked_mul(10)?.checked_add(u64::from(d - b'0'))).ok_or(Error::Format)
}

fn small(t: &[u8]) -> Result<u32, Error> {
    u32::try_from(unsigned(t)?).map_err(|_| Error::Format)
}

/// An expiration time. memcached reads it into a 32-bit signed number and
/// refuses one that does not fit.
fn signed(t: &[u8]) -> Result<i32, Error> {
    match t.split_first() {
        Some((b'-', digits)) => i32::try_from(-i128::from(unsigned(digits)?)).map_err(|_| Error::Format),
        _ => i32::try_from(unsigned(t)?).map_err(|_| Error::Format),
    }
}

fn length(t: &[u8]) -> Result<usize, Error> {
    let n = unsigned(t)?;
    if n > MAX_DECLARED as u64 {
        return Err(Error::Format);
    }
    Ok(n as usize)
}

/// A message whose data block of `n` bytes comes next, or the error for a
/// block too large to take.
fn block<T>(message: T, n: usize) -> Result<(T, Option<usize>), Error> {
    if n > MAX_VALUE { Err(Error::TooLarge(n)) } else { Ok((message, Some(n))) }
}

fn word(line: &mut Vec<u8>, w: &[u8]) {
    if !line.is_empty() {
        line.push(b' ');
    }
    line.extend_from_slice(w);
}

fn number(line: &mut Vec<u8>, n: impl std::fmt::Display) {
    word(line, n.to_string().as_bytes());
}

fn put_key(line: &mut Vec<u8>, key: &[u8]) -> Result<(), Error> {
    key_of(key)?;
    word(line, key);
    Ok(())
}

fn put_keys(line: &mut Vec<u8>, keys: &[Vec<u8>]) -> Result<(), Error> {
    if keys.is_empty() {
        return Err(Error::Format);
    }
    keys.iter().try_for_each(|k| put_key(line, k))
}

fn put_token(line: &mut Vec<u8>, t: &[u8]) -> Result<(), Error> {
    token_of(t)?;
    word(line, t);
    Ok(())
}

fn put_noreply(line: &mut Vec<u8>, noreply: bool) {
    if noreply {
        word(line, b"noreply");
    }
}

fn put_meta_flags(line: &mut Vec<u8>, flags: &[MetaFlag]) -> Result<(), Error> {
    if flags.len() > MAX_META_FLAGS {
        return Err(Error::Format);
    }
    for f in flags {
        if !is_token_byte(f.flag) || !f.token.iter().all(|&b| is_token_byte(b)) {
            return Err(Error::Format);
        }
        word(line, &[f.flag]);
        line.extend_from_slice(&f.token);
    }
    Ok(())
}

fn meta_line(line: &mut Vec<u8>, verb: &[u8], key: &[u8], n: Option<usize>, flags: &[MetaFlag]) -> Result<(), Error> {
    word(line, verb);
    put_key(line, key)?;
    if let Some(n) = n {
        number(line, n);
    }
    put_meta_flags(line, flags)
}

fn text_line(line: &mut Vec<u8>, first: &[u8], text: &[u8]) -> Result<(), Error> {
    check_text(text)?;
    word(line, first);
    if !text.is_empty() {
        line.push(b' ');
        line.extend_from_slice(text);
    }
    Ok(())
}

/// The line with its CR LF, then the data block with its own, after
/// checking both fit.
fn finish(mut line: Vec<u8>, data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    if let Some(d) = data
        && d.len() > MAX_VALUE
    {
        return Err(Error::TooLarge(d.len()));
    }
    if line.len() + 2 > MAX_LINE {
        return Err(Error::LineTooLong);
    }
    line.extend_from_slice(b"\r\n");
    if let Some(d) = data {
        line.extend_from_slice(d);
        line.extend_from_slice(b"\r\n");
    }
    Ok(line)
}

/// The length of the binary protocol header.
pub const BINARY_HEADER_LEN: usize = 24;
/// The first byte of a binary request.
pub const REQUEST_MAGIC: u8 = 0x80;
/// The first byte of a binary response.
pub const RESPONSE_MAGIC: u8 = 0x81;
/// The longest binary body: the most extras, the longest key and the
/// longest value.
pub const MAX_BODY: usize = 255 + MAX_KEY + MAX_VALUE;

/// Binary protocol opcodes. The ones ending in `Q` are quiet: the server
/// answers them only on failure, or, for gets, only on a hit.
pub mod opcode {
    #![allow(missing_docs)]
    pub const GET: u8 = 0x00;
    pub const SET: u8 = 0x01;
    pub const ADD: u8 = 0x02;
    pub const REPLACE: u8 = 0x03;
    pub const DELETE: u8 = 0x04;
    pub const INCREMENT: u8 = 0x05;
    pub const DECREMENT: u8 = 0x06;
    pub const QUIT: u8 = 0x07;
    pub const FLUSH: u8 = 0x08;
    pub const GETQ: u8 = 0x09;
    pub const NOOP: u8 = 0x0a;
    pub const VERSION: u8 = 0x0b;
    pub const GETK: u8 = 0x0c;
    pub const GETKQ: u8 = 0x0d;
    pub const APPEND: u8 = 0x0e;
    pub const PREPEND: u8 = 0x0f;
    pub const STAT: u8 = 0x10;
    pub const SETQ: u8 = 0x11;
    pub const ADDQ: u8 = 0x12;
    pub const REPLACEQ: u8 = 0x13;
    pub const DELETEQ: u8 = 0x14;
    pub const INCREMENTQ: u8 = 0x15;
    pub const DECREMENTQ: u8 = 0x16;
    pub const QUITQ: u8 = 0x17;
    pub const FLUSHQ: u8 = 0x18;
    pub const APPENDQ: u8 = 0x19;
    pub const PREPENDQ: u8 = 0x1a;
    pub const VERBOSITY: u8 = 0x1b;
    pub const TOUCH: u8 = 0x1c;
    pub const GAT: u8 = 0x1d;
    pub const GATQ: u8 = 0x1e;
    pub const SASL_LIST_MECHS: u8 = 0x20;
    pub const SASL_AUTH: u8 = 0x21;
    pub const SASL_STEP: u8 = 0x22;
    pub const GATK: u8 = 0x23;
    pub const GATKQ: u8 = 0x24;
}

/// Which way a binary packet goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Magic {
    /// From a client: [`REQUEST_MAGIC`].
    Request,
    /// From a server: [`RESPONSE_MAGIC`].
    Response,
}

impl Magic {
    /// The magic byte.
    pub fn byte(self) -> u8 {
        match self {
            Magic::Request => REQUEST_MAGIC,
            Magic::Response => RESPONSE_MAGIC,
        }
    }

    /// The direction a magic byte names, if it names one.
    pub fn from_byte(b: u8) -> Option<Magic> {
        match b {
            REQUEST_MAGIC => Some(Magic::Request),
            RESPONSE_MAGIC => Some(Magic::Response),
            _ => None,
        }
    }
}

/// The status in a binary response's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// 0x0000: done.
    NoError,
    /// 0x0001.
    KeyNotFound,
    /// 0x0002: the key holds a value, or the CAS value did not match.
    KeyExists,
    /// 0x0003.
    ValueTooLarge,
    /// 0x0004.
    InvalidArguments,
    /// 0x0005.
    ItemNotStored,
    /// 0x0006: increment or decrement on a value that is not a number.
    NonNumeric,
    /// 0x0007: the vbucket belongs to another server.
    WrongVbucket,
    /// 0x0008.
    AuthError,
    /// 0x0009: SASL authentication needs another step.
    AuthContinue,
    /// 0x0081.
    UnknownCommand,
    /// 0x0082.
    OutOfMemory,
    /// Any other code.
    Other(u16),
}

impl Status {
    /// The status's number.
    pub fn code(self) -> u16 {
        match self {
            Status::NoError => 0x00,
            Status::KeyNotFound => 0x01,
            Status::KeyExists => 0x02,
            Status::ValueTooLarge => 0x03,
            Status::InvalidArguments => 0x04,
            Status::ItemNotStored => 0x05,
            Status::NonNumeric => 0x06,
            Status::WrongVbucket => 0x07,
            Status::AuthError => 0x08,
            Status::AuthContinue => 0x09,
            Status::UnknownCommand => 0x81,
            Status::OutOfMemory => 0x82,
            Status::Other(c) => c,
        }
    }

    /// The status for code `c`.
    pub fn from_code(c: u16) -> Status {
        match c {
            0x00 => Status::NoError,
            0x01 => Status::KeyNotFound,
            0x02 => Status::KeyExists,
            0x03 => Status::ValueTooLarge,
            0x04 => Status::InvalidArguments,
            0x05 => Status::ItemNotStored,
            0x06 => Status::NonNumeric,
            0x07 => Status::WrongVbucket,
            0x08 => Status::AuthError,
            0x09 => Status::AuthContinue,
            0x81 => Status::UnknownCommand,
            0x82 => Status::OutOfMemory,
            c => Status::Other(c),
        }
    }
}

/// Why bytes are not a binary packet. Each one breaks the stream: a
/// reader cannot find where the next packet starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryError {
    /// The first byte was neither magic byte.
    Magic(u8),
    /// The key was longer than [`MAX_KEY`].
    KeyLength(usize),
    /// The extras were longer than 255 bytes. Only a writer gives this.
    ExtrasLength(usize),
    /// The body was longer than [`MAX_BODY`], or shorter than its extras
    /// and key.
    BodyLength(usize),
}

impl std::fmt::Display for BinaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryError::Magic(m) => write!(f, "magic byte {m:#04x}, not 0x80 or 0x81"),
            BinaryError::KeyLength(n) => write!(f, "key of {n} bytes, over {MAX_KEY}"),
            BinaryError::ExtrasLength(n) => write!(f, "extras of {n} bytes, over 255"),
            BinaryError::BodyLength(n) => write!(f, "body length {n}, over {MAX_BODY} or short of extras and key"),
        }
    }
}

impl std::error::Error for BinaryError {}

/// One binary protocol packet: the header's fields and the body. The
/// lengths in the header are worked out from the body, so none is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Request or response.
    pub magic: Magic,
    /// What the packet asks or answers; see [`opcode`].
    pub opcode: u8,
    /// Reserved, and 0 in practice.
    pub data_type: u8,
    /// In a response, the [`Status`] code. In a request, the vbucket id,
    /// usually 0.
    pub status: u16,
    /// Chosen by the client and copied into the response.
    pub opaque: u32,
    /// The item's CAS value, or 0.
    pub cas: u64,
    /// Fixed fields that depend on the opcode, such as [`StoreExtras`].
    pub extras: Vec<u8>,
    /// The key, as bytes.
    pub key: Vec<u8>,
    /// The value.
    pub value: Vec<u8>,
}

impl Packet {
    /// Reads the packet at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the packet and how many bytes
    /// of `b` it took. A bad magic byte is known from the first byte.
    pub fn parse(b: &[u8]) -> Result<Option<(Packet, usize)>, BinaryError> {
        let Some(&m) = b.first() else { return Ok(None) };
        let magic = Magic::from_byte(m).ok_or(BinaryError::Magic(m))?;
        if b.len() < BINARY_HEADER_LEN {
            return Ok(None);
        }
        let key_len = usize::from(be16(b, 2));
        let extras_len = usize::from(b[4]);
        let body = usize::try_from(be32(b, 8)).unwrap_or(usize::MAX);
        if key_len > MAX_KEY {
            return Err(BinaryError::KeyLength(key_len));
        }
        if body > MAX_BODY || key_len + extras_len > body {
            return Err(BinaryError::BodyLength(body));
        }
        let end = BINARY_HEADER_LEN + body;
        if b.len() < end {
            return Ok(None);
        }
        let (extras, rest) = b[BINARY_HEADER_LEN..end].split_at(extras_len);
        let (key, value) = rest.split_at(key_len);
        let packet = Packet {
            magic,
            opcode: b[1],
            data_type: b[5],
            status: be16(b, 6),
            opaque: be32(b, 12),
            cas: u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            extras: extras.to_vec(),
            key: key.to_vec(),
            value: value.to_vec(),
        };
        Ok(Some((packet, end)))
    }

    /// The packet's bytes. It refuses a key over [`MAX_KEY`], extras over
    /// 255 bytes, or a body over [`MAX_BODY`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, BinaryError> {
        if self.key.len() > MAX_KEY {
            return Err(BinaryError::KeyLength(self.key.len()));
        }
        let extras_len = u8::try_from(self.extras.len()).map_err(|_| BinaryError::ExtrasLength(self.extras.len()))?;
        let body = self.extras.len() + self.key.len() + self.value.len();
        if body > MAX_BODY {
            return Err(BinaryError::BodyLength(body));
        }
        let mut out = Vec::with_capacity(BINARY_HEADER_LEN + body);
        out.push(self.magic.byte());
        out.push(self.opcode);
        out.extend_from_slice(&(self.key.len() as u16).to_be_bytes());
        out.push(extras_len);
        out.push(self.data_type);
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&(body as u32).to_be_bytes());
        out.extend_from_slice(&self.opaque.to_be_bytes());
        out.extend_from_slice(&self.cas.to_be_bytes());
        out.extend_from_slice(&self.extras);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.value);
        Ok(out)
    }

    /// An empty response to this packet with `status`: the same opcode and
    /// opaque, and no CAS, extras, key or value.
    pub fn reply(&self, status: Status) -> Packet {
        Packet {
            magic: Magic::Response,
            opcode: self.opcode,
            data_type: 0,
            status: status.code(),
            opaque: self.opaque,
            cas: 0,
            extras: Vec::new(),
            key: Vec::new(),
            value: Vec::new(),
        }
    }
}

/// The extras of a set, add or replace request: the client's flags and
/// the expiration time. A get response's extras are the flags alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreExtras {
    /// The client's flags, stored with the value.
    pub flags: u32,
    /// The expiration time, as in the text protocol.
    pub expiration: u32,
}

impl StoreExtras {
    /// Reads extras of exactly 8 bytes.
    pub fn parse(extras: &[u8]) -> Option<StoreExtras> {
        let [a, b, c, d, e, f, g, h] = *extras else { return None };
        Some(StoreExtras { flags: u32::from_be_bytes([a, b, c, d]), expiration: u32::from_be_bytes([e, f, g, h]) })
    }

    /// The extras' 8 bytes.
    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0; 8];
        out[..4].copy_from_slice(&self.flags.to_be_bytes());
        out[4..].copy_from_slice(&self.expiration.to_be_bytes());
        out
    }
}

/// The extras of an increment or decrement request. A response carries
/// the new value as 8 bytes in its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterExtras {
    /// How much to add or subtract.
    pub delta: u64,
    /// The value to store if the key holds nothing.
    pub initial: u64,
    /// The expiration time. `0xffffffff` means fail rather than store
    /// `initial`.
    pub expiration: u32,
}

impl CounterExtras {
    /// Reads extras of exactly 20 bytes.
    pub fn parse(extras: &[u8]) -> Option<CounterExtras> {
        if extras.len() != 20 {
            return None;
        }
        let u64_at = |i: usize| {
            let mut b = [0; 8];
            b.copy_from_slice(&extras[i..i + 8]);
            u64::from_be_bytes(b)
        };
        Some(CounterExtras { delta: u64_at(0), initial: u64_at(8), expiration: be32(extras, 16) })
    }

    /// The extras' 20 bytes.
    pub fn to_bytes(self) -> [u8; 20] {
        let mut out = [0; 20];
        out[..8].copy_from_slice(&self.delta.to_be_bytes());
        out[8..16].copy_from_slice(&self.initial.to_be_bytes());
        out[16..].copy_from_slice(&self.expiration.to_be_bytes());
        out
    }
}

/// Splits a binary protocol stream into packets. Feed it the bytes a
/// connection reads, in order, and take packets out until it has none.
#[derive(Clone, Debug, Default)]
pub struct BinaryDecoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer.
    start: usize,
    failed: Option<BinaryError>,
}

impl BinaryDecoder {
    /// A decoder holding no bytes.
    pub fn new() -> BinaryDecoder {
        BinaryDecoder::default()
    }

    /// Adds bytes read from the connection. After a [`BinaryError`] the
    /// stream cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The next whole packet, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A decoder holds at most one packet's bytes beyond
    /// what has been taken out, plus what one `feed` added.
    pub fn next_packet(&mut self) -> Option<Result<Packet, BinaryError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match Packet::parse(&self.buf[self.start..]) {
            Ok(Some((packet, used))) => {
                self.start += used;
                Some(Ok(packet))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a packet.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

/// The length of the frame header on each UDP datagram.
pub const UDP_HEADER_LEN: usize = 8;
/// The longest datagram, header included, that [`UdpFrame::split`] makes.
/// memcached uses the same size for its replies.
pub const UDP_MAX_DATAGRAM: usize = 1400;
/// The longest payload a datagram may carry: the largest UDP payload over
/// IPv4, less the frame header.
pub const MAX_UDP_PAYLOAD: usize = 65_507 - UDP_HEADER_LEN;

/// One UDP datagram: the frame header's fields and the text protocol bytes
/// it carries. A request fits in one datagram. A reply may take many,
/// which the client puts back together by `sequence`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpFrame {
    /// Chosen by the client and copied into each datagram of the reply.
    pub request_id: u16,
    /// This datagram's place in the message, from 0.
    pub sequence: u16,
    /// How many datagrams the message takes.
    pub total: u16,
    /// Part of the message's bytes.
    pub payload: Vec<u8>,
}

/// Why a datagram is not a memcached UDP frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpError {
    /// Shorter than the 8-byte header, by its length.
    Short(usize),
    /// The reserved field was not 0.
    Reserved(u16),
    /// The total was 0, or the sequence number not below it.
    Sequence {
        /// The sequence number.
        sequence: u16,
        /// The total.
        total: u16,
    },
    /// The payload was longer than [`MAX_UDP_PAYLOAD`], or a message too
    /// long to split into 65535 datagrams.
    TooLong(usize),
}

impl std::fmt::Display for UdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpError::Short(n) => write!(f, "datagram of {n} bytes, shorter than the {UDP_HEADER_LEN}-byte header"),
            UdpError::Reserved(r) => write!(f, "reserved field {r}, not 0"),
            UdpError::Sequence { sequence, total } => write!(f, "sequence {sequence} of {total} datagrams"),
            UdpError::TooLong(n) => write!(f, "{n} bytes, too many for UDP"),
        }
    }
}

impl std::error::Error for UdpError {}

impl UdpFrame {
    /// Reads one datagram.
    pub fn parse(datagram: &[u8]) -> Result<UdpFrame, UdpError> {
        if datagram.len() < UDP_HEADER_LEN {
            return Err(UdpError::Short(datagram.len()));
        }
        let (sequence, total, reserved) = (be16(datagram, 2), be16(datagram, 4), be16(datagram, 6));
        if reserved != 0 {
            return Err(UdpError::Reserved(reserved));
        }
        if sequence >= total {
            return Err(UdpError::Sequence { sequence, total });
        }
        let payload = &datagram[UDP_HEADER_LEN..];
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(UdpError::TooLong(payload.len()));
        }
        Ok(UdpFrame { request_id: be16(datagram, 0), sequence, total, payload: payload.to_vec() })
    }

    /// The datagram's bytes. It refuses a sequence number not below the
    /// total, or a payload over [`MAX_UDP_PAYLOAD`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, UdpError> {
        if self.sequence >= self.total {
            return Err(UdpError::Sequence { sequence: self.sequence, total: self.total });
        }
        if self.payload.len() > MAX_UDP_PAYLOAD {
            return Err(UdpError::TooLong(self.payload.len()));
        }
        let mut out = Vec::with_capacity(UDP_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.request_id.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// A message split into datagrams of at most [`UDP_MAX_DATAGRAM`]
    /// bytes, numbered in order. An empty message takes one datagram.
    pub fn split(request_id: u16, message: &[u8]) -> Result<Vec<UdpFrame>, UdpError> {
        let chunk = UDP_MAX_DATAGRAM - UDP_HEADER_LEN;
        let count = message.len().div_ceil(chunk).max(1);
        let total = u16::try_from(count).map_err(|_| UdpError::TooLong(message.len()))?;
        let mut frames = Vec::with_capacity(count);
        for sequence in 0..total {
            let from = usize::from(sequence) * chunk;
            let to = (from + chunk).min(message.len());
            frames.push(UdpFrame { request_id, sequence, total, payload: message[from..to].to_vec() });
        }
        Ok(frames)
    }
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command a decoder gives for `bytes`, fed at once, up to and
    /// including the first fatal error.
    fn commands(bytes: &[u8]) -> Vec<Result<Command, Error>> {
        let mut d = CommandDecoder::new();
        d.feed(bytes);
        drain(|| d.next_command())
    }

    fn responses(bytes: &[u8]) -> Vec<Result<Response, Error>> {
        let mut d = ResponseDecoder::new();
        d.feed(bytes);
        drain(|| d.next_response())
    }

    fn drain<T>(mut next: impl FnMut() -> Option<Result<T, Error>>) -> Vec<Result<T, Error>> {
        let mut out = Vec::new();
        while let Some(r) = next() {
            let fatal = matches!(r, Err(e) if e.is_fatal());
            out.push(r);
            if fatal {
                break;
            }
        }
        out
    }

    fn one(bytes: &[u8]) -> Command {
        let got = commands(bytes);
        assert_eq!(got.len(), 1, "{got:?}");
        got.into_iter().next().unwrap().unwrap()
    }

    fn key(k: &str) -> Vec<u8> {
        k.as_bytes().to_vec()
    }

    fn sample_commands() -> Vec<Command> {
        let f = |flag, token: &str| MetaFlag::new(flag, token.as_bytes());
        vec![
            Command::Store {
                verb: StoreVerb::Set,
                key: key("a"),
                flags: 1,
                exptime: 0,
                data: b"xy".to_vec(),
                noreply: false,
            },
            Command::Store {
                verb: StoreVerb::Add,
                key: key("b"),
                flags: u32::MAX,
                exptime: -1,
                data: vec![],
                noreply: true,
            },
            Command::Store {
                verb: StoreVerb::Replace,
                key: key("c"),
                flags: 0,
                exptime: 60,
                data: b"\r\n".to_vec(),
                noreply: false,
            },
            Command::Store {
                verb: StoreVerb::Append,
                key: key("d"),
                flags: 0,
                exptime: 0,
                data: b"z".to_vec(),
                noreply: false,
            },
            Command::Store {
                verb: StoreVerb::Prepend,
                key: key("e"),
                flags: 0,
                exptime: 0,
                data: b"z".to_vec(),
                noreply: true,
            },
            Command::Cas { key: key("a"), flags: 0, exptime: 0, unique: u64::MAX, data: b"v".to_vec(), noreply: false },
            Command::Get { keys: vec![key("a"), key("b")], cas: false },
            Command::Get { keys: vec![key("noreply")], cas: true },
            Command::Gat { exptime: 10, keys: vec![key("a")], cas: false },
            Command::Gat { exptime: i32::MIN, keys: vec![key("a")], cas: true },
            Command::Delete { key: key("noreply"), noreply: false },
            Command::Delete { key: key("noreply"), noreply: true },
            Command::Incr { key: key("n"), delta: 5, noreply: false },
            Command::Decr { key: key("n"), delta: u64::MAX, noreply: true },
            Command::Touch { key: key("t"), exptime: 30, noreply: false },
            Command::Stats { args: vec![] },
            Command::Stats { args: vec![key("cachedump"), key("1"), key("2")] },
            Command::Version,
            Command::Verbosity { level: 1, noreply: true },
            Command::FlushAll { delay: None, noreply: false },
            Command::FlushAll { delay: Some(5), noreply: true },
            Command::Quit,
            Command::MetaGet { key: key("foo"), flags: vec![f(b'v', ""), f(b'T', "30"), f(b'O', "abc")] },
            Command::MetaSet { key: key("foo"), flags: vec![f(b'F', "1")], data: b"hi".to_vec() },
            Command::MetaDelete { key: key("foo"), flags: vec![f(b'q', "")] },
            Command::MetaArithmetic { key: key("n"), flags: vec![f(b'D', "2"), f(b'M', "I")] },
            Command::MetaDebug { key: key("foo"), flags: vec![] },
            Command::MetaNoop,
        ]
    }

    fn sample_responses() -> Vec<Response> {
        vec![
            Response::Stored,
            Response::NotStored,
            Response::Exists,
            Response::NotFound,
            Response::Deleted,
            Response::Touched,
            Response::End,
            Response::Ok,
            Response::Error,
            Response::ClientError(b"bad data chunk".to_vec()),
            Response::ClientError(vec![]),
            Response::ServerError(b"out of memory".to_vec()),
            Response::Value { key: key("a"), flags: 3, cas: None, data: b"hello".to_vec() },
            Response::Value { key: key("a"), flags: 0, cas: Some(77), data: vec![] },
            Response::Stat { name: key("pid"), value: key("1234") },
            Response::Stat { name: key("version"), value: key("1.6 beta") },
            Response::Version(b"1.6.21".to_vec()),
            Response::Number(0),
            Response::Number(u64::MAX),
            Response::Meta { status: MetaStatus::Header, flags: vec![MetaFlag::new(b'O', b"123")] },
            Response::Meta { status: MetaStatus::Miss, flags: vec![] },
            Response::Meta { status: MetaStatus::NotStored, flags: vec![] },
            Response::Meta { status: MetaStatus::Exists, flags: vec![] },
            Response::Meta { status: MetaStatus::NotFound, flags: vec![] },
            Response::Meta { status: MetaStatus::Noop, flags: vec![] },
            Response::MetaValue { flags: vec![MetaFlag::new(b't', b"-1")], data: b"hi".to_vec() },
            Response::MetaDebug { key: key("foo"), info: b"exp=-1 la=3 cas=2 fetch=no cls=1 size=63".to_vec() },
            Response::MetaDebug { key: key("foo"), info: vec![] },
        ]
    }

    // Examples from protocol.txt.

    #[test]
    fn storage_example() {
        let c = one(b"set mykey 0 900 4\r\ndata\r\n");
        assert_eq!(
            c,
            Command::Store {
                verb: StoreVerb::Set,
                key: key("mykey"),
                flags: 0,
                exptime: 900,
                data: b"data".to_vec(),
                noreply: false
            }
        );
        assert_eq!(c.to_bytes().unwrap(), b"set mykey 0 900 4\r\ndata\r\n");
        assert_eq!(opcode::VERBOSITY, 0x1b);
        assert_eq!((opcode::GATK, opcode::GATKQ), (0x23, 0x24));
        let c = one(b"cas k 7 0 1 12345 noreply\r\nx\r\n");
        assert_eq!(
            c,
            Command::Cas { key: key("k"), flags: 7, exptime: 0, unique: 12345, data: b"x".to_vec(), noreply: true }
        );
        assert!(c.is_quiet());
        // Data may hold CR LF; only its length counts.
        assert_eq!(
            one(b"append k 0 0 2\r\n\r\n\r\n"),
            Command::Store {
                verb: StoreVerb::Append,
                key: key("k"),
                flags: 0,
                exptime: 0,
                data: b"\r\n".to_vec(),
                noreply: false
            }
        );
    }

    #[test]
    fn retrieval_example() {
        assert_eq!(one(b"get a b c\r\n"), Command::Get { keys: vec![key("a"), key("b"), key("c")], cas: false });
        assert_eq!(one(b"gats 100 a\r\n"), Command::Gat { exptime: 100, keys: vec![key("a")], cas: true });
        let got = responses(b"VALUE a 0 5 99\r\nhello\r\nVALUE c 2 0\r\n\r\nEND\r\n");
        assert_eq!(
            got,
            [
                Ok(Response::Value { key: key("a"), flags: 0, cas: Some(99), data: b"hello".to_vec() }),
                Ok(Response::Value { key: key("c"), flags: 2, cas: None, data: vec![] }),
                Ok(Response::End),
            ]
        );
    }

    #[test]
    fn other_commands_example() {
        assert_eq!(one(b"delete k\r\n"), Command::Delete { key: key("k"), noreply: false });
        assert_eq!(one(b"delete k 0 noreply\r\n"), Command::Delete { key: key("k"), noreply: true });
        assert_eq!(one(b"incr n 10\r\n"), Command::Incr { key: key("n"), delta: 10, noreply: false });
        assert_eq!(one(b"decr n 3 noreply\r\n"), Command::Decr { key: key("n"), delta: 3, noreply: true });
        assert_eq!(one(b"touch k -1\r\n"), Command::Touch { key: key("k"), exptime: -1, noreply: false });
        assert_eq!(one(b"stats slabs\r\n"), Command::Stats { args: vec![key("slabs")] });
        assert_eq!(one(b"version\n"), Command::Version);
        assert_eq!(one(b"verbosity 1\r\n"), Command::Verbosity { level: 1, noreply: false });
        assert_eq!(one(b"flush_all noreply\r\n"), Command::FlushAll { delay: None, noreply: true });
        assert_eq!(one(b"flush_all 10\r\n"), Command::FlushAll { delay: Some(10), noreply: false });
        assert_eq!(one(b"quit\r\n"), Command::Quit);
        // Extra spaces count as one.
        assert_eq!(one(b"get  a   b \r\n"), Command::Get { keys: vec![key("a"), key("b")], cas: false });
        // A key named noreply is a key when the command needs one.
        assert_eq!(one(b"delete noreply\r\n"), Command::Delete { key: key("noreply"), noreply: false });
        // memcached ignores a word other than noreply after the last one
        // a command needs, and any words after version, quit and mn.
        assert_eq!(
            one(b"set k 0 0 1 x\r\nv\r\n"),
            Command::Store {
                verb: StoreVerb::Set,
                key: key("k"),
                flags: 0,
                exptime: 0,
                data: b"v".to_vec(),
                noreply: false
            }
        );
        assert_eq!(one(b"incr n 1 x\r\n"), Command::Incr { key: key("n"), delta: 1, noreply: false });
        assert_eq!(one(b"touch k 1 noreply\r\n"), Command::Touch { key: key("k"), exptime: 1, noreply: true });
        assert_eq!(one(b"flush_all 1 2\r\n"), Command::FlushAll { delay: Some(1), noreply: false });
        assert_eq!(one(b"version now\r\n"), Command::Version);
        assert_eq!(one(b"quit 1\r\n"), Command::Quit);
        assert_eq!(one(b"mn x\r\n"), Command::MetaNoop);
        // Expiration times are 32-bit signed numbers.
        assert_eq!(one(b"gat -2147483648 k\r\n"), Command::Gat { exptime: i32::MIN, keys: vec![key("k")], cas: false });
        assert_eq!(one(b"touch k 2147483647\r\n"), Command::Touch { key: key("k"), exptime: i32::MAX, noreply: false });
        let got = responses(b"STAT pid 2233\r\nSTAT uptime 45\r\nEND\r\n42\r\nVERSION 1.6.21\r\nTOUCHED\r\n");
        assert_eq!(
            got,
            [
                Ok(Response::Stat { name: key("pid"), value: key("2233") }),
                Ok(Response::Stat { name: key("uptime"), value: key("45") }),
                Ok(Response::End),
                Ok(Response::Number(42)),
                Ok(Response::Version(key("1.6.21"))),
                Ok(Response::Touched),
            ]
        );
    }

    #[test]
    fn meta_example() {
        let c = one(b"ms foo 2 T90 F1\r\nhi\r\n");
        assert_eq!(
            c,
            Command::MetaSet {
                key: key("foo"),
                flags: vec![MetaFlag::new(b'T', b"90"), MetaFlag::new(b'F', b"1")],
                data: b"hi".to_vec()
            }
        );
        let c = one(b"mg foo v t q\r\n");
        let Command::MetaGet { flags, .. } = &c else { panic!() };
        assert_eq!(meta_token(flags, b't'), Some(&b""[..]));
        assert_eq!(meta_token(flags, b'k'), None);
        assert!(c.is_quiet());
        assert_eq!(one(b"mn\r\n"), Command::MetaNoop);
        let got = responses(b"VA 2 t-1\r\nhi\r\nEN\r\nHD O123 k\r\nMN\r\nME foo exp=-1 la=3\r\n");
        assert_eq!(
            got,
            [
                Ok(Response::MetaValue { flags: vec![MetaFlag::new(b't', b"-1")], data: b"hi".to_vec() }),
                Ok(Response::Meta { status: MetaStatus::Miss, flags: vec![] }),
                Ok(Response::Meta {
                    status: MetaStatus::Header,
                    flags: vec![MetaFlag::new(b'O', b"123"), MetaFlag::new(b'k', b"")]
                }),
                Ok(Response::Meta { status: MetaStatus::Noop, flags: vec![] }),
                Ok(Response::MetaDebug { key: key("foo"), info: b"exp=-1 la=3".to_vec() }),
            ]
        );
    }

    #[test]
    fn commands_round_trip() {
        let all = sample_commands();
        let mut stream = Vec::new();
        for c in &all {
            let bytes = c.to_bytes().unwrap();
            assert_eq!(one(&bytes), *c, "{}", String::from_utf8_lossy(&bytes));
            stream.extend(bytes);
        }
        let got: Vec<_> = commands(&stream).into_iter().map(Result::unwrap).collect();
        assert_eq!(got, all);
    }

    #[test]
    fn responses_round_trip() {
        let all = sample_responses();
        let mut stream = Vec::new();
        for r in &all {
            let bytes = r.to_bytes().unwrap();
            assert_eq!(responses(&bytes), [Ok(r.clone())], "{}", String::from_utf8_lossy(&bytes));
            stream.extend(bytes);
        }
        let got: Vec<_> = responses(&stream).into_iter().map(Result::unwrap).collect();
        assert_eq!(got, all);
    }

    #[test]
    fn every_truncated_prefix_waits() {
        for c in sample_commands() {
            let bytes = c.to_bytes().unwrap();
            for n in 0..bytes.len() {
                let mut d = CommandDecoder::new();
                d.feed(&bytes[..n]);
                assert_eq!(d.next_command(), None, "{n} bytes of {:?}", String::from_utf8_lossy(&bytes));
                d.feed(&bytes[n..]);
                assert_eq!(d.next_command(), Some(Ok(c.clone())));
                assert_eq!(d.buffered(), 0);
            }
        }
        for r in sample_responses() {
            let bytes = r.to_bytes().unwrap();
            for n in 0..bytes.len() {
                let mut d = ResponseDecoder::new();
                d.feed(&bytes[..n]);
                assert_eq!(d.next_response(), None, "{n} bytes");
                d.feed(&bytes[n..]);
                assert_eq!(d.next_response(), Some(Ok(r.clone())));
            }
        }
    }

    #[test]
    fn command_errors() {
        // Unknown commands, and an empty line.
        assert_eq!(commands(b"frob\r\n\r\nGET a\r\n"), [const { Err(Error::UnknownCommand) }; 3]);
        // Wrong word counts and bad numbers.
        // Too few or too many words: memcached answers ERROR.
        for line in [
            &b"set k 0 0\r\n"[..],
            b"set k 0 0 1 2 3\r\n",
            b"cas k 0 0 1\r\n",
            b"cas k 0 0 1 2 noreply x\r\n",
            b"get\r\n",
            b"gats\r\n",
            b"delete\r\n",
            b"delete a b c d\r\n",
            b"incr k\r\n",
            b"decr k 1 noreply x\r\n",
            b"touch k\r\n",
            b"verbosity\r\n",
            b"flush_all 1 2 3\r\n",
        ] {
            assert_eq!(commands(line), [Err(Error::UnknownCommand)], "{}", String::from_utf8_lossy(line));
        }
        // A bad delta or expiration time has its own reply.
        for line in [&b"incr k -1\r\n"[..], b"incr k 18446744073709551616\r\n", b"decr k x\r\n"] {
            assert_eq!(commands(line), [Err(Error::Delta)], "{}", String::from_utf8_lossy(line));
        }
        for line in [&b"touch k x\r\n"[..], b"touch k 2147483648\r\n", b"gat x k\r\n", b"gats -2147483649 k\r\n"] {
            assert_eq!(commands(line), [Err(Error::Exptime)], "{}", String::from_utf8_lossy(line));
        }
        for line in [
            &b"set k x 0 1\r\n"[..],
            b"set k 4294967296 0 1\r\n",
            b"set k 0 0 -1\r\n",
            b"set k 0 0 +1\r\n",
            b"set k 0 2147483648 1\r\n",
            b"set k 0 -2147483649 1\r\n",
            b"set k 0 0 2147483646\r\n",
            b"gat 10\r\n",
            b"delete k 5\r\n",
            b"delete k noreply noreply\r\n",
            b"flush_all 2147483648\r\n",
            b"ms k\r\n",
            b"mg\r\n",
            b"stats a\x01\r\n",
            b"mg k \x7f\r\n",
        ] {
            assert_eq!(commands(line), [Err(Error::Format)], "{}", String::from_utf8_lossy(line));
        }
        let many = format!("mg k{}\r\n", " v".repeat(MAX_META_FLAGS + 1));
        assert_eq!(commands(many.as_bytes()), [Err(Error::Format)]);
        assert!(commands(format!("mg k{}\r\n", " v".repeat(MAX_META_FLAGS)).as_bytes())[0].is_ok());
        // Bad keys.
        let long = format!("get {}\r\n", "k".repeat(MAX_KEY + 1));
        assert_eq!(commands(long.as_bytes()), [Err(Error::Key)]);
        assert!(commands(format!("get {}\r\n", "k".repeat(MAX_KEY)).as_bytes())[0].is_ok());
        assert_eq!(commands(b"get a\tb\r\n"), [Err(Error::Key)]);
        assert_eq!(commands(b"get a\rb\r\n"), [Err(Error::Key)]);
        // After a bad storage line, the data block is read as a command.
        assert_eq!(commands(b"set k x 0 4\r\nquit\r\n"), [Err(Error::Format), Ok(Command::Quit)]);
        // But an ms line whose length was read drops its block on a bad
        // flag, as memcached does, so the block is not run as a command.
        assert_eq!(commands(b"ms k 4 \x01\r\nquit\r\nmn\r\n"), [Err(Error::Format), Ok(Command::MetaNoop)]);
        let mut d = CommandDecoder::new();
        let mut got = Vec::new();
        for b in b"ms k 4 v \x7f\r\nquit\r\nmn\r\n" {
            d.feed(std::slice::from_ref(b));
            got.extend(std::iter::from_fn(|| d.next_command()));
        }
        assert_eq!(got, [Err(Error::Format), Ok(Command::MetaNoop)]);
        // Too many flags is refused before the length is read, so the
        // block is read as a command.
        let many = format!("ms k 4{}\r\nquit\r\n", " v".repeat(MAX_META_FLAGS + 1));
        assert_eq!(commands(many.as_bytes()), [Err(Error::Format), Ok(Command::Quit)]);
        // A data block not ended by CR LF is skipped, and reading goes on.
        assert_eq!(commands(b"set k 0 0 2\r\nabcdversion\r\n"), [Err(Error::BadDataChunk), Ok(Command::Version)]);
        assert_eq!(commands(b"set k 0 0 2\r\nab\n\nversion\r\n"), [Err(Error::BadDataChunk), Ok(Command::Version)]);
        // Each error has the reply memcached sends.
        assert_eq!(Error::UnknownCommand.reply().to_bytes().unwrap(), b"ERROR\r\n");
        assert_eq!(Error::BadDataChunk.reply().to_bytes().unwrap(), b"CLIENT_ERROR bad data chunk\r\n");
        assert_eq!(Error::Key.reply().to_bytes().unwrap(), b"CLIENT_ERROR bad command line format\r\n");
        assert_eq!(Error::TooLarge(5).reply().to_bytes().unwrap(), b"SERVER_ERROR object too large for cache\r\n");
        assert_eq!(Error::LineTooLong.reply().to_bytes().unwrap(), b"CLIENT_ERROR line too long\r\n");
        assert_eq!(Error::Delta.reply().to_bytes().unwrap(), b"CLIENT_ERROR invalid numeric delta argument\r\n");
        assert_eq!(Error::Exptime.reply().to_bytes().unwrap(), b"CLIENT_ERROR invalid exptime argument\r\n");
        for e in [
            Error::LineTooLong,
            Error::UnknownCommand,
            Error::Format,
            Error::Delta,
            Error::Exptime,
            Error::Key,
            Error::TooLarge(1),
            Error::BadDataChunk,
        ] {
            assert!(!e.to_string().is_empty());
            assert_eq!(e.is_fatal(), e == Error::LineTooLong);
        }
    }

    #[test]
    fn too_large_values_are_skipped() {
        let n = MAX_VALUE + 1;
        let mut stream = format!("set k 0 0 {n}\r\n").into_bytes();
        stream.extend(vec![b'x'; n]);
        stream.extend_from_slice(b"\r\nversion\r\n");
        assert_eq!(commands(&stream), [Err(Error::TooLarge(n)), Ok(Command::Version)]);
        // The same a byte at a time, holding nothing while it skips.
        let mut d = CommandDecoder::new();
        let mut got = Vec::new();
        for b in &stream {
            d.feed(std::slice::from_ref(b));
            while let Some(r) = d.next_command() {
                got.push(r);
            }
            assert!(d.buffered() < MAX_LINE);
        }
        assert_eq!(got, [Err(Error::TooLarge(n)), Ok(Command::Version)]);
        let mut big = format!("VALUE k 0 {n}\r\n").into_bytes();
        big.extend(vec![0; n + 2]);
        big.extend_from_slice(b"END\r\n");
        assert_eq!(responses(&big), [Err(Error::TooLarge(n)), Ok(Response::End)]);
        // The largest block that fits is taken.
        let mut fits = format!("ms k {MAX_VALUE}\r\n").into_bytes();
        fits.extend(vec![b'y'; MAX_VALUE]);
        fits.extend_from_slice(b"\r\n");
        assert!(matches!(&commands(&fits)[..], [Ok(Command::MetaSet { data, .. })] if data.len() == MAX_VALUE));
    }

    #[test]
    fn long_lines_break_the_stream() {
        // MAX_LINE bytes and no LF.
        let mut d = CommandDecoder::new();
        d.feed(&vec![b'a'; MAX_LINE - 1]);
        assert_eq!(d.next_command(), None);
        d.feed(b"a");
        assert_eq!(d.next_command(), Some(Err(Error::LineTooLong)));
        d.feed(b"version\r\n");
        assert_eq!(d.next_command(), Some(Err(Error::LineTooLong)));
        assert_eq!(d.buffered(), 0);
        // The longest line fits with its CR LF; with a bare LF it is one too long.
        let mut line = b"get ".to_vec();
        while line.len() < MAX_LINE - 2 {
            line.extend_from_slice(b"k ");
        }
        line.truncate(MAX_LINE - 2);
        let mut ok = line.clone();
        ok.extend_from_slice(b"\r\n");
        assert!(commands(&ok)[0].is_ok());
        let mut bare = line.clone();
        bare.push(b'k');
        bare.push(b'\n');
        assert_eq!(bare.len(), MAX_LINE);
        assert_eq!(commands(&bare), [Err(Error::LineTooLong)]);
        assert_eq!(responses(&vec![b'1'; MAX_LINE]), [Err(Error::LineTooLong)]);
    }

    #[test]
    fn response_errors() {
        for line in [
            &b"STORED now\r\n"[..],
            b"END \r\n",
            b"18446744073709551616\r\n",
            b"12 \r\n",
            b"VALUE k 0\r\n",
            b"VALUE k 0 1 2 3\r\n",
            b"VALUE k 0 1 x\r\n",
            b"VA\r\n",
            b"VA x\r\n",
            b"STAT\r\n",
            b"STAT pid\r\n",
            b"STAT  1\r\n",
            b"ME\r\n",
            b"CLIENT_ERROR a\rb\r\n",
        ] {
            assert_eq!(responses(line), [Err(Error::Format)], "{}", String::from_utf8_lossy(line));
        }
        assert_eq!(responses(b"VALUE \x01 0 1\r\n"), [Err(Error::Key)]);
        assert_eq!(responses(b"BOGUS\r\nhd\r\n\r\n"), [const { Err(Error::UnknownCommand) }; 3]);
        assert_eq!(
            responses(b"VA 1\r\nxy\r\nEND\r\n"),
            [Err(Error::BadDataChunk), Err(Error::UnknownCommand), Ok(Response::End)]
        );
        // Message text may be empty, and may hold spaces.
        assert_eq!(responses(b"SERVER_ERROR\r\n"), [Ok(Response::ServerError(vec![]))]);
        assert_eq!(responses(b"CLIENT_ERROR  two  spaces\r\n"), [Ok(Response::ClientError(b" two  spaces".to_vec()))]);
    }

    #[test]
    fn writers_refuse_what_readers_refuse() {
        let bad_key = Command::Get { keys: vec![key("a b")], cas: false };
        assert_eq!(bad_key.to_bytes(), Err(Error::Key));
        assert_eq!(Command::Delete { key: vec![], noreply: false }.to_bytes(), Err(Error::Key));
        assert_eq!(
            Command::Touch { key: vec![b'k'; MAX_KEY + 1], exptime: 0, noreply: false }.to_bytes(),
            Err(Error::Key)
        );
        assert_eq!(Command::Get { keys: vec![], cas: false }.to_bytes(), Err(Error::Format));
        assert_eq!(Command::Stats { args: vec![vec![]] }.to_bytes(), Err(Error::Format));
        assert_eq!(
            Command::MetaGet { key: key("k"), flags: vec![MetaFlag::new(b' ', b"")] }.to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Command::MetaGet { key: key("k"), flags: vec![MetaFlag::new(b'v', b"a b")] }.to_bytes(),
            Err(Error::Format)
        );
        let flags = vec![MetaFlag::new(b'v', b""); MAX_META_FLAGS + 1];
        assert_eq!(Command::MetaGet { key: key("k"), flags: flags.clone() }.to_bytes(), Err(Error::Format));
        assert_eq!(Response::Meta { status: MetaStatus::Header, flags }.to_bytes(), Err(Error::Format));
        let big = vec![0; MAX_VALUE + 1];
        let store = Command::Store {
            verb: StoreVerb::Set,
            key: key("k"),
            flags: 0,
            exptime: 0,
            data: big.clone(),
            noreply: false,
        };
        assert_eq!(store.to_bytes(), Err(Error::TooLarge(MAX_VALUE + 1)));
        assert_eq!(Response::MetaValue { flags: vec![], data: big }.to_bytes(), Err(Error::TooLarge(MAX_VALUE + 1)));
        let keys = vec![key("kkkkkkkk"); MAX_LINE / 9 + 1];
        assert_eq!(Command::Get { keys, cas: false }.to_bytes(), Err(Error::LineTooLong));
        assert_eq!(Response::ClientError(b"a\nb".to_vec()).to_bytes(), Err(Error::Format));
        assert_eq!(Response::Version(b"\r".to_vec()).to_bytes(), Err(Error::Format));
        assert_eq!(Response::Stat { name: key("a b"), value: vec![] }.to_bytes(), Err(Error::Format));
        assert_eq!(Response::MetaDebug { key: key("k"), info: b"\n".to_vec() }.to_bytes(), Err(Error::Format));
        assert_eq!(Response::ServerError(vec![b'x'; MAX_LINE]).to_bytes(), Err(Error::LineTooLong));
    }

    // From the binary protocol wiki: a get of "Hello" and its response.
    const GET_REQUEST: [u8; 29] = [
        0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, b'H', b'e', b'l', b'l', b'o',
    ];
    const GET_RESPONSE: [u8; 33] = [
        0x81, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, b'W', b'o', b'r', b'l', b'd',
    ];

    #[test]
    fn binary_get_example() {
        let (req, used) = Packet::parse(&GET_REQUEST).unwrap().unwrap();
        assert_eq!(used, GET_REQUEST.len());
        assert_eq!(req.magic, Magic::Request);
        assert_eq!(req.opcode, opcode::GET);
        assert_eq!(req.key, b"Hello");
        assert!(req.extras.is_empty() && req.value.is_empty());
        assert_eq!(req.to_bytes().unwrap(), GET_REQUEST);
        let mut resp = req.reply(Status::NoError);
        resp.extras = vec![0xde, 0xad, 0xbe, 0xef];
        resp.value = b"World".to_vec();
        resp.cas = 1;
        assert_eq!(resp.to_bytes().unwrap(), GET_RESPONSE);
        assert_eq!(Packet::parse(&GET_RESPONSE).unwrap().unwrap().0, resp);
        for n in 0..GET_REQUEST.len() {
            assert_eq!(Packet::parse(&GET_REQUEST[..n]), Ok(None), "{n} bytes");
        }
    }

    #[test]
    fn binary_extras() {
        let s = StoreExtras { flags: 0xdeadbeef, expiration: 0xe10 };
        assert_eq!(s.to_bytes(), [0xde, 0xad, 0xbe, 0xef, 0, 0, 0x0e, 0x10]);
        assert_eq!(StoreExtras::parse(&s.to_bytes()), Some(s));
        assert_eq!(StoreExtras::parse(&[0; 7]), None);
        let c = CounterExtras { delta: 1, initial: 0, expiration: 0xe10 };
        assert_eq!(c.to_bytes()[7], 1);
        assert_eq!(CounterExtras::parse(&c.to_bytes()), Some(c));
        assert_eq!(CounterExtras::parse(&[0; 21]), None);
        for code in 0..=u16::MAX {
            assert_eq!(Status::from_code(code).code(), code);
        }
    }

    #[test]
    fn binary_errors() {
        assert_eq!(Packet::parse(&[0x82]), Err(BinaryError::Magic(0x82)));
        let mut h = GET_REQUEST;
        h[2..4].copy_from_slice(&251u16.to_be_bytes());
        h[8..12].copy_from_slice(&300u32.to_be_bytes());
        assert_eq!(Packet::parse(&h), Err(BinaryError::KeyLength(251)));
        let mut h = GET_REQUEST;
        h[4] = 1; // extras and key past the body
        assert_eq!(Packet::parse(&h), Err(BinaryError::BodyLength(5)));
        let mut h = GET_REQUEST;
        h[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Packet::parse(&h), Err(BinaryError::BodyLength(u32::MAX as usize)));
        let mut p = Packet::parse(&GET_REQUEST).unwrap().unwrap().0;
        p.extras = vec![0; 256];
        assert_eq!(p.to_bytes(), Err(BinaryError::ExtrasLength(256)));
        p.extras = vec![];
        p.key = vec![0; MAX_KEY + 1];
        assert_eq!(p.to_bytes(), Err(BinaryError::KeyLength(MAX_KEY + 1)));
        p.key = vec![];
        p.value = vec![0; MAX_BODY + 1];
        assert_eq!(p.to_bytes(), Err(BinaryError::BodyLength(MAX_BODY + 1)));
        p.value = vec![0; MAX_BODY];
        assert!(Packet::parse(&p.to_bytes().unwrap()).unwrap().is_some());
        for e in
            [BinaryError::Magic(0), BinaryError::KeyLength(1), BinaryError::ExtrasLength(1), BinaryError::BodyLength(1)]
        {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn binary_decoder() {
        let stream: Vec<u8> = GET_REQUEST.iter().chain(&GET_RESPONSE).copied().collect();
        let mut d = BinaryDecoder::new();
        let mut got = Vec::new();
        for b in &stream {
            d.feed(std::slice::from_ref(b));
            while let Some(p) = d.next_packet() {
                got.push(p.unwrap().magic);
            }
        }
        assert_eq!(got, [Magic::Request, Magic::Response]);
        assert_eq!(d.buffered(), 0);
        // Decoders can be cloned, to fork a connection's state.
        let mut text = CommandDecoder::new();
        text.feed(b"get a");
        let mut fork = text.clone();
        fork.feed(b"\r\n");
        assert_eq!(fork.next_command(), Some(Ok(Command::Get { keys: vec![key("a")], cas: false })));
        assert_eq!(text.next_command(), None);
        let _ = (d.clone(), ResponseDecoder::new().clone());
        d.feed(&[0x00]);
        assert_eq!(d.next_packet(), Some(Err(BinaryError::Magic(0))));
        d.feed(&GET_REQUEST);
        assert_eq!(d.next_packet(), Some(Err(BinaryError::Magic(0))));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn udp_frames() {
        let f = UdpFrame::parse(b"\x00\x07\x00\x00\x00\x01\x00\x00get a\r\n").unwrap();
        assert_eq!(f, UdpFrame { request_id: 7, sequence: 0, total: 1, payload: b"get a\r\n".to_vec() });
        assert_eq!(f.to_bytes().unwrap(), b"\x00\x07\x00\x00\x00\x01\x00\x00get a\r\n");
        for n in 0..UDP_HEADER_LEN {
            assert_eq!(UdpFrame::parse(&[0; 8][..n]), Err(UdpError::Short(n)));
        }
        assert_eq!(UdpFrame::parse(&[0, 0, 0, 0, 0, 1, 0, 1]), Err(UdpError::Reserved(1)));
        assert_eq!(UdpFrame::parse(&[0, 0, 0, 1, 0, 1, 0, 0]), Err(UdpError::Sequence { sequence: 1, total: 1 }));
        assert_eq!(UdpFrame::parse(&[0; 8]), Err(UdpError::Sequence { sequence: 0, total: 0 }));
        let mut long = vec![0, 0, 0, 0, 0, 1, 0, 0];
        long.extend(vec![0; MAX_UDP_PAYLOAD + 1]);
        assert_eq!(UdpFrame::parse(&long), Err(UdpError::TooLong(MAX_UDP_PAYLOAD + 1)));
        let bad = UdpFrame { request_id: 0, sequence: 2, total: 2, payload: vec![] };
        assert_eq!(bad.to_bytes(), Err(UdpError::Sequence { sequence: 2, total: 2 }));
        let bad = UdpFrame { request_id: 0, sequence: 0, total: 1, payload: vec![0; MAX_UDP_PAYLOAD + 1] };
        assert_eq!(bad.to_bytes(), Err(UdpError::TooLong(MAX_UDP_PAYLOAD + 1)));
        // A reply split and put back together.
        let message: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let frames = UdpFrame::split(9, &message).unwrap();
        assert_eq!(frames.len(), 4);
        let mut back = Vec::new();
        for f in &frames {
            let bytes = f.to_bytes().unwrap();
            assert!(bytes.len() <= UDP_MAX_DATAGRAM);
            let again = UdpFrame::parse(&bytes).unwrap();
            assert_eq!((again.request_id, again.total), (9, 4));
            back.extend(again.payload);
        }
        assert_eq!(back, message);
        assert_eq!(UdpFrame::split(1, b"").unwrap().len(), 1);
        for e in [
            UdpError::Short(1),
            UdpError::Reserved(1),
            UdpError::Sequence { sequence: 1, total: 0 },
            UdpError::TooLong(1),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn decoder_takes_many_small_commands_in_linear_time() {
        let one = b"set k 0 0 1\r\nx\r\nget k\r\n";
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 100_000).collect();
        let started = std::time::Instant::now();
        let got = commands(&stream);
        assert_eq!(got.len(), 200_000);
        assert!(got.iter().all(Result::is_ok));
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
        // A long line a byte at a time is searched once.
        let mut d = CommandDecoder::new();
        let started = std::time::Instant::now();
        for _ in 0..200 {
            for _ in 0..MAX_LINE - 3 {
                d.feed(b" ");
                assert_eq!(d.next_command(), None);
            }
            d.feed(b"\r\n");
            assert_eq!(d.next_command(), Some(Err(Error::UnknownCommand)));
        }
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    /// A deterministic generator: the 64-bit LCG from Knuth's MMIX.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Bytes built from pieces of well-formed messages, cut, joined and
    /// bit-flipped, so the readers see near misses as well as noise.
    fn fuzz_buffer(rng: &mut Lcg, pieces: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        for _ in 0..rng.below(6) {
            let piece = &pieces[rng.below(pieces.len())];
            match rng.below(4) {
                0 => buf.extend_from_slice(&piece[..rng.below(piece.len() + 1)]),
                1 => buf.extend((0..rng.below(40)).map(|_| rng.next() as u8)),
                _ => buf.extend_from_slice(piece),
            }
        }
        for _ in 0..rng.below(4) {
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf[i] = match rng.below(4) {
                    0 => b' ',
                    1 => b'\n',
                    2 => b'0' + rng.below(10) as u8,
                    _ => rng.next() as u8,
                };
            }
        }
        buf
    }

    #[test]
    fn fuzz_text_decoders() {
        let mut pieces: Vec<Vec<u8>> = sample_commands().iter().map(|c| c.to_bytes().unwrap()).collect();
        pieces.extend(sample_responses().iter().map(|r| r.to_bytes().unwrap()));
        pieces.push(b"set k 0 0 99999999\r\n".to_vec());
        pieces.push(b"\r\n".to_vec());
        let mut rng = Lcg(1);
        for _ in 0..4000 {
            let buf = fuzz_buffer(&mut rng, &pieces);
            // Commands: whole, and a byte at a time, give the same.
            let whole = commands(&buf);
            let mut d = CommandDecoder::new();
            let mut bytewise = Vec::new();
            'outer: for b in &buf {
                d.feed(std::slice::from_ref(b));
                while let Some(r) = d.next_command() {
                    let fatal = matches!(r, Err(e) if e.is_fatal());
                    bytewise.push(r);
                    if fatal {
                        break 'outer;
                    }
                }
            }
            assert_eq!(whole, bytewise, "{buf:?}");
            for c in whole.iter().flatten() {
                let bytes = c.to_bytes().unwrap();
                assert_eq!(commands(&bytes), [Ok(c.clone())]);
            }
            // Replies, the same way.
            let whole = responses(&buf);
            let mut d = ResponseDecoder::new();
            let mut bytewise = Vec::new();
            'outer: for b in &buf {
                d.feed(std::slice::from_ref(b));
                while let Some(r) = d.next_response() {
                    let fatal = matches!(r, Err(e) if e.is_fatal());
                    bytewise.push(r);
                    if fatal {
                        break 'outer;
                    }
                }
            }
            assert_eq!(whole, bytewise, "{buf:?}");
            for r in whole.iter().flatten() {
                let bytes = r.to_bytes().unwrap();
                assert_eq!(responses(&bytes), [Ok(r.clone())]);
            }
        }
    }

    #[test]
    fn fuzz_binary_and_udp() {
        let mut set = Packet::parse(&GET_REQUEST).unwrap().unwrap().0;
        set.opcode = opcode::SET;
        set.extras = StoreExtras { flags: 1, expiration: 2 }.to_bytes().to_vec();
        set.value = b"value".to_vec();
        let pieces = vec![
            GET_REQUEST.to_vec(),
            GET_RESPONSE.to_vec(),
            set.to_bytes().unwrap(),
            b"\x00\x01\x00\x00\x00\x01\x00\x00x".to_vec(),
        ];
        let mut rng = Lcg(2);
        for _ in 0..4000 {
            let buf = fuzz_buffer(&mut rng, &pieces);
            let mut whole = BinaryDecoder::new();
            whole.feed(&buf);
            let mut packets = Vec::new();
            while let Some(Ok(p)) = whole.next_packet() {
                packets.push(p);
            }
            let mut bytewise = BinaryDecoder::new();
            let mut again = Vec::new();
            for b in &buf {
                bytewise.feed(std::slice::from_ref(b));
                while let Some(Ok(p)) = bytewise.next_packet() {
                    again.push(p);
                }
            }
            assert_eq!(packets, again);
            for p in &packets {
                let bytes = p.to_bytes().unwrap();
                assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
                let _ = StoreExtras::parse(&p.extras);
                let _ = CounterExtras::parse(&p.extras);
            }
            if let Ok(f) = UdpFrame::parse(&buf) {
                assert_eq!(f.to_bytes().unwrap(), buf);
            }
        }
    }
}
