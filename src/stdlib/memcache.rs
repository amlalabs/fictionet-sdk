//! memcached: reading and writing the text protocol, the binary protocol
//! and UDP frames, with no I/O.
//!
//! `Command`, `Response`, `Packet`, and `UdpFrame` implement `Wire`. Text
//! decoders and `codec::Frames<Packet>` handle streams. There is no cache
//! session or `Service`, storage engine, expiration scheduler, or live
//! transport.
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
//! A world that plays a memcached server pushes TCP bytes into
//! [`Stream<Commands>`](fictionet::stdlib::codec::Stream), reads [`Command`] values,
//! and writes each [`Response`] back. A client uses
//! [`Stream<Responses>`](fictionet::stdlib::codec::Stream). Headers accept CRLF or
//! bare LF; counted data blocks require CRLF. Binary connections use
//! [`Stream<codec::Frames<Packet>>`](fictionet::stdlib::codec::Stream). [`UdpFrame`] describes each
//! datagram. Cache contents and expiration belong to world code.
//!
//! Every reader checks keys, line lengths, numbers and data lengths,
//! because the agent can send any bytes it likes. A command that breaks the
//! protocol becomes an [`Error`], and [`Error::reply`] is what memcached
//! answers it with, unless [`Commands::quiet_error`] says the command
//! asked for no reply. Only a line longer than [`MAX_LINE`] (or
//! [`MAX_GET_LINE`] for `get` and `gets`) breaks the stream for good, and
//! the server should then close the connection, as memcached does with a
//! line it will not take. Each text input buffer holds at most [`MAX_LINE`]
//! bytes. Assemblies are bounded by [`MAX_TEXT_HELD`]. Writers refuse
//! invalid fields, oversized values, and values that would change when
//! read back.
//!
//! ```
//! use std::collections::HashMap;
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::memcache::{Command, Commands, Response};
//!
//! let mut cache: HashMap<Vec<u8>, (u32, Vec<u8>)> = HashMap::new();
//! let mut decoder = Stream::new(Commands::new());
//! let input = b"set greeting 5 0 5\r\nhello\r\nget greeting other\r\nfrob\r\n";
//! assert_eq!(decoder.push(input), input.len());
//! let mut out = Vec::new();
//! while let Some(command) = decoder.next() {
//!     let Ok(command) = command else { break };
//!     let replies = match command {
//!         // The command asked for no reply, so its error gets none.
//!         Err(_) if decoder.decoder().quiet_error() => vec![],
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
//!         reply.write(&mut out).unwrap();
//!     }
//! }
//! assert_eq!(out, b"STORED\r\nVALUE greeting 5 5\r\nhello\r\nEND\r\nERROR\r\n");
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Prefixed;
use fictionet::stdlib::codec::{self, Decode, Step, Wire, be16, be32, be64};

/// The port memcached listens on, for both TCP and UDP.
pub const PORT: u16 = 11211;
/// The longest key, in bytes.
pub const MAX_KEY: usize = 250;
/// The longest text protocol line, counting its CR LF, other than a `get`
/// or `gets` command. A longer line breaks the stream. This is the
/// module's own bound: memcached closes the connection once 2048 bytes
/// have come without an LF, unless the line is a `get` or `gets`.
pub const MAX_LINE: usize = 8192;
/// The longest data block a reader takes in, and a writer writes. It is
/// memcached's default item size limit, 1 MiB.
pub const MAX_VALUE: usize = 1024 * 1024;
/// The longest `get` or `gets` command line, counting its CR LF. memcached
/// takes multigets of any length; this module bounds them at 1 MiB, room
/// for over 4000 keys of the longest length. A command decoder treats a
/// line as one of these when it starts with `get ` or `gets ` after at
/// most 100 spaces, as memcached does.
pub const MAX_GET_LINE: usize = MAX_VALUE;
/// The largest data length a line may state. A larger one is a format
/// error, as in memcached, which reads it into a 32-bit signed number.
pub const MAX_DECLARED: usize = i32::MAX as usize - 2;
/// The most flags one meta command or meta reply may carry.
pub const MAX_META_FLAGS: usize = 24;

/// Why a text protocol line, a data block after it, a binary packet or a
/// UDP frame cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A writer's line exceeds [`MAX_LINE`], or [`MAX_GET_LINE`] for `get`
    /// or `gets`, including CRLF. Also returned by [`Wire::parse`] for
    /// input beyond [`MAX_TEXT_UNIT`]. Stream readers report overlong
    /// lines as [`FrameError::LineTooLong`].
    LineTooLong,
    /// The first word was not a command, or not a reply, this module
    /// knows. An empty line is one too. A command with too few or too many
    /// words is one as well, since memcached answers both with `ERROR`.
    UnknownCommand,
    /// A number was not a number or out of range, a word held a space or
    /// control byte, or a meta command, `delete`, `gat` or a reply had the
    /// wrong words. A meta command's flags are checked as memcached checks
    /// them, and this is the error for a flag it does not know, a flag
    /// given twice, a token that is not the number the flag takes, a mode
    /// the command does not have, an opaque token over 32 bytes counting
    /// its `O`, or, with `b`, a key that is not base64. Writers also return
    /// this for an empty key list or token, too many meta flags, or CR or
    /// LF in message text.
    Format,
    /// The delta of `incr` or `decr` was not a number from 0 to
    /// `u64::MAX`.
    Delta,
    /// The expiration time of `touch`, `gat` or `gats` was not a number
    /// that fits in 32 signed bits.
    Exptime,
    /// A key was empty, longer than [`MAX_KEY`], or held a space or control byte.
    Key,
    /// A declared data block length exceeds the reader's configured limit
    /// ([`MAX_VALUE`] by default), or a writer's block exceeds [`MAX_VALUE`].
    /// A decoder skips the block, as memcached does.
    TooLarge(usize),
    /// The data block did not end with CR LF. A decoder has skipped it.
    BadDataChunk,
    /// A command or response would be refused or change when read back
    /// after its fields pass the writer's checks. The stream readers
    /// ([`Commands`] and [`Responses`]) never yield this.
    Unwritable,
    /// The text unit ended early.
    Incomplete,
    /// Bytes followed the text unit or binary packet.
    Trailing,
    /// A binary packet's first byte was neither magic byte. It breaks the
    /// stream: a reader cannot find where the next packet starts.
    Magic(u8),
    /// A binary packet's key was longer than [`MAX_KEY`].
    KeyLength(usize),
    /// A binary packet's extras were longer than 255 bytes. Only a writer
    /// gives this.
    ExtrasLength(usize),
    /// A binary packet's body was longer than [`MAX_BODY`], or shorter
    /// than its extras and key.
    BodyLength(usize),
    /// An extras payload has the wrong length.
    Extras {
        /// Required bytes for this extras type.
        expected: usize,
        /// Bytes supplied by the caller.
        actual: usize,
    },
    /// A datagram was shorter than the 8-byte UDP frame header, by its length.
    Short(usize),
    /// A UDP frame's reserved field was not 0.
    Reserved(u16),
    /// A UDP frame's total was 0, or its sequence number not below it.
    Sequence {
        /// The sequence number.
        sequence: u16,
        /// The total.
        total: u16,
    },
    /// A UDP payload was longer than [`MAX_UDP_PAYLOAD`], or a message too
    /// long to split into 65535 datagrams.
    PayloadTooLong(usize),
}

impl Error {
    /// The reply memcached sends a client for this protocol error.
    /// [`Error::Unwritable`], and the errors that only a writer, a binary
    /// packet or a UDP frame gives, map to the generic `ERROR` reply.
    pub fn reply(self) -> Response {
        match self {
            Error::LineTooLong => Response::ClientError(b"line too long".to_vec()),
            Error::UnknownCommand
            | Error::Unwritable
            | Error::Incomplete
            | Error::Trailing
            | Error::Magic(_)
            | Error::KeyLength(_)
            | Error::ExtrasLength(_)
            | Error::BodyLength(_)
            | Error::Extras { .. }
            | Error::Short(_)
            | Error::Reserved(_)
            | Error::Sequence { .. }
            | Error::PayloadTooLong(_) => Response::Error,
            Error::Format | Error::Key => {
                Response::ClientError(b"bad command line format".to_vec())
            }
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
            Error::Key => write!(
                f,
                "key empty, over {MAX_KEY} bytes, or holding a space or control byte"
            ),
            Error::TooLarge(n) => write!(f, "data block of {n} bytes exceeds the configured limit"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::BadDataChunk => f.write_str("data block not ended by CR LF"),
            Error::Incomplete => f.write_str("incomplete memcache unit"),
            Error::Trailing => f.write_str("bytes after memcache unit"),
            Error::Magic(m) => write!(f, "magic byte {m:#04x}, not 0x80 or 0x81"),
            Error::KeyLength(n) => write!(f, "key of {n} bytes, over {MAX_KEY}"),
            Error::ExtrasLength(n) => write!(f, "extras of {n} bytes, over 255"),
            Error::BodyLength(n) => write!(
                f,
                "body length {n}, over {MAX_BODY} or short of extras and key"
            ),
            Error::Extras { expected, actual } => {
                write!(f, "extras require {expected} bytes, got {actual}")
            }
            Error::Short(n) => write!(
                f,
                "datagram of {n} bytes, shorter than the {UDP_HEADER_LEN}-byte header"
            ),
            Error::Reserved(r) => write!(f, "reserved field {r}, not 0"),
            Error::Sequence { sequence, total } => {
                write!(f, "sequence {sequence} of {total} datagrams")
            }
            Error::PayloadTooLong(n) => write!(f, "{n} bytes, too many for UDP"),
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
        MetaFlag {
            flag,
            token: token.to_vec(),
        }
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
pub enum Command {
    /// `set`, `add`, `replace`, `append` or `prepend`: store `data` under
    /// `key` with the client's `flags` and expiration time `exptime`. With
    /// `noreply` the server sends nothing back.
    Store {
        /// The storage operation.
        verb: StoreVerb,
        /// The item key.
        key: Vec<u8>,
        /// The client flags stored with the item.
        flags: u32,
        /// The expiration time in seconds.
        exptime: i32,
        /// The counted data block.
        data: Vec<u8>,
        /// Whether the server should omit the reply.
        noreply: bool,
    },
    /// `cas`: store as `set` does, only if the item's CAS value is still
    /// `unique`.
    Cas {
        /// The item key.
        key: Vec<u8>,
        /// The client flags stored with the item.
        flags: u32,
        /// The expiration time in seconds.
        exptime: i32,
        /// The CAS value that must still match.
        unique: u64,
        /// The counted data block.
        data: Vec<u8>,
        /// Whether the server should omit the reply.
        noreply: bool,
    },
    /// `get`, or `gets` when `cas` is set: the values of `keys`.
    Get {
        /// The item keys, in request order.
        keys: Vec<Vec<u8>>,
        /// Whether to request CAS values.
        cas: bool,
    },
    /// `gat`, or `gats` when `cas` is set: the values of `keys`, also
    /// setting their expiration time to `exptime`.
    Gat {
        /// The expiration time in seconds.
        exptime: i32,
        /// The item keys, in request order.
        keys: Vec<Vec<u8>>,
        /// Whether to request CAS values.
        cas: bool,
    },
    /// `delete`: remove `key`.
    Delete {
        /// The item key.
        key: Vec<u8>,
        /// Whether the server should omit the reply.
        noreply: bool,
    },
    /// `incr`: add `delta` to the number `key` holds.
    Incr {
        /// The item key.
        key: Vec<u8>,
        /// The amount to add or subtract.
        delta: u64,
        /// Whether the server should omit the reply.
        noreply: bool,
    },
    /// `decr`: subtract `delta` from the number `key` holds, stopping at 0.
    Decr {
        /// The item key.
        key: Vec<u8>,
        /// The amount to add or subtract.
        delta: u64,
        /// Whether the server should omit the reply.
        noreply: bool,
    },
    /// `touch`: set the expiration time of `key`.
    Touch {
        /// The item key.
        key: Vec<u8>,
        /// The expiration time in seconds.
        exptime: i32,
        /// Whether the server should omit the reply.
        noreply: bool,
    },
    /// `stats`, with any words after it, such as `items` or `slabs`.
    Stats {
        /// The words after the command.
        args: Vec<Vec<u8>>,
    },
    /// `version`: the server's version.
    Version,
    /// `verbosity`: set how much the server logs.
    Verbosity {
        /// The server logging level.
        level: u32,
        /// Whether the server should omit the reply.
        noreply: bool,
    },
    /// `flush_all`: drop every item, now or after `delay` seconds.
    FlushAll {
        /// The optional delay in seconds.
        delay: Option<i32>,
        /// Whether the server should omit the reply.
        noreply: bool,
    },
    /// `quit`: the client is done. The server closes the connection.
    Quit,
    /// `mg`: read `key`, returning what `flags` ask for.
    MetaGet {
        /// The item key.
        key: Vec<u8>,
        /// The meta flags, in wire order.
        flags: Vec<MetaFlag>,
    },
    /// `ms`: store `data` under `key`, as `flags` say.
    MetaSet {
        /// The item key.
        key: Vec<u8>,
        /// The meta flags, in wire order.
        flags: Vec<MetaFlag>,
        /// The counted data block.
        data: Vec<u8>,
    },
    /// `md`: delete `key`, as `flags` say.
    MetaDelete {
        /// The item key.
        key: Vec<u8>,
        /// The meta flags, in wire order.
        flags: Vec<MetaFlag>,
    },
    /// `ma`: add to or subtract from the number `key` holds, as `flags` say.
    MetaArithmetic {
        /// The item key.
        key: Vec<u8>,
        /// The meta flags, in wire order.
        flags: Vec<MetaFlag>,
    },
    /// `me`: what the server knows about the item under `key`.
    MetaDebug {
        /// The item key.
        key: Vec<u8>,
        /// The meta flags, in wire order.
        flags: Vec<MetaFlag>,
    },
    /// `mn`: nothing. The server answers `MN`, which marks the end of a
    /// batch of quiet commands.
    MetaNoop,
}

impl Command {
    /// Whether the command carries `noreply`, on the classic commands, or
    /// the `q` flag, on `mg`, `ms`, `md` and `ma`. With `noreply` the
    /// server sends nothing back. With `q` it leaves out only the usual
    /// reply: `EN` for `mg`, and `HD` for `ms`, `md` and `ma`. It still
    /// sends a value, any other status, and any error.
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
    /// `RESET`: the answer to `stats reset`.
    Reset,
    /// `CLIENT_ERROR`, with a message: the command broke the protocol.
    ClientError(Vec<u8>),
    /// `SERVER_ERROR`, with a message: the server failed.
    ServerError(Vec<u8>),
    /// `VALUE`: one item, with its CAS value if asked with `gets`.
    Value {
        /// The item key.
        key: Vec<u8>,
        /// The client flags stored with the item.
        flags: u32,
        /// The optional CAS value.
        cas: Option<u64>,
        /// The counted data block.
        data: Vec<u8>,
    },
    /// `STAT`: one statistic's `name` and `value`.
    Stat {
        /// The statistic name.
        name: Vec<u8>,
        /// The statistic value.
        value: Vec<u8>,
    },
    /// `VERSION`, with the version text.
    Version(Vec<u8>),
    /// The new value after `incr` or `decr`.
    Number(u64),
    /// A meta reply without a value, with the flags it returns.
    Meta {
        /// The meta reply status.
        status: MetaStatus,
        /// The meta flags, in wire order.
        flags: Vec<MetaFlag>,
    },
    /// `VA`: a meta reply with a value.
    MetaValue {
        /// The meta flags, in wire order.
        flags: Vec<MetaFlag>,
        /// The counted data block.
        data: Vec<u8>,
    },
    /// `ME`: what the server knows about `key`, as `name=value` words.
    MetaDebug {
        /// The item key.
        key: Vec<u8>,
        /// The item details as name=value words.
        info: Vec<u8>,
    },
}

/// What reads a line: the message, and the length of the data block that
/// follows it, if one does.
type Head<T> = fn(&[u8]) -> Result<(T, Option<usize>), Fail>;

/// A line that could not be read, how many bytes after it to drop (the
/// data block the line stated, with its CR LF, or 0), and whether the line
/// asked for no reply.
#[derive(Debug)]
struct Fail {
    error: Error,
    skip: u64,
    quiet: bool,
}

impl Fail {
    /// The failure for `error`, dropping `skip` bytes after the line. A
    /// block too large to take is dropped whatever `skip` says, as
    /// memcached does.
    fn new(error: Error, skip: u64, quiet: bool) -> Fail {
        let skip = if let Error::TooLarge(n) = error {
            n as u64 + 2
        } else {
            skip
        };
        Fail { error, skip, quiet }
    }
}

/// Whether held bytes start a `get` or `gets` line, after at most 100
/// spaces: the lines memcached lets run past its usual bound.
fn is_get_line(rest: &[u8]) -> bool {
    // Counting past 100 would only refuse the line, and would make a long
    // run of spaces that comes a byte at a time slow to read.
    let spaces = rest.iter().take(101).take_while(|&&b| b == b' ').count();
    let word = &rest[spaces..];
    spaces <= 100 && (word.starts_with(b"get ") || word.starts_with(b"gets "))
}

fn parse_command(line: &[u8]) -> Result<(Command, Option<usize>), Fail> {
    let (mut skip, mut quiet) = (0, false);
    parse_command_line(line, &mut skip, &mut quiet).map_err(|error| Fail::new(error, skip, quiet))
}

/// Reads a command line. When an error comes after the line's data length
/// is known, and the data block should be dropped with it, `skip` says how
/// many bytes that is. Once a classic command's `noreply` is known,
/// `quiet` says whether it was there, since memcached sends no reply for
/// an error after that.
fn parse_command_line(
    line: &[u8],
    skip: &mut u64,
    quiet: &mut bool,
) -> Result<(Command, Option<usize>), Error> {
    let t = tokens(line);
    let Some((&verb, args)) = t.split_first() else {
        return Err(Error::UnknownCommand);
    };
    if let Some(verb) = StoreVerb::from_name(verb) {
        let (args, noreply) = optional_noreply(args, 4)?;
        *quiet = noreply;
        let [key, flags, exptime, bytes] = args else {
            return Err(Error::UnknownCommand);
        };
        let (key, flags, exptime, n) = (
            key_of(key)?,
            small(flags)?,
            signed(exptime)?,
            length(bytes)?,
        );
        return block(
            Command::Store {
                verb,
                key,
                flags,
                exptime,
                data: Vec::new(),
                noreply,
            },
            n,
        );
    }
    let command = match verb {
        b"cas" => {
            let (args, noreply) = optional_noreply(args, 5)?;
            *quiet = noreply;
            let [key, flags, exptime, bytes, unique] = args else {
                return Err(Error::UnknownCommand);
            };
            let (key, flags, exptime, n) = (
                key_of(key)?,
                small(flags)?,
                signed(exptime)?,
                length(bytes)?,
            );
            let unique = unsigned(unique)?;
            return block(
                Command::Cas {
                    key,
                    flags,
                    exptime,
                    unique,
                    data: Vec::new(),
                    noreply,
                },
                n,
            );
        }
        b"get" | b"gets" => {
            if args.is_empty() {
                return Err(Error::UnknownCommand);
            }
            Command::Get {
                keys: keys_of(args)?,
                cas: verb == b"gets",
            }
        }
        b"gat" | b"gats" => {
            let (exptime, keys) = args.split_first().ok_or(Error::UnknownCommand)?;
            let exptime = signed(exptime).map_err(|_| Error::Exptime)?;
            Command::Gat {
                exptime,
                keys: keys_of(keys)?,
                cas: verb == b"gats",
            }
        }
        b"delete" => {
            if args.is_empty() || args.len() > 3 {
                return Err(Error::UnknownCommand);
            }
            let (args, noreply) = strip_noreply(args, 1);
            *quiet = noreply;
            // memcached still takes an old time argument, if it is 0.
            match args {
                [key] => Command::Delete {
                    key: key_of(key)?,
                    noreply,
                },
                [key, time] if *time == b"0" => Command::Delete {
                    key: key_of(key)?,
                    noreply,
                },
                _ => return Err(Error::Format),
            }
        }
        b"incr" | b"decr" => {
            let (args, noreply) = optional_noreply(args, 2)?;
            *quiet = noreply;
            let [key, delta] = args else {
                return Err(Error::UnknownCommand);
            };
            let (key, delta) = (key_of(key)?, unsigned(delta).map_err(|_| Error::Delta)?);
            if verb == b"incr" {
                Command::Incr {
                    key,
                    delta,
                    noreply,
                }
            } else {
                Command::Decr {
                    key,
                    delta,
                    noreply,
                }
            }
        }
        b"touch" => {
            let (args, noreply) = optional_noreply(args, 2)?;
            *quiet = noreply;
            let [key, exptime] = args else {
                return Err(Error::UnknownCommand);
            };
            let key = key_of(key)?;
            Command::Touch {
                key,
                exptime: signed(exptime).map_err(|_| Error::Exptime)?,
                noreply,
            }
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
            *quiet = noreply;
            let [level] = args else {
                return Err(Error::UnknownCommand);
            };
            Command::Verbosity {
                level: small(level)?,
                noreply,
            }
        }
        b"flush_all" => {
            if args.len() > 2 {
                return Err(Error::UnknownCommand);
            }
            // A final noreply is taken off, and a word after the delay is
            // ignored, as memcached does.
            let (args, noreply) = strip_noreply(args, 0);
            *quiet = noreply;
            match args.first() {
                None => Command::FlushAll {
                    delay: None,
                    noreply,
                },
                Some(delay) => Command::FlushAll {
                    delay: Some(signed(delay)?),
                    noreply,
                },
            }
        }
        b"ms" => {
            let [key, bytes, flags @ ..] = args else {
                return Err(Error::Format);
            };
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
            check_meta(b"ms", &key, &flags)?;
            return block(
                Command::MetaSet {
                    key,
                    flags,
                    data: Vec::new(),
                },
                n,
            );
        }
        b"mg" | b"md" | b"ma" | b"me" => {
            let [key, flags @ ..] = args else {
                return Err(Error::Format);
            };
            let (key, flags) = (key_of(key)?, meta_flags(flags)?);
            check_meta(verb, &key, &flags)?;
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
    if let Command::Store { data, .. } | Command::Cas { data, .. } | Command::MetaSet { data, .. } =
        command
    {
        *data = block;
    }
}

fn parse_response(line: &[u8]) -> Result<(Response, Option<usize>), Fail> {
    let mut skip = 0;
    parse_response_line(line, &mut skip).map_err(|error| Fail::new(error, skip, false))
}

/// Reads a reply line. When an error comes after a `VALUE` or `VA` line's
/// data length is known, `skip` says how many bytes to drop with it.
fn parse_response_line(line: &[u8], skip: &mut u64) -> Result<(Response, Option<usize>), Error> {
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
        b"RESET" => Some(Response::Reset),
        _ if !first.is_empty() && first.iter().all(u8::is_ascii_digit) => {
            let n = unsigned(first)?;
            // protocol.txt lets the new value of a decr be padded with
            // spaces at the end.
            return match rest {
                Some(pad) if pad.iter().any(|&b| b != b' ') => Err(Error::Format),
                _ => Ok((Response::Number(n), None)),
            };
        }
        _ => None,
    };
    if let Some(r) = fixed {
        return if rest.is_none() {
            Ok((r, None))
        } else {
            Err(Error::Format)
        };
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
            Response::Stat {
                name: token_of(&rest[..i])?,
                value: text(Some(&rest[i + 1..]))?,
            }
        }
        b"ME" => {
            let rest = rest.ok_or(Error::Format)?;
            let (key, info) = match rest.iter().position(|&b| b == b' ') {
                Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                None => (rest, None),
            };
            Response::MetaDebug {
                key: key_of(key)?,
                info: text(info)?,
            }
        }
        b"VALUE" => {
            let t = tokens(rest.unwrap_or(b""));
            let (key, flags, bytes, cas) = match t[..] {
                [key, flags, bytes] => (key, flags, bytes, None),
                [key, flags, bytes, cas] => (key, flags, bytes, Some(cas)),
                _ => return Err(Error::Format),
            };
            // Once the length is known, a bad word drops the data block too,
            // so its bytes are not read as replies.
            let n = length(bytes)?;
            *skip = n as u64 + 2;
            let (key, flags, cas) = (key_of(key)?, small(flags)?, cas.map(unsigned).transpose()?);
            return block(
                Response::Value {
                    key,
                    flags,
                    cas,
                    data: Vec::new(),
                },
                n,
            );
        }
        b"VA" => {
            let t = tokens(rest.unwrap_or(b""));
            let [bytes, flags @ ..] = &t[..] else {
                return Err(Error::Format);
            };
            let n = length(bytes)?;
            *skip = n as u64 + 2;
            let flags = meta_flags(flags)?;
            return block(
                Response::MetaValue {
                    flags,
                    data: Vec::new(),
                },
                n,
            );
        }
        code => match MetaStatus::from_code(code) {
            Some(status) => Response::Meta {
                status,
                flags: meta_flags(&tokens(rest.unwrap_or(b"")))?,
            },
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
    line.split(|&b| b == b' ')
        .filter(|t| !t.is_empty())
        .collect()
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
fn optional_noreply<'a, 'b>(
    args: &'a [&'b [u8]],
    required: usize,
) -> Result<(&'a [&'b [u8]], bool), Error> {
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

fn check_key(t: &[u8]) -> Result<(), Error> {
    if t.is_empty() || t.len() > MAX_KEY || !t.iter().all(|&b| is_token_byte(b)) {
        return Err(Error::Key);
    }
    Ok(())
}

fn key_of(t: &[u8]) -> Result<Vec<u8>, Error> {
    check_key(t)?;
    Ok(t.to_vec())
}

fn keys_of(ts: &[&[u8]]) -> Result<Vec<Vec<u8>>, Error> {
    if ts.is_empty() {
        return Err(Error::Format);
    }
    ts.iter().map(|k| key_of(k)).collect()
}

fn check_token(t: &[u8]) -> Result<(), Error> {
    if t.is_empty() || !t.iter().all(|&b| is_token_byte(b)) {
        return Err(Error::Format);
    }
    Ok(())
}

fn token_of(t: &[u8]) -> Result<Vec<u8>, Error> {
    check_token(t)?;
    Ok(t.to_vec())
}

fn meta_flags(ts: &[&[u8]]) -> Result<Vec<MetaFlag>, Error> {
    if ts.len() > MAX_META_FLAGS {
        return Err(Error::Format);
    }
    ts.iter()
        .map(|t| {
            let t = token_of(t)?;
            Ok(MetaFlag {
                flag: t[0],
                token: t[1..].to_vec(),
            })
        })
        .collect()
}

/// The flags memcached takes on `mg`, `ms`, `md` and `ma`. It refuses any
/// other.
const META_COMMAND_FLAGS: &[u8] = b"bcCDEfFhIJklLMNOPqRstTuvx";

/// The longest opaque token memcached takes, counting its `O`.
const MAX_OPAQUE: usize = 32;

/// Checks the flags of a meta command as memcached does: each flag is one
/// it knows and comes once, a number is a number of the flag's type, a
/// mode is one the command has, an opaque token is at most 32 bytes with
/// its `O`, and with `b` the key decodes as base64. `me` takes any flags.
fn check_meta(verb: &[u8], key: &[u8], flags: &[MetaFlag]) -> Result<(), Error> {
    if verb == b"me" {
        return Ok(());
    }
    let mut seen = [false; 128];
    for f in flags {
        // Every known flag is ASCII, so the index is in range.
        if !META_COMMAND_FLAGS.contains(&f.flag)
            || std::mem::replace(&mut seen[usize::from(f.flag)], true)
        {
            return Err(Error::Format);
        }
        let t = &f.token[..];
        let ok = match f.flag {
            b'N' | b'T' | b'R' => signed(t).is_ok(),
            b'F' => small(t).is_ok(),
            b'C' | b'E' | b'J' | b'D' => unsigned(t).is_ok(),
            b'M' => match (verb, t) {
                (b"ms", [m]) => b"EAPRS".contains(m),
                (b"ma", [m]) => b"I+D-".contains(m),
                (_, [_]) => true,
                _ => false,
            },
            b'O' => t.len() < MAX_OPAQUE,
            b'b' => is_base64(key),
            _ => true,
        };
        if !ok {
            return Err(Error::Format);
        }
    }
    Ok(())
}

/// Whether memcached's base64 decoder takes `key`. It skips bytes outside
/// the alphabet, needs a nonzero multiple of 4 of the rest, and stops at
/// the first group that holds padding, which may hold at most two `=`.
fn is_base64(key: &[u8]) -> bool {
    let alphabet = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
    let count = key.iter().filter(|&&b| alphabet(b)).count();
    if count == 0 || count % 4 != 0 {
        return false;
    }
    let (mut n, mut pad) = (0, 0);
    for &b in key.iter().filter(|&&b| alphabet(b)) {
        n += 1;
        pad += usize::from(b == b'=');
        if n % 4 == 0 && pad > 0 {
            return pad <= 2;
        }
    }
    true
}

/// Message text: anything but CR and LF.
fn check_text(t: &[u8]) -> Result<(), Error> {
    if t.iter().any(|&b| b == b'\r' || b == b'\n') {
        Err(Error::Format)
    } else {
        Ok(())
    }
}

fn unsigned(t: &[u8]) -> Result<u64, Error> {
    if t.is_empty() || !t.iter().all(u8::is_ascii_digit) {
        return Err(Error::Format);
    }
    t.iter()
        .try_fold(0u64, |n, &d| {
            n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
        })
        .ok_or(Error::Format)
}

fn small(t: &[u8]) -> Result<u32, Error> {
    u32::try_from(unsigned(t)?).map_err(|_| Error::Format)
}

/// An expiration time. memcached reads it into a 32-bit signed number and
/// refuses one that does not fit.
fn signed(t: &[u8]) -> Result<i32, Error> {
    match t.split_first() {
        Some((b'-', digits)) => {
            i32::try_from(-i128::from(unsigned(digits)?)).map_err(|_| Error::Format)
        }
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
    if n > MAX_VALUE {
        Err(Error::TooLarge(n))
    } else {
        Ok((message, Some(n)))
    }
}

/// A line being written. Each word is checked against `limit`, counting
/// the CR LF still to come, before it is copied, so a line never grows
/// past its limit.
#[derive(Debug)]
struct Line {
    buf: Vec<u8>,
    limit: usize,
}

impl Line {
    fn new(limit: usize) -> Line {
        Line {
            buf: Vec::new(),
            limit,
        }
    }

    /// Whether `n` more bytes fit, with the CR LF.
    fn fits(&self, n: usize) -> Result<(), Error> {
        if self.buf.len().saturating_add(n).saturating_add(2) > self.limit {
            return Err(Error::LineTooLong);
        }
        Ok(())
    }

    /// Adds one word made of `parts`, after a space unless it is the first.
    fn word(&mut self, parts: &[&[u8]]) -> Result<(), Error> {
        let space = usize::from(!self.buf.is_empty());
        self.fits(parts.iter().fold(space, |n, p| n.saturating_add(p.len())))?;
        if space == 1 {
            self.buf.push(b' ');
        }
        for p in parts {
            self.buf.extend_from_slice(p);
        }
        Ok(())
    }

    fn number(&mut self, n: impl std::fmt::Display) -> Result<(), Error> {
        self.word(&[n.to_string().as_bytes()])
    }

    fn key(&mut self, key: &[u8]) -> Result<(), Error> {
        check_key(key)?;
        self.word(&[key])
    }

    fn keys(&mut self, keys: &[Vec<u8>]) -> Result<(), Error> {
        if keys.is_empty() {
            return Err(Error::Format);
        }
        keys.iter().try_for_each(|k| self.key(k))
    }

    fn token(&mut self, t: &[u8]) -> Result<(), Error> {
        check_token(t)?;
        self.word(&[t])
    }

    fn noreply(&mut self, noreply: bool) -> Result<(), Error> {
        if noreply {
            self.word(&[b"noreply"])
        } else {
            Ok(())
        }
    }

    /// Adds message text, which may hold spaces, after a space. Empty text
    /// adds nothing unless `always` is set.
    fn rest(&mut self, text: &[u8], always: bool) -> Result<(), Error> {
        if text.is_empty() && !always {
            return Ok(());
        }
        self.fits(text.len().saturating_add(1))?;
        check_text(text)?;
        self.buf.push(b' ');
        self.buf.extend_from_slice(text);
        Ok(())
    }

    /// A first word, then message text.
    fn text(&mut self, first: &[u8], text: &[u8]) -> Result<(), Error> {
        self.word(&[first])?;
        self.rest(text, false)
    }

    fn meta_flags(&mut self, flags: &[MetaFlag]) -> Result<(), Error> {
        if flags.len() > MAX_META_FLAGS {
            return Err(Error::Format);
        }
        for f in flags {
            if !is_token_byte(f.flag) || !f.token.iter().all(|&b| is_token_byte(b)) {
                return Err(Error::Format);
            }
            self.word(&[&[f.flag], &f.token])?;
        }
        Ok(())
    }

    fn meta(
        &mut self,
        verb: &[u8],
        key: &[u8],
        n: Option<usize>,
        flags: &[MetaFlag],
    ) -> Result<(), Error> {
        self.word(&[verb])?;
        self.key(key)?;
        if let Some(n) = n {
            self.number(n)?;
        }
        self.meta_flags(flags)?;
        check_meta(verb, key, flags)
    }

    /// The line with its CR LF, then the data block with its own, after
    /// checking the block fits.
    fn finish(self, data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        if let Some(d) = data
            && d.len() > MAX_VALUE
        {
            return Err(Error::TooLarge(d.len()));
        }
        let mut out = self.buf;
        out.extend_from_slice(b"\r\n");
        if let Some(d) = data {
            out.extend_from_slice(d);
            out.extend_from_slice(b"\r\n");
        }
        Ok(out)
    }
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
/// The input capacity of [`codec::Frames<Packet>`](fictionet::stdlib::codec::Frames): one packet of the longest
/// body, with its header.
pub const MAX_BINARY_BUFFERED: usize = BINARY_HEADER_LEN + MAX_BODY;

/// Binary protocol opcodes. The ones ending in `Q` are quiet: the server
/// answers them only on failure, or, for gets, only on a hit.
pub mod opcode {
    /// Read a value.
    pub const GET: u8 = 0x00;
    /// Store a value.
    pub const SET: u8 = 0x01;
    /// Store only when the key is absent.
    pub const ADD: u8 = 0x02;
    /// Store only when the key exists.
    pub const REPLACE: u8 = 0x03;
    /// Delete a value.
    pub const DELETE: u8 = 0x04;
    /// Increase a counter.
    pub const INCREMENT: u8 = 0x05;
    /// Decrease a counter.
    pub const DECREMENT: u8 = 0x06;
    /// Close the connection.
    pub const QUIT: u8 = 0x07;
    /// Invalidate all items.
    pub const FLUSH: u8 = 0x08;
    /// Quiet form of [`GET`].
    pub const GETQ: u8 = 0x09;
    /// End a command batch.
    pub const NOOP: u8 = 0x0a;
    /// Read the server version.
    pub const VERSION: u8 = 0x0b;
    /// Read a value and its key.
    pub const GETK: u8 = 0x0c;
    /// Quiet form of [`GETK`].
    pub const GETKQ: u8 = 0x0d;
    /// Append bytes to a value.
    pub const APPEND: u8 = 0x0e;
    /// Prepend bytes to a value.
    pub const PREPEND: u8 = 0x0f;
    /// Read statistics.
    pub const STAT: u8 = 0x10;
    /// Quiet form of [`SET`].
    pub const SETQ: u8 = 0x11;
    /// Quiet form of [`ADD`].
    pub const ADDQ: u8 = 0x12;
    /// Quiet form of [`REPLACE`].
    pub const REPLACEQ: u8 = 0x13;
    /// Quiet form of [`DELETE`].
    pub const DELETEQ: u8 = 0x14;
    /// Quiet form of [`INCREMENT`].
    pub const INCREMENTQ: u8 = 0x15;
    /// Quiet form of [`DECREMENT`].
    pub const DECREMENTQ: u8 = 0x16;
    /// Quiet form of [`QUIT`].
    pub const QUITQ: u8 = 0x17;
    /// Quiet form of [`FLUSH`].
    pub const FLUSHQ: u8 = 0x18;
    /// Quiet form of [`APPEND`].
    pub const APPENDQ: u8 = 0x19;
    /// Quiet form of [`PREPEND`].
    pub const PREPENDQ: u8 = 0x1a;
    /// Set the logging level.
    pub const VERBOSITY: u8 = 0x1b;
    /// Update expiration.
    pub const TOUCH: u8 = 0x1c;
    /// Read a value and update expiration.
    pub const GAT: u8 = 0x1d;
    /// Quiet form of [`GAT`].
    pub const GATQ: u8 = 0x1e;
    /// List SASL mechanisms.
    pub const SASL_LIST_MECHS: u8 = 0x20;
    /// Begin SASL authentication.
    pub const SASL_AUTH: u8 = 0x21;
    /// Continue SASL authentication.
    pub const SASL_STEP: u8 = 0x22;
    /// Read a value and key and update expiration.
    pub const GATK: u8 = 0x23;
    /// Quiet form of [`GATK`].
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
    /// 0x0020: SASL authentication failed, or is needed first. The binary
    /// protocol page's status table gives 0x0008, but memcached and its
    /// SASL page use 0x0020, so 0x0008 is [`Status::Other`].
    AuthError,
    /// 0x0021: SASL authentication needs another step. As with
    /// [`Status::AuthError`], memcached uses this code, not the table's
    /// 0x0009.
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
            Status::AuthError => 0x20,
            Status::AuthContinue => 0x21,
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
            0x20 => Status::AuthError,
            0x21 => Status::AuthContinue,
            0x81 => Status::UnknownCommand,
            0x82 => Status::OutOfMemory,
            c => Status::Other(c),
        }
    }
}

/// One binary protocol packet: the header's fields and the body. The
/// lengths in the header are worked out from the body, so none is kept.
/// Reading and writing a packet checks only its framing, not whether its
/// extras, key and value suit its opcode: a GET request with extras is
/// still a whole packet. memcached reads such a request, answers it with
/// [`Status::InvalidArguments`] and closes the connection, and a world
/// that plays a server does the same in its own code.
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
    fn parse_prefix(b: &[u8]) -> Result<Option<(Packet, usize)>, Error> {
        let Some(&m) = b.first() else { return Ok(None) };
        let magic = Magic::from_byte(m).ok_or(Error::Magic(m))?;
        if b.len() < BINARY_HEADER_LEN {
            return Ok(None);
        }
        let key_len = usize::from(be16(b, 2).ok_or(Error::Incomplete)?);
        let extras_len = usize::from(b[4]);
        let body = usize::try_from(be32(b, 8).ok_or(Error::Incomplete)?).unwrap_or(usize::MAX);
        if key_len > MAX_KEY {
            return Err(Error::KeyLength(key_len));
        }
        if body > MAX_BODY || key_len + extras_len > body {
            return Err(Error::BodyLength(body));
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
            status: be16(b, 6).ok_or(Error::Incomplete)?,
            opaque: be32(b, 12).ok_or(Error::Incomplete)?,
            cas: u64::from_be_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
            extras: extras.to_vec(),
            key: key.to_vec(),
            value: value.to_vec(),
        };
        Ok(Some((packet, end)))
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

impl Wire for StoreExtras {
    type ParseError = Error;
    type WriteError = core::convert::Infallible;

    /// Reads exactly 8 bytes. Refuses every other length.
    fn parse(extras: &[u8]) -> Result<Self, Error> {
        let [a, b, c, d, e, f, g, h] = *extras else {
            return Err(Error::Extras {
                expected: 8,
                actual: extras.len(),
            });
        };
        Ok(StoreExtras {
            flags: u32::from_be_bytes([a, b, c, d]),
            expiration: u32::from_be_bytes([e, f, g, h]),
        })
    }

    /// Appends the 8 bytes of extras. Every value is representable;
    /// no values are refused.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        Ok(())
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

impl Wire for CounterExtras {
    type ParseError = Error;
    type WriteError = core::convert::Infallible;

    /// Reads exactly 20 bytes. Refuses every other length.
    fn parse(extras: &[u8]) -> Result<Self, Error> {
        if extras.len() != 20 {
            return Err(Error::Extras {
                expected: 20,
                actual: extras.len(),
            });
        }
        let bad = Error::Extras {
            expected: 20,
            actual: extras.len(),
        };
        Ok(CounterExtras {
            delta: be64(extras, 0).ok_or(bad)?,
            initial: be64(extras, 8).ok_or(bad)?,
            expiration: be32(extras, 16).ok_or(bad)?,
        })
    }

    /// Appends the 20 bytes of extras. Every value is representable;
    /// no values are refused.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError> {
        out.extend_from_slice(&self.delta.to_be_bytes());
        out.extend_from_slice(&self.initial.to_be_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        Ok(())
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

impl Wire for UdpFrame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete datagram. Refuses short headers, nonzero reserved
    /// fields, invalid sequence counts, and payloads over [`MAX_UDP_PAYLOAD`].
    fn parse(datagram: &[u8]) -> Result<Self, Error> {
        if datagram.len() < UDP_HEADER_LEN {
            return Err(Error::Short(datagram.len()));
        }
        let (sequence, total, reserved) = (
            be16(datagram, 2).ok_or(Error::Short(datagram.len()))?,
            be16(datagram, 4).ok_or(Error::Short(datagram.len()))?,
            be16(datagram, 6).ok_or(Error::Short(datagram.len()))?,
        );
        if reserved != 0 {
            return Err(Error::Reserved(reserved));
        }
        if sequence >= total {
            return Err(Error::Sequence { sequence, total });
        }
        let payload = &datagram[UDP_HEADER_LEN..];
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(Error::PayloadTooLong(payload.len()));
        }
        Ok(UdpFrame {
            request_id: be16(datagram, 0).ok_or(Error::Short(datagram.len()))?,
            sequence,
            total,
            payload: payload.to_vec(),
        })
    }

    /// Appends one datagram. Refuses invalid sequence counts and payloads
    /// over [`MAX_UDP_PAYLOAD`], leaving `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.sequence >= self.total {
            return Err(Error::Sequence {
                sequence: self.sequence,
                total: self.total,
            });
        }
        if self.payload.len() > MAX_UDP_PAYLOAD {
            return Err(Error::PayloadTooLong(self.payload.len()));
        }
        out.extend_from_slice(&self.request_id.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl UdpFrame {
    /// A message split into datagrams of at most [`UDP_MAX_DATAGRAM`]
    /// bytes, numbered in order. An empty message takes one datagram.
    /// Refuses messages that need more than 65535 datagrams.
    pub fn split(request_id: u16, message: &[u8]) -> Result<Vec<UdpFrame>, Error> {
        let chunk = UDP_MAX_DATAGRAM - UDP_HEADER_LEN;
        let count = message.len().div_ceil(chunk).max(1);
        let total = u16::try_from(count).map_err(|_| Error::PayloadTooLong(message.len()))?;
        let mut frames = Vec::with_capacity(count);
        for sequence in 0..total {
            let from = usize::from(sequence) * chunk;
            let to = (from + chunk).min(message.len());
            frames.push(UdpFrame {
                request_id,
                sequence,
                total,
                payload: message[from..to].to_vec(),
            });
        }
        Ok(frames)
    }
}

/// Maximum bytes retained while assembling a long line or a header and data block.
pub const MAX_TEXT_HELD: usize = MAX_LINE + MAX_VALUE;
/// Maximum wire bytes in one text command or response.
pub const MAX_TEXT_UNIT: usize = MAX_GET_LINE + MAX_VALUE + 2;

/// A terminal text framing fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A line exceeded its named limit.
    LineTooLong,
    /// EOF interrupted a line, counted block, or skipped block.
    Incomplete,
}
impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::LineTooLong => "memcache text line too long",
            Self::Incomplete => "incomplete memcache text unit",
        })
    }
}
impl core::error::Error for FrameError {}

struct TextUnits<T> {
    lines: codec::Lines,
    partial_line: Vec<u8>,
    get_lines: bool,
    long_line: bool,
    pending: Option<(T, usize)>,
    data: Vec<u8>,
    head_bytes: usize,
    skip: u64,
    quiet: bool,
    limit: usize,
}
impl<T: core::fmt::Debug> core::fmt::Debug for TextUnits<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TextUnits")
            .field("partial_line", &self.partial_line)
            .field("get_lines", &self.get_lines)
            .field("long_line", &self.long_line)
            .field("pending", &self.pending)
            .field("data", &self.data)
            .field("head_bytes", &self.head_bytes)
            .field("skip", &self.skip)
            .field("quiet", &self.quiet)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}
impl<T> TextUnits<T> {
    fn new(get_lines: bool, limit: usize) -> Self {
        Self {
            lines: codec::Lines::new(MAX_LINE - 2, codec::Ending::LfOrCrlf),
            partial_line: Vec::new(),
            get_lines,
            long_line: false,
            pending: None,
            data: Vec::new(),
            head_bytes: 0,
            skip: 0,
            quiet: false,
            limit: limit.min(MAX_VALUE),
        }
    }
    fn capacity(&self) -> usize {
        MAX_LINE
    }
    fn held(&self) -> usize {
        self.head_bytes
            .saturating_add(self.data.len())
            .saturating_add(self.partial_line.len())
    }

    fn decode(
        &mut self,
        input: &[u8],
        eof: bool,
        head: Head<T>,
        attach: fn(&mut T, Vec<u8>),
        quiet_block: fn(&T) -> bool,
    ) -> Result<Step<Result<T, Error>>, FrameError> {
        if self.skip != 0 {
            let n = usize::try_from(self.skip)
                .unwrap_or(usize::MAX)
                .min(input.len());
            if n == 0 {
                return if eof {
                    Err(FrameError::Incomplete)
                } else {
                    Ok(Step::Need)
                };
            }
            self.skip = self.skip.saturating_sub(n as u64);
            return Ok(Step::Skip(n));
        }
        if let Some((_, length)) = &self.pending {
            let remaining = length.saturating_sub(self.data.len());
            if remaining != 0 {
                let n = remaining.min(input.len());
                if n == 0 {
                    return if eof {
                        Err(FrameError::Incomplete)
                    } else {
                        Ok(Step::Need)
                    };
                }
                self.data
                    .extend_from_slice(input.get(..n).unwrap_or_default());
                return Ok(Step::Skip(n));
            }
            let Some(tail) = input.get(..2) else {
                return if eof {
                    Err(FrameError::Incomplete)
                } else {
                    Ok(Step::Need)
                };
            };
            let Some((mut item, _)) = self.pending.take() else {
                return Err(FrameError::Incomplete);
            };
            self.head_bytes = 0;
            self.quiet = tail != b"\r\n" && quiet_block(&item);
            let data = core::mem::take(&mut self.data);
            let item = if tail == b"\r\n" {
                attach(&mut item, data);
                Ok(item)
            } else {
                Err(Error::BadDataChunk)
            };
            return Ok(Step::Item(item, 2));
        }
        // Classification inspects at most 106 prefix bytes. Once get/gets
        // is known, only Lines' cursor scans the remaining input.
        if self.get_lines && !self.long_line && is_get_line(input) {
            self.long_line = true;
            self.lines = codec::Lines::new(MAX_GET_LINE - 2, codec::Ending::LfOrCrlf);
        }
        let step = self
            .lines
            .decode(input, eof)
            .unwrap_or_else(|never| match never {});
        match step {
            Step::Item(Ok(line), n) => {
                let line = if self.partial_line.is_empty() {
                    line
                } else {
                    let mut whole = core::mem::take(&mut self.partial_line);
                    whole.extend_from_slice(&line);
                    whole
                };
                self.long_line = false;
                self.lines = codec::Lines::new(MAX_LINE - 2, codec::Ending::LfOrCrlf);
                self.quiet = false;
                match head(&line) {
                    Ok((item, None)) => Ok(Step::Item(Ok(item), n)),
                    Ok((item, Some(length))) if length > self.limit => {
                        self.skip = (length as u64).saturating_add(2);
                        self.quiet = quiet_block(&item);
                        Ok(Step::Item(Err(Error::TooLarge(length)), n))
                    }
                    Ok((item, Some(length))) => {
                        self.pending = Some((item, length));
                        self.head_bytes = line.len();
                        Ok(Step::Skip(n))
                    }
                    Err(Fail { error, skip, quiet }) => {
                        self.skip = skip;
                        self.quiet = quiet;
                        Ok(Step::Item(Err(error), n))
                    }
                }
            }
            Step::Item(Err(codec::LineError::TooLong { .. }), _) => Err(FrameError::LineTooLong),
            Step::Item(Err(_), _) => Err(FrameError::Incomplete),
            Step::Skip(n) => Ok(Step::Skip(n)),
            Step::Need if self.long_line && input.len() >= MAX_LINE => {
                // A multiget may span several bounded input windows. Only
                // consumed bytes move into the line assembly.
                // Leave a final CR unread so Lines can recognize CRLF
                // when the LF arrives in the next input window.
                let remaining = MAX_GET_LINE
                    .saturating_sub(2)
                    .saturating_sub(self.partial_line.len());
                let n = input
                    .len()
                    .saturating_sub(usize::from(input.last() == Some(&b'\r')))
                    .min(remaining);
                let part = input.get(..n).ok_or(FrameError::LineTooLong)?;
                self.partial_line.extend_from_slice(part);
                self.lines =
                    codec::Lines::new(remaining.saturating_sub(n), codec::Ending::LfOrCrlf);
                Ok(Step::Skip(n))
            }
            Step::Need if eof && !self.partial_line.is_empty() => Err(FrameError::Incomplete),
            Step::Need => Ok(Step::Need),
            Step::End => Ok(Step::End),
        }
    }
}

fn quiet_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Store { noreply: true, .. } | Command::Cas { noreply: true, .. }
    )
}

/// Reads text commands using [`fictionet::stdlib::codec::Lines`] and counted bodies.
///
/// CRLF and bare LF end headers. Data blocks require trailing CRLF.
/// Ordinary lines use [`MAX_LINE`]; `get` and `gets` use [`MAX_GET_LINE`].
/// Input capacity stays at [`MAX_LINE`]; longer multigets assemble consumed
/// windows under [`MAX_GET_LINE`].
/// A parsed header supplies its body's exact count. The assembler consumes
/// that many bytes without interpreting their content. No session mode or
/// text/binary switch is inferred; choose [`codec::Frames<Packet>`](fictionet::stdlib::codec::Frames) for binary streams.
///
/// Bad lines and blocks are error items. Oversized blocks and malformed
/// meta storage blocks are skipped by their declared count, as memcached
/// does. Overlong lines and incomplete EOF end framing.
/// Held state is bounded by [`MAX_TEXT_HELD`].
///
/// [`Wire::parse`] requires exactly one complete command and also checks
/// that it can be written and read back unchanged.
pub struct Commands {
    inner: TextUnits<Command>,
}
impl core::fmt::Debug for Commands {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Commands")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}
impl Commands {
    /// Creates a reader accepting data blocks up to [`MAX_VALUE`].
    pub fn new() -> Self {
        Self::with_limit(MAX_VALUE)
    }
    /// Sets the data block limit, clamped to [`MAX_VALUE`].
    /// Larger blocks are refused from the header and skipped without storage.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            inner: TextUnits::new(true, limit),
        }
    }
    /// The maximum accepted data block length.
    pub fn limit(&self) -> usize {
        self.inner.limit
    }
    /// Whether an error item came from a classic command with `noreply`.
    /// Read this immediately after the error item; the flag persists while
    /// skipping its block or waiting for more input, until another header is decoded.
    pub fn quiet_error(&self) -> bool {
        self.inner.quiet
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
    const NAME: &'static str = "memcache text commands";
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
    fn held(&self) -> usize {
        self.inner.held()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, FrameError> {
        self.inner
            .decode(input, eof, parse_command, attach_command, quiet_command)
    }
}

/// Reads text replies using [`fictionet::stdlib::codec::Lines`] and counted bodies.
///
/// Headers accept CRLF or bare LF under [`MAX_LINE`]. VALUE and VA bodies
/// use the parsed count and require trailing CRLF. Invalid lines and data
/// blocks are error items; overlong lines and incomplete EOF are terminal.
/// Held state is bounded by [`MAX_TEXT_HELD`].
///
/// [`Wire::parse`] requires exactly one complete response and also checks
/// that it can be written and read back unchanged.
pub struct Responses {
    inner: TextUnits<Response>,
}
impl core::fmt::Debug for Responses {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responses")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}
impl Responses {
    /// Creates a reader accepting data blocks up to [`MAX_VALUE`].
    pub fn new() -> Self {
        Self::with_limit(MAX_VALUE)
    }
    /// Sets the data block limit, clamped to [`MAX_VALUE`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            inner: TextUnits::new(false, limit),
        }
    }
    /// The maximum accepted data block length.
    pub fn limit(&self) -> usize {
        self.inner.limit
    }
}
impl Default for Responses {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for Responses {
    type Item = Result<Response, Error>;
    type Error = FrameError;
    const NAME: &'static str = "memcache text replies";
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
    fn held(&self) -> usize {
        self.inner.held()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, FrameError> {
        self.inner
            .decode(input, eof, parse_response, attach_response, |_| false)
    }
}

/// Reads one text unit under its size limit and refuses trailing bytes.
fn exact_text<D, T>(mut decoder: D, mut bytes: &[u8]) -> Result<T, Error>
where
    D: Decode<Item = Result<T, Error>, Error = FrameError>,
{
    if bytes.len() > MAX_TEXT_UNIT {
        return Err(Error::LineTooLong);
    }
    loop {
        match decoder.decode(bytes, true).map_err(|e| match e {
            FrameError::LineTooLong => Error::LineTooLong,
            FrameError::Incomplete => Error::Incomplete,
        })? {
            Step::Item(Err(e), _) => return Err(e),
            Step::Item(Ok(item), used) if used == bytes.len() => return Ok(item),
            Step::Item(_, _) => return Err(Error::Trailing),
            Step::Skip(used) => match bytes.get(used..) {
                Some(rest) => bytes = rest,
                None => return Err(Error::Incomplete),
            },
            Step::Need | Step::End => return Err(Error::Incomplete),
        }
    }
}

fn exact_command(bytes: &[u8]) -> Result<Command, Error> {
    exact_text(Commands::new(), bytes)
}

impl Wire for Command {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one command under the named line and body limits.
    /// Incomplete input and trailing bytes are errors. Re-encodes the value
    /// and refuses commands that do not round trip.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let item = exact_command(bytes)?;
        item.to_bytes()?;
        Ok(item)
    }

    /// Appends one command and its counted block with CRLF endings.
    /// Refuses invalid keys, numbers, meta flags, or word counts, lines
    /// above [`MAX_LINE`] ([`MAX_GET_LINE`] for get), blocks above
    /// [`MAX_VALUE`], and values that would read back differently.
    /// Refused values leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let limit = if matches!(self, Command::Get { .. }) {
            MAX_GET_LINE
        } else {
            MAX_LINE
        };
        let mut line = Line::new(limit);
        let mut data = None;
        match self {
            Command::Store {
                verb,
                key,
                flags,
                exptime,
                data: d,
                noreply,
            } => {
                line.word(&[verb.name().as_bytes()])?;
                line.key(key)?;
                line.number(flags)?;
                line.number(exptime)?;
                line.number(d.len())?;
                line.noreply(*noreply)?;
                data = Some(d);
            }
            Command::Cas {
                key,
                flags,
                exptime,
                unique,
                data: d,
                noreply,
            } => {
                line.word(&[b"cas"])?;
                line.key(key)?;
                line.number(flags)?;
                line.number(exptime)?;
                line.number(d.len())?;
                line.number(unique)?;
                line.noreply(*noreply)?;
                data = Some(d);
            }
            Command::Get { keys, cas } => {
                line.word(&[if *cas { b"gets" } else { b"get" }])?;
                line.keys(keys)?;
            }
            Command::Gat { exptime, keys, cas } => {
                line.word(&[if *cas { b"gats" } else { b"gat" }])?;
                line.number(exptime)?;
                line.keys(keys)?;
            }
            Command::Delete { key, noreply } => {
                line.word(&[b"delete"])?;
                line.key(key)?;
                line.noreply(*noreply)?;
            }
            Command::Incr {
                key,
                delta,
                noreply,
            }
            | Command::Decr {
                key,
                delta,
                noreply,
            } => {
                line.word(&[if matches!(self, Command::Incr { .. }) {
                    b"incr"
                } else {
                    b"decr"
                }])?;
                line.key(key)?;
                line.number(delta)?;
                line.noreply(*noreply)?;
            }
            Command::Touch {
                key,
                exptime,
                noreply,
            } => {
                line.word(&[b"touch"])?;
                line.key(key)?;
                line.number(exptime)?;
                line.noreply(*noreply)?;
            }
            Command::Stats { args } => {
                line.word(&[b"stats"])?;
                for a in args {
                    line.token(a)?;
                }
            }
            Command::Version => line.word(&[b"version"])?,
            Command::Verbosity { level, noreply } => {
                line.word(&[b"verbosity"])?;
                line.number(level)?;
                line.noreply(*noreply)?;
            }
            Command::FlushAll { delay, noreply } => {
                line.word(&[b"flush_all"])?;
                if let Some(d) = delay {
                    line.number(d)?;
                }
                line.noreply(*noreply)?;
            }
            Command::Quit => line.word(&[b"quit"])?,
            Command::MetaGet { key, flags } => line.meta(b"mg", key, None, flags)?,
            Command::MetaSet {
                key,
                flags,
                data: d,
            } => {
                line.meta(b"ms", key, Some(d.len()), flags)?;
                data = Some(d);
            }
            Command::MetaDelete { key, flags } => line.meta(b"md", key, None, flags)?,
            Command::MetaArithmetic { key, flags } => line.meta(b"ma", key, None, flags)?,
            Command::MetaDebug { key, flags } => line.meta(b"me", key, None, flags)?,
            Command::MetaNoop => line.word(&[b"mn"])?,
        }
        let bytes = line.finish(data.map(|d| &d[..]))?;
        if exact_command(&bytes).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

fn exact_response(bytes: &[u8]) -> Result<Response, Error> {
    exact_text(Responses::new(), bytes)
}

impl Wire for Response {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one response under the named line and body limits.
    /// Incomplete input and trailing bytes are errors. Re-encodes the value
    /// and refuses responses that do not round trip.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let item = exact_response(bytes)?;
        item.to_bytes()?;
        Ok(item)
    }

    /// Appends one response and its counted block with CRLF endings.
    /// Refuses invalid keys, tokens, meta flags, CR or LF in line text,
    /// lines above [`MAX_LINE`], blocks above [`MAX_VALUE`], and values
    /// that would read back differently. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut line = Line::new(MAX_LINE);
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
            Response::Reset => b"RESET",
            _ => b"",
        };
        match self {
            Response::ClientError(m) => line.text(b"CLIENT_ERROR", m)?,
            Response::ServerError(m) => line.text(b"SERVER_ERROR", m)?,
            Response::Version(v) => line.text(b"VERSION", v)?,
            Response::Value {
                key,
                flags,
                cas,
                data: d,
            } => {
                line.word(&[b"VALUE"])?;
                line.key(key)?;
                line.number(flags)?;
                line.number(d.len())?;
                if let Some(c) = cas {
                    line.number(c)?;
                }
                data = Some(d);
            }
            Response::Stat { name, value } => {
                line.word(&[b"STAT"])?;
                line.token(name)?;
                line.rest(value, true)?;
            }
            Response::Number(n) => line.number(n)?,
            Response::Meta { status, flags } => {
                line.word(&[status.code().as_bytes()])?;
                line.meta_flags(flags)?;
            }
            Response::MetaValue { flags, data: d } => {
                line.word(&[b"VA"])?;
                line.number(d.len())?;
                line.meta_flags(flags)?;
                data = Some(d);
            }
            Response::MetaDebug { key, info } => {
                line.word(&[b"ME"])?;
                line.key(key)?;
                line.rest(info, false)?;
            }
            _ => line.word(&[fixed])?,
        }
        let bytes = line.finish(data.map(|d| &d[..]))?;
        if exact_response(&bytes).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// Reads binary packets without retaining input.
///
/// Capacity is [`BINARY_HEADER_LEN`] plus the body limit. A declared body
/// exceeding that limit is refused from the 24-byte header. All header
/// errors are terminal. Partial packets return
/// [`Step::Need`], so [`codec::Stream`] reports truncation at EOF.
impl Prefixed for Packet {
    type Item = Packet;
    type Error = Error;
    type Limit = usize;
    const NAME: &'static str = "memcache binary";

    #[inline]
    fn default_limit() -> Self::Limit {
        MAX_BODY
    }

    #[inline]
    fn normalize_limit(limit: Self::Limit) -> Self::Limit {
        limit.min(MAX_BODY)
    }

    #[inline]
    fn capacity(limit: &Self::Limit) -> usize {
        let limit = *limit;
        BINARY_HEADER_LEN.saturating_add(limit)
    }

    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        if let Some(&m) = input.first() {
            Magic::from_byte(m).ok_or(Error::Magic(m))?;
        }
        if let Some(header) = input.get(..BINARY_HEADER_LEN) {
            let key_len = usize::from(be16(header, 2).ok_or(Error::Incomplete)?);
            if key_len > MAX_KEY {
                return Err(Error::KeyLength(key_len));
            }
            let body =
                usize::try_from(be32(header, 8).ok_or(Error::Incomplete)?).unwrap_or(usize::MAX);
            if body > limit {
                return Err(Error::BodyLength(body));
            }
        }
        Packet::parse_prefix(input)
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one binary packet. Refuses invalid magic, keys above
    /// [`MAX_KEY`], bodies above [`MAX_BODY`], a key and extras that exceed
    /// the declared body, incomplete input, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Packet::parse_prefix(bytes)? {
            Some((packet, used)) if used == bytes.len() => Ok(packet),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Incomplete),
        }
    }
    /// Appends one binary packet. Refuses keys above [`MAX_KEY`], extras
    /// above 255 bytes, and bodies above [`MAX_BODY`]. Leaves `out`
    /// unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.key.len() > MAX_KEY {
            return Err(Error::KeyLength(self.key.len()));
        }
        let extras_len =
            u8::try_from(self.extras.len()).map_err(|_| Error::ExtrasLength(self.extras.len()))?;
        let body = self
            .extras
            .len()
            .checked_add(self.key.len())
            .and_then(|n| n.checked_add(self.value.len()))
            .ok_or(Error::BodyLength(usize::MAX))?;
        if body > MAX_BODY {
            return Err(Error::BodyLength(body));
        }
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use codec::{Lcg, Stream};
    use fictionet::stdlib::test_support::contract;

    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn commands(bytes: &[u8]) -> Vec<Result<Command, Error>> {
        decode_all(Commands::new, bytes).0
    }

    fn responses(bytes: &[u8]) -> Vec<Result<Response, Error>> {
        decode_all(Responses::new, bytes).0
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
            Command::Cas {
                key: key("a"),
                flags: 0,
                exptime: 0,
                unique: u64::MAX,
                data: b"v".to_vec(),
                noreply: false,
            },
            Command::Get {
                keys: vec![key("a"), key("b")],
                cas: false,
            },
            Command::Get {
                keys: vec![key("noreply")],
                cas: true,
            },
            Command::Gat {
                exptime: 10,
                keys: vec![key("a")],
                cas: false,
            },
            Command::Gat {
                exptime: i32::MIN,
                keys: vec![key("a")],
                cas: true,
            },
            Command::Delete {
                key: key("noreply"),
                noreply: false,
            },
            Command::Delete {
                key: key("noreply"),
                noreply: true,
            },
            Command::Incr {
                key: key("n"),
                delta: 5,
                noreply: false,
            },
            Command::Decr {
                key: key("n"),
                delta: u64::MAX,
                noreply: true,
            },
            Command::Touch {
                key: key("t"),
                exptime: 30,
                noreply: false,
            },
            Command::Stats { args: vec![] },
            Command::Stats {
                args: vec![key("cachedump"), key("1"), key("2")],
            },
            Command::Version,
            Command::Verbosity {
                level: 1,
                noreply: true,
            },
            Command::FlushAll {
                delay: None,
                noreply: false,
            },
            Command::FlushAll {
                delay: Some(5),
                noreply: true,
            },
            Command::Quit,
            Command::MetaGet {
                key: key("foo"),
                flags: vec![f(b'v', ""), f(b'T', "30"), f(b'O', "abc")],
            },
            Command::MetaSet {
                key: key("foo"),
                flags: vec![f(b'F', "1")],
                data: b"hi".to_vec(),
            },
            Command::MetaDelete {
                key: key("foo"),
                flags: vec![f(b'q', "")],
            },
            Command::MetaArithmetic {
                key: key("n"),
                flags: vec![f(b'D', "2"), f(b'M', "I")],
            },
            Command::MetaDebug {
                key: key("foo"),
                flags: vec![],
            },
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
            Response::Value {
                key: key("a"),
                flags: 3,
                cas: None,
                data: b"hello".to_vec(),
            },
            Response::Value {
                key: key("a"),
                flags: 0,
                cas: Some(77),
                data: vec![],
            },
            Response::Stat {
                name: key("pid"),
                value: key("1234"),
            },
            Response::Stat {
                name: key("version"),
                value: key("1.6 beta"),
            },
            Response::Version(b"1.6.21".to_vec()),
            Response::Number(0),
            Response::Number(u64::MAX),
            Response::Meta {
                status: MetaStatus::Header,
                flags: vec![MetaFlag::new(b'O', b"123")],
            },
            Response::Meta {
                status: MetaStatus::Miss,
                flags: vec![],
            },
            Response::Meta {
                status: MetaStatus::NotStored,
                flags: vec![],
            },
            Response::Meta {
                status: MetaStatus::Exists,
                flags: vec![],
            },
            Response::Meta {
                status: MetaStatus::NotFound,
                flags: vec![],
            },
            Response::Meta {
                status: MetaStatus::Noop,
                flags: vec![],
            },
            Response::MetaValue {
                flags: vec![MetaFlag::new(b't', b"-1")],
                data: b"hi".to_vec(),
            },
            Response::MetaDebug {
                key: key("foo"),
                info: b"exp=-1 la=3 cas=2 fetch=no cls=1 size=63".to_vec(),
            },
            Response::MetaDebug {
                key: key("foo"),
                info: vec![],
            },
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
            Command::Cas {
                key: key("k"),
                flags: 7,
                exptime: 0,
                unique: 12345,
                data: b"x".to_vec(),
                noreply: true
            }
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
        assert_eq!(
            one(b"get a b c\r\n"),
            Command::Get {
                keys: vec![key("a"), key("b"), key("c")],
                cas: false
            }
        );
        assert_eq!(
            one(b"gats 100 a\r\n"),
            Command::Gat {
                exptime: 100,
                keys: vec![key("a")],
                cas: true
            }
        );
        let got = responses(b"VALUE a 0 5 99\r\nhello\r\nVALUE c 2 0\r\n\r\nEND\r\n");
        assert_eq!(
            got,
            [
                Ok(Response::Value {
                    key: key("a"),
                    flags: 0,
                    cas: Some(99),
                    data: b"hello".to_vec()
                }),
                Ok(Response::Value {
                    key: key("c"),
                    flags: 2,
                    cas: None,
                    data: vec![]
                }),
                Ok(Response::End),
            ]
        );
    }

    #[test]
    fn other_commands_example() {
        assert_eq!(
            one(b"delete k\r\n"),
            Command::Delete {
                key: key("k"),
                noreply: false
            }
        );
        assert_eq!(
            one(b"delete k 0 noreply\r\n"),
            Command::Delete {
                key: key("k"),
                noreply: true
            }
        );
        assert_eq!(
            one(b"incr n 10\r\n"),
            Command::Incr {
                key: key("n"),
                delta: 10,
                noreply: false
            }
        );
        assert_eq!(
            one(b"decr n 3 noreply\r\n"),
            Command::Decr {
                key: key("n"),
                delta: 3,
                noreply: true
            }
        );
        assert_eq!(
            one(b"touch k -1\r\n"),
            Command::Touch {
                key: key("k"),
                exptime: -1,
                noreply: false
            }
        );
        assert_eq!(
            one(b"stats slabs\r\n"),
            Command::Stats {
                args: vec![key("slabs")]
            }
        );
        assert_eq!(one(b"version\n"), Command::Version);
        assert_eq!(
            one(b"verbosity 1\r\n"),
            Command::Verbosity {
                level: 1,
                noreply: false
            }
        );
        assert_eq!(
            one(b"flush_all noreply\r\n"),
            Command::FlushAll {
                delay: None,
                noreply: true
            }
        );
        assert_eq!(
            one(b"flush_all 10\r\n"),
            Command::FlushAll {
                delay: Some(10),
                noreply: false
            }
        );
        assert_eq!(one(b"quit\r\n"), Command::Quit);
        // Extra spaces count as one.
        assert_eq!(
            one(b"get  a   b \r\n"),
            Command::Get {
                keys: vec![key("a"), key("b")],
                cas: false
            }
        );
        // A key named noreply is a key when the command needs one.
        assert_eq!(
            one(b"delete noreply\r\n"),
            Command::Delete {
                key: key("noreply"),
                noreply: false
            }
        );
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
        assert_eq!(
            one(b"incr n 1 x\r\n"),
            Command::Incr {
                key: key("n"),
                delta: 1,
                noreply: false
            }
        );
        assert_eq!(
            one(b"touch k 1 noreply\r\n"),
            Command::Touch {
                key: key("k"),
                exptime: 1,
                noreply: true
            }
        );
        assert_eq!(
            one(b"flush_all 1 2\r\n"),
            Command::FlushAll {
                delay: Some(1),
                noreply: false
            }
        );
        assert_eq!(one(b"version now\r\n"), Command::Version);
        assert_eq!(one(b"quit 1\r\n"), Command::Quit);
        assert_eq!(one(b"mn x\r\n"), Command::MetaNoop);
        // Expiration times are 32-bit signed numbers.
        assert_eq!(
            one(b"gat -2147483648 k\r\n"),
            Command::Gat {
                exptime: i32::MIN,
                keys: vec![key("k")],
                cas: false
            }
        );
        assert_eq!(
            one(b"touch k 2147483647\r\n"),
            Command::Touch {
                key: key("k"),
                exptime: i32::MAX,
                noreply: false
            }
        );
        let got = responses(
            b"STAT pid 2233\r\nSTAT uptime 45\r\nEND\r\n42\r\nVERSION 1.6.21\r\nTOUCHED\r\n",
        );
        assert_eq!(
            got,
            [
                Ok(Response::Stat {
                    name: key("pid"),
                    value: key("2233")
                }),
                Ok(Response::Stat {
                    name: key("uptime"),
                    value: key("45")
                }),
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
        let Command::MetaGet { flags, .. } = &c else {
            panic!()
        };
        assert_eq!(meta_token(flags, b't'), Some(&b""[..]));
        assert_eq!(meta_token(flags, b'k'), None);
        assert!(c.is_quiet());
        assert_eq!(one(b"mn\r\n"), Command::MetaNoop);
        let got = responses(b"VA 2 t-1\r\nhi\r\nEN\r\nHD O123 k\r\nMN\r\nME foo exp=-1 la=3\r\n");
        assert_eq!(
            got,
            [
                Ok(Response::MetaValue {
                    flags: vec![MetaFlag::new(b't', b"-1")],
                    data: b"hi".to_vec()
                }),
                Ok(Response::Meta {
                    status: MetaStatus::Miss,
                    flags: vec![]
                }),
                Ok(Response::Meta {
                    status: MetaStatus::Header,
                    flags: vec![MetaFlag::new(b'O', b"123"), MetaFlag::new(b'k', b"")]
                }),
                Ok(Response::Meta {
                    status: MetaStatus::Noop,
                    flags: vec![]
                }),
                Ok(Response::MetaDebug {
                    key: key("foo"),
                    info: b"exp=-1 la=3".to_vec()
                }),
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
            assert_eq!(
                responses(&bytes),
                [Ok(r.clone())],
                "{}",
                String::from_utf8_lossy(&bytes)
            );
            stream.extend(bytes);
        }
        let got: Vec<_> = responses(&stream).into_iter().map(Result::unwrap).collect();
        assert_eq!(got, all);
    }

    #[test]
    fn every_truncated_prefix_waits() {
        for command in sample_commands() {
            let bytes = command.to_bytes().unwrap();
            contract::check_decode_with_alloc_limit(Commands::new, &bytes, 2 * MAX_LINE);
            for end in 1..bytes.len() {
                assert!(Command::parse(&bytes[..end]).is_err());
                assert_eq!(
                    decode_all(Commands::new, &bytes[..end]),
                    (vec![], Some(codec::Fail::Protocol(FrameError::Incomplete)),)
                );
            }
        }
        for response in sample_responses() {
            let bytes = response.to_bytes().unwrap();
            contract::check_decode_with_alloc_limit(Responses::new, &bytes, 2 * MAX_LINE);
            for end in 1..bytes.len() {
                assert!(Response::parse(&bytes[..end]).is_err());
                assert_eq!(
                    decode_all(Responses::new, &bytes[..end]),
                    (vec![], Some(codec::Fail::Protocol(FrameError::Incomplete)),)
                );
            }
        }
    }

    #[test]
    fn command_errors() {
        // Unknown commands, and an empty line.
        assert_eq!(
            commands(b"frob\r\n\r\nGET a\r\n"),
            [const { Err(Error::UnknownCommand) }; 3]
        );
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
            assert_eq!(
                commands(line),
                [Err(Error::UnknownCommand)],
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        // A bad delta or expiration time has its own reply.
        for line in [
            &b"incr k -1\r\n"[..],
            b"incr k 18446744073709551616\r\n",
            b"decr k x\r\n",
        ] {
            assert_eq!(
                commands(line),
                [Err(Error::Delta)],
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        for line in [
            &b"touch k x\r\n"[..],
            b"touch k 2147483648\r\n",
            b"gat x k\r\n",
            b"gats -2147483649 k\r\n",
        ] {
            assert_eq!(
                commands(line),
                [Err(Error::Exptime)],
                "{}",
                String::from_utf8_lossy(line)
            );
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
            assert_eq!(
                commands(line),
                [Err(Error::Format)],
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        let many = format!("mg k{}\r\n", " v".repeat(MAX_META_FLAGS + 1));
        assert_eq!(commands(many.as_bytes()), [Err(Error::Format)]);
        // The most flags, each a different one.
        let most = "mg k k s t c f v h u q x l O1 P L I N1 T1 R1 F1 C1 E1 J1 D1 MZ\r\n";
        assert_eq!(most.split(' ').count() - 2, MAX_META_FLAGS);
        assert!(
            commands(most.as_bytes())[0].is_ok(),
            "{:?}",
            commands(most.as_bytes())
        );
        // Bad keys.
        let long = format!("get {}\r\n", "k".repeat(MAX_KEY + 1));
        assert_eq!(commands(long.as_bytes()), [Err(Error::Key)]);
        assert!(commands(format!("get {}\r\n", "k".repeat(MAX_KEY)).as_bytes())[0].is_ok());
        assert_eq!(commands(b"get a\tb\r\n"), [Err(Error::Key)]);
        assert_eq!(commands(b"get a\rb\r\n"), [Err(Error::Key)]);
        // After a bad storage line, the data block is read as a command.
        assert_eq!(
            commands(b"set k x 0 4\r\nquit\r\n"),
            [Err(Error::Format), Ok(Command::Quit)]
        );
        // But an ms line whose length was read drops its block on a bad
        // flag, as memcached does, so the block is not run as a command.
        assert_eq!(
            commands(b"ms k 4 \x01\r\nquit\r\nmn\r\n"),
            [Err(Error::Format), Ok(Command::MetaNoop)]
        );
        let bad = b"ms k 4 v \x7f\r\nquit\r\nmn\r\n";
        assert_eq!(commands(bad), [Err(Error::Format), Ok(Command::MetaNoop)]);
        contract::check_decode_with_alloc_limit(Commands::new, bad, 2 * MAX_LINE);
        // Too many flags is refused before the length is read, so the
        // block is read as a command.
        let many = format!("ms k 4{}\r\nquit\r\n", " v".repeat(MAX_META_FLAGS + 1));
        assert_eq!(
            commands(many.as_bytes()),
            [Err(Error::Format), Ok(Command::Quit)]
        );
        // A data block not ended by CR LF is skipped, and reading goes on.
        assert_eq!(
            commands(b"set k 0 0 2\r\nabcdversion\r\n"),
            [Err(Error::BadDataChunk), Ok(Command::Version)]
        );
        assert_eq!(
            commands(b"set k 0 0 2\r\nab\n\nversion\r\n"),
            [Err(Error::BadDataChunk), Ok(Command::Version)]
        );
        // Each error has the reply memcached sends.
        assert_eq!(
            Error::UnknownCommand.reply().to_bytes().unwrap(),
            b"ERROR\r\n"
        );
        assert_eq!(Error::Unwritable.reply(), Response::Error);
        assert_eq!(Error::Unwritable.reply().to_bytes().unwrap(), b"ERROR\r\n");
        assert_eq!(
            Error::BadDataChunk.reply().to_bytes().unwrap(),
            b"CLIENT_ERROR bad data chunk\r\n"
        );
        assert_eq!(
            Error::Key.reply().to_bytes().unwrap(),
            b"CLIENT_ERROR bad command line format\r\n"
        );
        assert_eq!(
            Error::TooLarge(5).reply().to_bytes().unwrap(),
            b"SERVER_ERROR object too large for cache\r\n"
        );
        assert_eq!(
            Error::LineTooLong.reply().to_bytes().unwrap(),
            b"CLIENT_ERROR line too long\r\n"
        );
        assert_eq!(
            Error::Delta.reply().to_bytes().unwrap(),
            b"CLIENT_ERROR invalid numeric delta argument\r\n"
        );
        assert_eq!(
            Error::Exptime.reply().to_bytes().unwrap(),
            b"CLIENT_ERROR invalid exptime argument\r\n"
        );
        for e in [
            Error::LineTooLong,
            Error::UnknownCommand,
            Error::Format,
            Error::Delta,
            Error::Exptime,
            Error::Key,
            Error::TooLarge(1),
            Error::BadDataChunk,
            Error::Unwritable,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn too_large_values_are_skipped() {
        let n = MAX_VALUE + 1;
        let mut stream = format!("set k 0 0 {n}\r\n").into_bytes();
        stream.extend(vec![b'x'; n]);
        stream.extend_from_slice(b"\r\nversion\r\n");
        assert_eq!(
            commands(&stream),
            [Err(Error::TooLarge(n)), Ok(Command::Version)]
        );
        contract::check_decode_with_alloc_limit(Commands::new, &stream, 2 * MAX_LINE);
        contract::check_decode_with_held_limit(Commands::new, &stream, MAX_TEXT_HELD);
        let mut big = format!("VALUE k 0 {n}\r\n").into_bytes();
        big.extend(vec![0; n + 2]);
        big.extend_from_slice(b"END\r\n");
        assert_eq!(
            responses(&big),
            [Err(Error::TooLarge(n)), Ok(Response::End)]
        );
        // The largest block that fits is taken.
        let mut fits = format!("ms k {MAX_VALUE}\r\n").into_bytes();
        fits.extend(vec![b'y'; MAX_VALUE]);
        fits.extend_from_slice(b"\r\n");
        assert!(
            matches!(&commands(&fits)[..], [Ok(Command::MetaSet { data, .. })] if data.len() == MAX_VALUE)
        );
    }

    #[test]
    fn long_lines_break_the_stream() {
        let mut stream = Stream::new(Commands::new());
        assert_eq!(stream.push(&vec![b'a'; MAX_LINE - 1]), MAX_LINE - 1);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"a"), 1);
        assert_eq!(
            stream.next(),
            Some(Err(codec::Fail::Protocol(FrameError::LineTooLong)))
        );
        assert_eq!(stream.push(b"version\r\n"), 9);
        assert_eq!(stream.next(), None);
        assert_eq!(
            stream.failed(),
            Some(&codec::Fail::Protocol(FrameError::LineTooLong))
        );
        let line = [b"stats ".as_slice(), &vec![b'k'; MAX_LINE - 8], b"\r\n"].concat();
        assert!(commands(&line)[0].is_ok());
        let bare = [line[..line.len() - 2].to_vec(), b"k\n".to_vec()].concat();
        assert_eq!(
            decode_all(Commands::new, &bare).1,
            Some(codec::Fail::Protocol(FrameError::LineTooLong))
        );
        assert_eq!(
            decode_all(Responses::new, &vec![b'1'; MAX_LINE]).1,
            Some(codec::Fail::Protocol(FrameError::LineTooLong))
        );
    }

    #[test]
    fn response_errors() {
        for line in [
            &b"STORED now\r\n"[..],
            b"END \r\n",
            b"18446744073709551616\r\n",
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
            assert_eq!(
                responses(line),
                [Err(Error::Format)],
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        assert_eq!(responses(b"VALUE \x01 0 1\r\n"), [Err(Error::Key)]);
        assert_eq!(
            responses(b"BOGUS\r\nhd\r\n\r\n"),
            [const { Err(Error::UnknownCommand) }; 3]
        );
        assert_eq!(
            responses(b"VA 1\r\nxy\r\nEND\r\n"),
            [
                Err(Error::BadDataChunk),
                Err(Error::UnknownCommand),
                Ok(Response::End)
            ]
        );
        // Message text may be empty, and may hold spaces.
        assert_eq!(
            responses(b"SERVER_ERROR\r\n"),
            [Ok(Response::ServerError(vec![]))]
        );
        assert_eq!(
            responses(b"CLIENT_ERROR  two  spaces\r\n"),
            [Ok(Response::ClientError(b" two  spaces".to_vec()))]
        );
    }

    #[test]
    fn writers_refuse_what_readers_refuse() {
        let bad_key = Command::Get {
            keys: vec![key("a b")],
            cas: false,
        };
        assert_eq!(bad_key.to_bytes(), Err(Error::Key));
        assert_eq!(
            Command::Delete {
                key: vec![],
                noreply: false
            }
            .to_bytes(),
            Err(Error::Key)
        );
        assert_eq!(
            Command::Touch {
                key: vec![b'k'; MAX_KEY + 1],
                exptime: 0,
                noreply: false
            }
            .to_bytes(),
            Err(Error::Key)
        );
        assert_eq!(
            Command::Get {
                keys: vec![],
                cas: false
            }
            .to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Command::Stats { args: vec![vec![]] }.to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Command::MetaGet {
                key: key("k"),
                flags: vec![MetaFlag::new(b' ', b"")]
            }
            .to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Command::MetaGet {
                key: key("k"),
                flags: vec![MetaFlag::new(b'v', b"a b")]
            }
            .to_bytes(),
            Err(Error::Format)
        );
        let flags = vec![MetaFlag::new(b'v', b""); MAX_META_FLAGS + 1];
        assert_eq!(
            Command::MetaGet {
                key: key("k"),
                flags: flags.clone()
            }
            .to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Response::Meta {
                status: MetaStatus::Header,
                flags
            }
            .to_bytes(),
            Err(Error::Format)
        );
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
        assert_eq!(
            Response::MetaValue {
                flags: vec![],
                data: big
            }
            .to_bytes(),
            Err(Error::TooLarge(MAX_VALUE + 1))
        );
        let keys = vec![key("kkkkkkkk"); MAX_LINE / 9 + 1];
        assert_eq!(
            Command::Gat {
                exptime: 0,
                keys,
                cas: false
            }
            .to_bytes(),
            Err(Error::LineTooLong)
        );
        assert_eq!(
            Response::ClientError(b"a\nb".to_vec()).to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Response::Version(b"\r".to_vec()).to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Response::Stat {
                name: key("a b"),
                value: vec![]
            }
            .to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Response::MetaDebug {
                key: key("k"),
                info: b"\n".to_vec()
            }
            .to_bytes(),
            Err(Error::Format)
        );
        assert_eq!(
            Response::ServerError(vec![b'x'; MAX_LINE]).to_bytes(),
            Err(Error::LineTooLong)
        );
    }

    // From the binary protocol wiki: a get of "Hello" and its response.
    const GET_REQUEST: [u8; 29] = [
        0x80, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, b'H', b'e', b'l', b'l', b'o',
    ];
    const GET_RESPONSE: [u8; 33] = [
        0x81, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, b'W', b'o',
        b'r', b'l', b'd',
    ];

    #[test]
    fn binary_get_example() {
        let req = Packet::parse(&GET_REQUEST).unwrap();
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
        assert_eq!(Packet::parse(&GET_RESPONSE).unwrap(), resp);
        for n in 0..GET_REQUEST.len() {
            assert_eq!(
                Frames::<Packet>::new().decode(&GET_REQUEST[..n], false),
                Ok(Step::Need),
                "{n} bytes"
            );
        }
    }

    #[test]
    fn binary_extras() {
        let s = StoreExtras {
            flags: 0xdeadbeef,
            expiration: 0xe10,
        };
        assert_eq!(
            s.to_bytes().unwrap(),
            [0xde, 0xad, 0xbe, 0xef, 0, 0, 0x0e, 0x10]
        );
        assert_eq!(StoreExtras::parse(&s.to_bytes().unwrap()), Ok(s));
        assert_eq!(
            StoreExtras::parse(&[0; 7]),
            Err(Error::Extras {
                expected: 8,
                actual: 7
            })
        );
        let c = CounterExtras {
            delta: 1,
            initial: 0,
            expiration: 0xe10,
        };
        assert_eq!(c.to_bytes().unwrap()[7], 1);
        assert_eq!(CounterExtras::parse(&c.to_bytes().unwrap()), Ok(c));
        assert_eq!(
            CounterExtras::parse(&[0; 21]),
            Err(Error::Extras {
                expected: 20,
                actual: 21
            })
        );
        for code in 0..=u16::MAX {
            assert_eq!(Status::from_code(code).code(), code);
        }
    }

    #[test]
    fn binary_errors() {
        assert_eq!(Packet::parse(&[0x82]), Err(Error::Magic(0x82)));
        let mut h = GET_REQUEST;
        h[2..4].copy_from_slice(&251u16.to_be_bytes());
        h[8..12].copy_from_slice(&300u32.to_be_bytes());
        assert_eq!(Packet::parse(&h), Err(Error::KeyLength(251)));
        let mut h = GET_REQUEST;
        h[4] = 1; // extras and key past the body
        assert_eq!(Packet::parse(&h), Err(Error::BodyLength(5)));
        let mut h = GET_REQUEST;
        h[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(Packet::parse(&h), Err(Error::BodyLength(u32::MAX as usize)));
        let mut p = Packet::parse(&GET_REQUEST).unwrap();
        p.extras = vec![0; 256];
        assert_eq!(p.to_bytes(), Err(Error::ExtrasLength(256)));
        p.extras = vec![];
        p.key = vec![0; MAX_KEY + 1];
        assert_eq!(p.to_bytes(), Err(Error::KeyLength(MAX_KEY + 1)));
        p.key = vec![];
        p.value = vec![0; MAX_BODY + 1];
        assert_eq!(p.to_bytes(), Err(Error::BodyLength(MAX_BODY + 1)));
        p.value = vec![0; MAX_BODY];
        assert!(Packet::parse(&p.to_bytes().unwrap()).is_ok());
        for e in [
            Error::Magic(0),
            Error::KeyLength(1),
            Error::ExtrasLength(1),
            Error::BodyLength(1),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn binary_decoder() {
        let bytes = [GET_REQUEST.as_slice(), GET_RESPONSE.as_slice()].concat();
        let (packets, failure) = decode_all(Frames::<Packet>::new, &bytes);
        assert_eq!(failure, None);
        assert_eq!(
            packets.iter().map(|p| p.magic).collect::<Vec<_>>(),
            [Magic::Request, Magic::Response]
        );
        contract::check_decode_with_alloc_limit(
            Frames::<Packet>::new,
            &bytes,
            2 * MAX_BINARY_BUFFERED,
        );
        let mut stream = Stream::new(Frames::<Packet>::new());
        assert_eq!(stream.push(&[0]), 1);
        assert_eq!(
            stream.next(),
            Some(Err(codec::Fail::Protocol(Error::Magic(0))))
        );
        assert_eq!(stream.push(&GET_REQUEST), GET_REQUEST.len());
        assert!(stream.next().is_none());
        assert_eq!(
            stream.failed(),
            Some(&codec::Fail::Protocol(Error::Magic(0)))
        );
    }

    #[test]
    fn udp_frames() {
        let f = UdpFrame::parse(b"\x00\x07\x00\x00\x00\x01\x00\x00get a\r\n").unwrap();
        assert_eq!(
            f,
            UdpFrame {
                request_id: 7,
                sequence: 0,
                total: 1,
                payload: b"get a\r\n".to_vec()
            }
        );
        assert_eq!(
            f.to_bytes().unwrap(),
            b"\x00\x07\x00\x00\x00\x01\x00\x00get a\r\n"
        );
        for n in 0..UDP_HEADER_LEN {
            assert_eq!(UdpFrame::parse(&[0; 8][..n]), Err(Error::Short(n)));
        }
        assert_eq!(
            UdpFrame::parse(&[0, 0, 0, 0, 0, 1, 0, 1]),
            Err(Error::Reserved(1))
        );
        assert_eq!(
            UdpFrame::parse(&[0, 0, 0, 1, 0, 1, 0, 0]),
            Err(Error::Sequence {
                sequence: 1,
                total: 1
            })
        );
        assert_eq!(
            UdpFrame::parse(&[0; 8]),
            Err(Error::Sequence {
                sequence: 0,
                total: 0
            })
        );
        let mut long = vec![0, 0, 0, 0, 0, 1, 0, 0];
        long.extend(vec![0; MAX_UDP_PAYLOAD + 1]);
        assert_eq!(
            UdpFrame::parse(&long),
            Err(Error::PayloadTooLong(MAX_UDP_PAYLOAD + 1))
        );
        let bad = UdpFrame {
            request_id: 0,
            sequence: 2,
            total: 2,
            payload: vec![],
        };
        assert_eq!(
            bad.to_bytes(),
            Err(Error::Sequence {
                sequence: 2,
                total: 2
            })
        );
        let bad = UdpFrame {
            request_id: 0,
            sequence: 0,
            total: 1,
            payload: vec![0; MAX_UDP_PAYLOAD + 1],
        };
        assert_eq!(
            bad.to_bytes(),
            Err(Error::PayloadTooLong(MAX_UDP_PAYLOAD + 1))
        );
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
            Error::Short(1),
            Error::Reserved(1),
            Error::Sequence {
                sequence: 1,
                total: 0,
            },
            Error::PayloadTooLong(1),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn decoder_takes_many_small_commands_in_linear_time() {
        use fictionet::stdlib::test_support::assert_linear;
        let one = b"set k 0 0 1\r\nx\r\nget k\r\n";
        assert_linear("memcache commands", 6_250, |n| {
            let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * n).collect();
            let got = commands(&stream);
            assert_eq!(got.len(), 2 * n);
            assert!(got.iter().all(Result::is_ok));
        });
        // Shared schedules include single-byte pushes and must stay linear.
        let line = [vec![b' '; MAX_LINE - 3], b"\r\n".to_vec()].concat();
        assert_linear("memcache long lines", 5, |n| {
            contract::check_decode_with_alloc_limit(Commands::new, &line.repeat(n), 2 * MAX_LINE);
        });
    }

    fn fuzz_buffer(rng: &mut Lcg, pieces: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..rng.index(7) {
            let piece = &pieces[rng.index(pieces.len())];
            match rng.index(4) {
                0 => bytes.extend_from_slice(&piece[..rng.index(piece.len() + 1)]),
                1 => bytes.extend(rng.bytes(100)),
                _ => bytes.extend_from_slice(piece),
            }
        }
        for _ in 0..rng.index(4) {
            mutate(rng, &mut bytes);
        }
        bytes
    }

    #[test]
    fn fuzz_text_decoders() {
        let mut pieces: Vec<Vec<u8>> = sample_commands()
            .iter()
            .map(|c| c.to_bytes().unwrap())
            .collect();
        pieces.extend(sample_responses().iter().map(|r| r.to_bytes().unwrap()));
        pieces.push(b"set k 0 0 99999999\r\n".to_vec());
        pieces.push(b"\r\n".to_vec());
        let mut rng = Lcg::new(1);
        for _ in 0..4000 {
            let bytes = fuzz_buffer(&mut rng, &pieces);
            contract::check_decode_with_alloc_limit(Commands::new, &bytes, 2 * MAX_LINE);
            contract::check_decode_with_alloc_limit(Responses::new, &bytes, 2 * MAX_LINE);
            contract::check_wire::<Command>(&bytes);
            contract::check_wire::<Response>(&bytes);
            for command in commands(&bytes).iter().flatten() {
                contract::check_wire_value(command);
                let bytes = command.to_bytes().unwrap();
                assert_eq!(
                    decode_all(Commands::new, &bytes),
                    (vec![Ok(command.clone())], None)
                );
            }
            for response in responses(&bytes).iter().flatten() {
                contract::check_wire_value(response);
                let bytes = response.to_bytes().unwrap();
                assert_eq!(
                    decode_all(Responses::new, &bytes),
                    (vec![Ok(response.clone())], None)
                );
            }
        }
    }

    #[test]
    fn fuzz_binary_and_udp() {
        let mut set = Packet::parse(&GET_REQUEST).unwrap();
        set.opcode = opcode::SET;
        set.extras = StoreExtras {
            flags: 1,
            expiration: 2,
        }
        .to_bytes()
        .unwrap();
        set.value = b"value".to_vec();
        let pieces = vec![
            GET_REQUEST.to_vec(),
            GET_RESPONSE.to_vec(),
            set.to_bytes().unwrap(),
            b"\x00\x01\x00\x00\x00\x01\x00\x00x".to_vec(),
        ];
        let mut rng = Lcg::new(2);
        for _ in 0..4000 {
            let bytes = fuzz_buffer(&mut rng, &pieces);
            contract::check_decode_with_alloc_limit(
                Frames::<Packet>::new,
                &bytes,
                2 * MAX_BINARY_BUFFERED,
            );
            contract::check_wire::<Packet>(&bytes);
            contract::check_wire::<UdpFrame>(&bytes);
            contract::check_wire::<StoreExtras>(&bytes);
            contract::check_wire::<CounterExtras>(&bytes);
            for packet in decode_all(Frames::<Packet>::new, &bytes).0 {
                contract::check_wire_value(&packet);
                contract::check_wire::<StoreExtras>(&packet.extras);
                contract::check_wire::<CounterExtras>(&packet.extras);
            }
        }
    }

    // Findings from review, one test each.

    #[test]
    fn decoders_hold_a_bounded_number_of_bytes() {
        let flood = vec![b'a'; 4 * MAX_LINE];
        contract::check_decode_with_alloc_limit(Commands::new, &flood, 2 * MAX_LINE);
        contract::check_decode_with_alloc_limit(Responses::new, &flood, 2 * MAX_LINE);
        let mut stream = Stream::new(Commands::new());
        let bytes = b"get k\r\n".repeat(MAX_LINE);
        assert_eq!(stream.push(&bytes), MAX_LINE);
        assert_eq!(stream.push(&bytes), 0);
        assert_eq!(commands(&bytes).len(), MAX_LINE);
        contract::check_decode_with_alloc_limit(
            Frames::<Packet>::new,
            &[0; 4096],
            2 * MAX_BINARY_BUFFERED,
        );
        let mut packet = Packet::parse(&GET_REQUEST).unwrap();
        packet.value = vec![0; MAX_BODY - packet.key.len()];
        let bytes = packet.to_bytes().unwrap();
        assert_eq!(
            decode_all(Frames::<Packet>::new, &bytes),
            (vec![packet], None)
        );
        contract::check_decode_with_alloc_limit(
            Frames::<Packet>::new,
            &bytes,
            2 * MAX_BINARY_BUFFERED,
        );
    }

    /// The loop of the module's example: replies for every command, until
    /// the stream breaks.
    fn serve(input: &[u8]) -> (Vec<u8>, usize) {
        let mut decoder = Stream::new(Commands::new());
        let mut out = Vec::new();
        let mut turns = 0;
        let mut rest = input;
        while !rest.is_empty() {
            let n = decoder.push(rest);
            rest = &rest[n..];
            while let Some(command) = decoder.next() {
                turns += 1;
                assert!(turns < 1000, "the loop does not end");
                let replies = match command {
                    Err(_) => return (out, turns),
                    Ok(command) => match command {
                        Err(_) if decoder.decoder().quiet_error() => vec![],
                        Ok(Command::Get { .. }) => vec![Response::End],
                        Ok(_) => vec![Response::Error],
                        Err(e) => vec![e.reply()],
                    },
                };
                for reply in replies {
                    out.extend(reply.to_bytes().unwrap());
                }
            }
        }
        (out, turns)
    }

    #[test]
    fn the_example_loop_ends_on_a_fatal_error() {
        let mut input = b"get a\r\n".to_vec();
        input.extend(vec![b'x'; MAX_LINE]);
        let (out, turns) = serve(&input);
        assert_eq!(out, b"END\r\n");
        assert_eq!(turns, 2);
    }

    #[test]
    fn writers_check_length_before_copying() {
        let big = vec![b'x'; 16 * MAX_LINE];
        let mut line = Line::new(MAX_LINE);
        line.word(&[b"SERVER_ERROR"]).unwrap();
        assert_eq!(line.rest(&big, false), Err(Error::LineTooLong));
        assert_eq!(line.word(&[&big]), Err(Error::LineTooLong));
        assert_eq!(line.token(&big), Err(Error::LineTooLong));
        // Nothing of the long text was copied.
        assert!(line.buf.capacity() < MAX_LINE, "{}", line.buf.capacity());
        assert_eq!(line.buf, b"SERVER_ERROR");
        // The same through the public writers.
        assert_eq!(
            Response::ServerError(big.clone()).to_bytes(),
            Err(Error::LineTooLong)
        );
        assert_eq!(
            Command::Stats {
                args: vec![big.clone()]
            }
            .to_bytes(),
            Err(Error::LineTooLong)
        );
        assert_eq!(
            Response::Stat {
                name: key("a"),
                value: big.clone()
            }
            .to_bytes(),
            Err(Error::LineTooLong)
        );
        let flags = vec![MetaFlag::new(b'O', &big)];
        assert_eq!(
            Response::Meta {
                status: MetaStatus::Header,
                flags
            }
            .to_bytes(),
            Err(Error::LineTooLong)
        );
        // A line that just fits is written.
        let fits = vec![b'x'; MAX_LINE - 2 - b"SERVER_ERROR ".len()];
        assert_eq!(
            Response::ServerError(fits).to_bytes().unwrap().len(),
            MAX_LINE
        );
    }

    #[test]
    fn sasl_status_codes_are_memcacheds() {
        // A SASL auth response asking for another step, as memcached sends it.
        let continue_auth = [
            0x81,
            opcode::SASL_AUTH,
            0,
            0,
            0,
            0,
            0x00,
            0x21,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let p = Packet::parse(&continue_auth).unwrap();
        assert_eq!(Status::from_code(p.status), Status::AuthContinue);
        assert_eq!(Status::from_code(0x20), Status::AuthError);
        assert_eq!(Status::AuthError.code(), 0x20);
        assert_eq!(
            p.reply(Status::AuthError).to_bytes().unwrap()[6..8],
            [0x00, 0x20]
        );
        assert_eq!(Status::from_code(0x08), Status::Other(0x08));
        assert_eq!(Status::from_code(0x09), Status::Other(0x09));
    }

    #[test]
    fn meta_flags_are_checked_as_memcached_checks_them() {
        for line in [
            &b"mg k v v\r\n"[..],
            b"ma n Dnope\r\n",
            b"ma n D-1\r\n",
            b"ma n Jx\r\n",
            b"mg k T\r\n",
            b"mg k Tx\r\n",
            b"mg k T2147483648\r\n",
            b"mg k N1x\r\n",
            b"md k C-1\r\n",
            b"ms k 1 F4294967296\r\nx\r\n",
            b"ma n MZ\r\n",
            b"ma n MII\r\n",
            b"mg k M\r\n",
            b"mg k Z\r\n",
            b"mg k W\r\n",
            b"mg k Oabcdefghijklmnopqrstuvwxyz123456\r\n",
            b"mg a b\r\n",
            b"mg ==== b\r\n",
            b"mg A=== b\r\n",
        ] {
            assert_eq!(
                commands(line),
                [Err(Error::Format)],
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        // ms drops its block after a bad flag.
        assert_eq!(
            commands(b"ms k 1 MZ\r\nx\r\nmn\r\n"),
            [Err(Error::Format), Ok(Command::MetaNoop)]
        );
        assert_eq!(
            commands(b"ms k 1 T1 T2\r\nx\r\nmn\r\n"),
            [Err(Error::Format), Ok(Command::MetaNoop)]
        );
        // What memcached takes.
        for line in [
            &b"mg k v T-1 N30 R5\r\n"[..],
            b"ma n D18446744073709551615 J0 M+ N0\r\n",
            b"ma n MD\r\n",
            b"ms k 1 MA F4294967295 C1 E2 I\r\nx\r\n",
            b"md k q x C5\r\n",
            b"mg k Oabcdefghijklmnopqrstuvwxyz12345 MQ\r\n",
            b"mg Zm9v b v\r\n",
            b"mg Zg== b\r\n",
            b"me k Z Z\r\n",
        ] {
            assert!(
                matches!(&commands(line)[..], [Ok(_)]),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        // Writers refuse the same.
        let f = |flag, token: &str| MetaFlag::new(flag, token.as_bytes());
        for (verb, flags) in [
            ("mg", vec![f(b'v', ""), f(b'v', "")]),
            ("ma", vec![f(b'D', "nope")]),
            ("ma", vec![f(b'M', "Z")]),
            ("mg", vec![f(b'Z', "")]),
            ("mg", vec![f(b'O', &"o".repeat(MAX_OPAQUE))]),
            ("mg", vec![f(b'b', "")]),
        ] {
            let c = match verb {
                "mg" => Command::MetaGet {
                    key: key("k"),
                    flags,
                },
                _ => Command::MetaArithmetic {
                    key: key("k"),
                    flags,
                },
            };
            assert_eq!(c.to_bytes(), Err(Error::Format), "{c:?}");
        }
        let ms = Command::MetaSet {
            key: key("k"),
            flags: vec![f(b'M', "Z")],
            data: b"x".to_vec(),
        };
        assert_eq!(ms.to_bytes(), Err(Error::Format));
    }

    #[test]
    fn noreply_errors_are_quiet() {
        let errors = |bytes: &[u8]| {
            let mut d = Stream::new(Commands::new());
            let mut out = Vec::new();
            let mut rest = bytes;
            while !rest.is_empty() {
                let n = d.push(rest);
                rest = &rest[n..];
                while let Some(r) = d.next() {
                    out.push(
                        r.unwrap()
                            .map(|_| ())
                            .map_err(|e| (e, d.decoder().quiet_error())),
                    );
                }
            }
            out
        };
        let n = MAX_VALUE + 1;
        let mut big = format!("set k 0 0 {n} noreply\r\n").into_bytes();
        big.extend(vec![b'x'; n]);
        big.extend_from_slice(b"\r\nmn\r\n");
        assert_eq!(errors(&big), [Err((Error::TooLarge(n), true)), Ok(())]);
        assert_eq!(
            errors(b"set k 0 0 1 noreply\r\nxy\r\n")[0],
            Err((Error::BadDataChunk, true))
        );
        assert_eq!(
            errors(b"cas k 0 0 1 1 noreply\r\nxy\r\n")[0],
            Err((Error::BadDataChunk, true))
        );
        assert_eq!(
            errors(b"set k x 0 1 noreply\r\n"),
            [Err((Error::Format, true))]
        );
        assert_eq!(errors(b"incr k x noreply\r\n"), [Err((Error::Delta, true))]);
        assert_eq!(
            errors(b"touch k x noreply\r\n"),
            [Err((Error::Exptime, true))]
        );
        assert_eq!(
            errors(b"delete k 5 noreply\r\n"),
            [Err((Error::Format, true))]
        );
        assert_eq!(
            errors(b"flush_all x noreply\r\n"),
            [Err((Error::Format, true))]
        );
        // Without noreply, a word count memcached answers with ERROR, a
        // word other than noreply, and every meta error are not quiet.
        assert_eq!(
            errors(b"set k 0 0 1\r\nxy\r\n")[0],
            Err((Error::BadDataChunk, false))
        );
        assert_eq!(
            errors(b"set k x 0 1 nope\r\n"),
            [Err((Error::Format, false))]
        );
        assert_eq!(
            errors(b"set k 0 noreply\r\n"),
            [Err((Error::UnknownCommand, false))]
        );
        assert_eq!(
            errors(b"ms k 1 q\r\nxy\r\n")[0],
            Err((Error::BadDataChunk, false))
        );
        assert_eq!(errors(b"mg k q v v\r\n"), [Err((Error::Format, false))]);
        // A command after a quiet error is not quiet.
        let mut d = Stream::new(Commands::new());
        assert_eq!(
            d.push(b"incr k x noreply\r\nmn\r\n"),
            b"incr k x noreply\r\nmn\r\n".len()
        );
        assert!(d.next().unwrap().unwrap().is_err() && d.decoder().quiet_error());
        assert!(d.next().unwrap().unwrap().is_ok() && !d.decoder().quiet_error());
    }

    #[test]
    fn a_bad_value_line_drops_its_block() {
        assert_eq!(
            responses(b"VALUE k 0 8 nope\r\nSTORED\r\n\r\nEND\r\n"),
            [Err(Error::Format), Ok(Response::End)]
        );
        assert_eq!(
            responses(b"VALUE k x 3\r\nEND\r\nEND\r\n"),
            [Err(Error::Format), Ok(Response::End)]
        );
        assert_eq!(
            responses(b"VALUE \x01 0 3\r\nEND\r\nEND\r\n"),
            [Err(Error::Key), Ok(Response::End)]
        );
        assert_eq!(
            responses(b"VA 3 \x01\r\nEND\r\nEND\r\n"),
            [Err(Error::Format), Ok(Response::End)]
        );
        contract::check_decode_with_alloc_limit(
            Responses::new,
            b"VALUE k 0 8 nope\r\nSTORED\r\n\r\nEND\r\n",
            2 * MAX_LINE,
        );
    }

    #[test]
    fn a_decremented_number_may_be_padded() {
        assert_eq!(
            responses(b"12 \r\n9   \r\n"),
            [Ok(Response::Number(12)), Ok(Response::Number(9))]
        );
        assert_eq!(responses(b"12 x\r\n"), [Err(Error::Format)]);
        assert_eq!(responses(b"12  3\r\n"), [Err(Error::Format)]);
    }

    #[test]
    fn stats_reset_has_its_reply() {
        assert_eq!(responses(b"RESET\r\n"), [Ok(Response::Reset)]);
        assert_eq!(Response::Reset.to_bytes().unwrap(), b"RESET\r\n");
        assert_eq!(responses(b"RESET now\r\n"), [Err(Error::Format)]);
        assert_eq!(
            one(b"stats reset\r\n"),
            Command::Stats {
                args: vec![key("reset")]
            }
        );
    }

    #[test]
    fn long_multigets_are_taken() {
        // 33 keys of the longest length: over MAX_LINE.
        let keys: Vec<Vec<u8>> = (0..33u8).map(|i| vec![b'a' + i % 26; MAX_KEY]).collect();
        let get = Command::Get {
            keys: keys.clone(),
            cas: false,
        };
        let bytes = get.to_bytes().unwrap();
        assert!(bytes.len() > MAX_LINE);
        assert_eq!(one(&bytes), get);
        let gets = Command::Get { keys, cas: true };
        let mut stream = format!("{}gets", " ".repeat(100)).into_bytes();
        stream.extend_from_slice(&gets.to_bytes().unwrap()[4..]);
        stream.extend_from_slice(b"mn\r\n");
        assert_eq!(commands(&stream), [Ok(gets.clone()), Ok(Command::MetaNoop)]);
        contract::check_decode_with_alloc_limit(Commands::new, &stream, 2 * MAX_LINE);
        // Other long lines still break the stream, as does a get after more
        // than 100 spaces, and one past MAX_GET_LINE.
        let mut far = format!("{}get", " ".repeat(101)).into_bytes();
        far.extend_from_slice(&bytes[3..]);
        assert_eq!(
            decode_all(Commands::new, &far).1,
            Some(codec::Fail::Protocol(FrameError::LineTooLong))
        );
        let mut gat = b"gat 0".to_vec();
        gat.extend_from_slice(&bytes[3..]);
        assert_eq!(
            decode_all(Commands::new, &gat).1,
            Some(codec::Fail::Protocol(FrameError::LineTooLong))
        );
        let huge = vec![vec![b'k'; MAX_KEY]; MAX_GET_LINE / MAX_KEY];
        assert_eq!(
            Command::Get {
                keys: huge.clone(),
                cas: false
            }
            .to_bytes(),
            Err(Error::LineTooLong)
        );
        let mut line = b"get".to_vec();
        for k in &huge {
            line.push(b' ');
            line.extend_from_slice(k);
        }
        line.extend_from_slice(b"\r\n");
        assert_eq!(
            decode_all(Commands::new, &line).1,
            Some(codec::Fail::Protocol(FrameError::LineTooLong))
        );
        // Replies are held to MAX_LINE.
        assert_eq!(
            decode_all(Responses::new, &bytes).1,
            Some(codec::Fail::Protocol(FrameError::LineTooLong))
        );
    }
}
