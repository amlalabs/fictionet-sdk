//! TFTP: reading and writing packets, negotiating options, and serving one
//! read transfer, with no I/O.
//!
//! TFTP (the Trivial File Transfer Protocol) moves files over UDP with
//! almost no machinery. Network boot uses it to fetch kernels and boot
//! images, and switches, routers and phones use it to load firmware and
//! configuration. A client sends a read request (RRQ) or write request
//! (WRQ) to port 69. The file then moves in numbered DATA blocks, each
//! answered by an ACK, until a block shorter than the block size ends it.
//! Either side can stop the transfer with an ERROR packet. This module
//! follows RFC 1350 for the base protocol, RFC 2347 for options and the
//! OACK packet, RFC 2348 for the `blksize` option, and RFC 2349 for the
//! `timeout` and `tsize` options.
//!
//! Nothing here reads a socket or a clock. A world that plays a TFTP
//! server reads each datagram itself, gives its bytes to
//! [`Packet::parse`], decides which file a request names, and sends back
//! the bytes of [`Packet::write`]. [`negotiate`] answers a request's
//! options, and a [`ReadTransfer`] works out which packet to send next
//! for one read. When to resend a packet, and how many times, is up to
//! the caller: on a timeout it sends [`ReadTransfer::current`] again.
//! Read netascii DATA bodies with [`Stream<NetasciiBytes>`](fictionet::stdlib::codec::Stream)
//! to retain a CR split across packets.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Strings, option lists and packets all have limits, given below
//! as constants, and the writers refuse values above those limits.
//! A request may name each option only once (RFC 2347), so the readers
//! and writers both refuse repeated option names.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::tftp::{negotiate, Event, Packet, ReadTransfer, MAX_BLOCK_SIZE};
//!
//! // A read request for boot.img, asking for 1024-byte blocks and the size.
//! let rrq = b"\x00\x01boot.img\x00octet\x00blksize\x001024\x00tsize\x000\x00";
//! let Packet::ReadRequest(request) = Packet::parse(rrq).unwrap() else { panic!("not a read request") };
//! assert_eq!(request.filename, "boot.img");
//!
//! let file = vec![0xab; 1500];
//! let agreed = negotiate(&request.options, Some(file.len() as u64), MAX_BLOCK_SIZE);
//! assert_eq!(agreed.block_size, 1024);
//! let mut transfer = ReadTransfer::negotiated(file, &agreed);
//!
//! // The server answers the options first, with an OACK.
//! let oack = transfer.current().unwrap();
//! assert_eq!(oack.to_bytes().unwrap(), b"\x00\x06blksize\x001024\x00tsize\x001500\x00");
//!
//! // ACK 0 accepts the options, and block 1 follows.
//! let Event::Send(Packet::Data { block: 1, data }) = transfer.on_packet(&Packet::parse(&[0, 4, 0, 0]).unwrap())
//! else {
//!     panic!("expected block 1")
//! };
//! assert_eq!(data.len(), 1024);
//! // A second ACK 0 is a duplicate. It sends nothing.
//! assert_eq!(transfer.on_packet(&Packet::Ack { block: 0 }), Event::Duplicate);
//!
//! // Block 2 holds the last 476 bytes, and its ACK ends the transfer.
//! let Event::Send(Packet::Data { block: 2, data }) = transfer.on_packet(&Packet::Ack { block: 1 }) else {
//!     panic!("expected block 2")
//! };
//! assert_eq!(data.len(), 476);
//! assert_eq!(transfer.on_packet(&Packet::Ack { block: 2 }), Event::Complete);
//! assert!(transfer.is_complete());
//! assert_eq!(transfer.current(), None);
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The UDP port TFTP servers listen on for requests. The transfer itself
/// runs from a port of the server's choosing.
pub const PORT: u16 = 69;
/// The block size when no `blksize` option is agreed (RFC 1350).
pub const DEFAULT_BLOCK_SIZE: u16 = 512;
/// The smallest block size the `blksize` option allows (RFC 2348).
pub const MIN_BLOCK_SIZE: u16 = 8;
/// The largest block size the `blksize` option allows (RFC 2348).
pub const MAX_BLOCK_SIZE: u16 = 65464;
/// The smallest `timeout` option, in seconds (RFC 2349).
pub const MIN_TIMEOUT: u8 = 1;
/// The largest `timeout` option, in seconds (RFC 2349).
pub const MAX_TIMEOUT: u8 = 255;
/// The longest packet: a DATA header and the largest block.
pub const MAX_PACKET: usize = 4 + MAX_BLOCK_SIZE as usize;
/// The longest read or write request, options included (RFC 2347).
pub const MAX_REQUEST: usize = 512;
/// The longest string (a filename, mode, option name, option value or
/// error message), in bytes, not counting its closing NUL.
pub const MAX_STRING: usize = 512;
/// The most options a request or OACK may carry. Each option takes at
/// least two bytes, so a request within [`MAX_REQUEST`] bytes never
/// reaches this limit: RFC 2347 bounds requests only by their size, and
/// the limit binds only OACKs.
pub const MAX_OPTIONS: usize = MAX_REQUEST / 2;
/// The longest decimal number an option value may hold: `u64::MAX` has
/// 20 digits.
pub const MAX_DIGITS: usize = 20;

/// Opcodes, the first two bytes of every packet.
pub mod opcode {
    /// Read request.
    pub const RRQ: u16 = 1;
    /// Write request.
    pub const WRQ: u16 = 2;
    /// A block of file data.
    pub const DATA: u16 = 3;
    /// An acknowledgment of one block.
    pub const ACK: u16 = 4;
    /// An error, which ends the transfer.
    pub const ERROR: u16 = 5;
    /// An option acknowledgment (RFC 2347).
    pub const OACK: u16 = 6;
}

/// Option names this module negotiates. Names are matched without regard
/// to case.
pub mod option {
    /// The block size in bytes (RFC 2348).
    pub const BLKSIZE: &str = "blksize";
    /// The retransmission timeout in seconds (RFC 2349).
    pub const TIMEOUT: &str = "timeout";
    /// The transfer size in bytes (RFC 2349).
    pub const TSIZE: &str = "tsize";
}

/// How the file's bytes are carried. Modes are matched without regard to
/// case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Text with CR LF line endings and CR written as CR NUL. See
    /// [`NetasciiByte`] and [`NetasciiBytes`].
    NetAscii,
    /// Bytes as they are.
    Octet,
    /// Mail to a user, which RFC 1350 calls obsolete. It is read and
    /// written, but its meaning is left to the world. RFC 1350 allows it
    /// only in a write request, so a world answers a read request in
    /// mail mode with an ERROR packet ([`ErrorCode::IllegalOperation`]).
    Mail,
}

impl Mode {
    /// The mode's name as written in a request.
    pub fn name(self) -> &'static str {
        match self {
            Mode::NetAscii => "netascii",
            Mode::Octet => "octet",
            Mode::Mail => "mail",
        }
    }

    /// The mode a request names, in any case, or `None` for an unknown
    /// one.
    pub fn from_name(name: &str) -> Option<Mode> {
        [Mode::NetAscii, Mode::Octet, Mode::Mail].into_iter().find(|m| m.name().eq_ignore_ascii_case(name))
    }
}

/// One option: a name and its value, both strings, as RFC 2347 carries
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TftpOption {
    /// The option's name, such as `blksize`. Kept in the case it came in.
    pub name: String,
    /// The option's value, such as `1024`.
    pub value: String,
}

impl TftpOption {
    /// An option from a name and a value.
    pub fn new(name: &str, value: &str) -> TftpOption {
        TftpOption { name: name.to_string(), value: value.to_string() }
    }
}

/// The body of a read or write request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The file the client asks for, as the client wrote it. The world
    /// decides what it means.
    pub filename: String,
    /// How the file's bytes are carried.
    pub mode: Mode,
    /// The options the client asks for, in order (RFC 2347).
    pub options: Vec<TftpOption>,
}

/// The error codes of an ERROR packet. Two codes are equal when their
/// numbers are, so `Other(1)` equals `FileNotFound`.
#[derive(Clone, Copy, Debug)]
pub enum ErrorCode {
    /// Not defined; the message says what went wrong.
    NotDefined,
    /// File not found.
    FileNotFound,
    /// Access violation.
    AccessViolation,
    /// Disk full or allocation exceeded.
    DiskFull,
    /// Illegal TFTP operation.
    IllegalOperation,
    /// Unknown transfer ID: a packet came from the wrong port.
    UnknownTransferId,
    /// File already exists.
    FileExists,
    /// No such user.
    NoSuchUser,
    /// The options could not be agreed (RFC 2347).
    OptionNegotiation,
    /// Any other code. [`ErrorCode::from_code`] gives it only for codes
    /// above 8.
    Other(u16),
}

impl PartialEq for ErrorCode {
    fn eq(&self, other: &ErrorCode) -> bool {
        self.code() == other.code()
    }
}

impl Eq for ErrorCode {}

impl ErrorCode {
    /// The code's number.
    pub fn code(self) -> u16 {
        match self {
            ErrorCode::NotDefined => 0,
            ErrorCode::FileNotFound => 1,
            ErrorCode::AccessViolation => 2,
            ErrorCode::DiskFull => 3,
            ErrorCode::IllegalOperation => 4,
            ErrorCode::UnknownTransferId => 5,
            ErrorCode::FileExists => 6,
            ErrorCode::NoSuchUser => 7,
            ErrorCode::OptionNegotiation => 8,
            ErrorCode::Other(c) => c,
        }
    }

    /// The code a number stands for. Every number has one, and
    /// `from_code(c).code() == c`.
    pub fn from_code(code: u16) -> ErrorCode {
        match code {
            0 => ErrorCode::NotDefined,
            1 => ErrorCode::FileNotFound,
            2 => ErrorCode::AccessViolation,
            3 => ErrorCode::DiskFull,
            4 => ErrorCode::IllegalOperation,
            5 => ErrorCode::UnknownTransferId,
            6 => ErrorCode::FileExists,
            7 => ErrorCode::NoSuchUser,
            8 => ErrorCode::OptionNegotiation,
            c => ErrorCode::Other(c),
        }
    }

    /// The message RFC 1350 and RFC 2347 give for the code, for an ERROR
    /// packet that has nothing more specific to say.
    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::NotDefined | ErrorCode::Other(_) => "Not defined",
            ErrorCode::FileNotFound => "File not found",
            ErrorCode::AccessViolation => "Access violation",
            ErrorCode::DiskFull => "Disk full or allocation exceeded",
            ErrorCode::IllegalOperation => "Illegal TFTP operation",
            ErrorCode::UnknownTransferId => "Unknown transfer ID",
            ErrorCode::FileExists => "File already exists",
            ErrorCode::NoSuchUser => "No such user",
            ErrorCode::OptionNegotiation => "Option negotiation failed",
        }
    }
}

/// One TFTP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// RRQ: the client wants to read a file.
    ReadRequest(Request),
    /// WRQ: the client wants to write a file.
    WriteRequest(Request),
    /// DATA: one block of the file. A block shorter than the agreed block
    /// size is the last one.
    Data {
        /// The block number, starting at 1 and wrapping after 65535.
        block: u16,
        /// The block's bytes, at most [`MAX_BLOCK_SIZE`].
        data: Vec<u8>,
    },
    /// ACK: the block with this number arrived. ACK 0 accepts an OACK.
    Ack {
        /// The block number acknowledged.
        block: u16,
    },
    /// ERROR: the transfer is over.
    Error {
        /// What went wrong.
        code: ErrorCode,
        /// A message for a person to read.
        message: String,
    },
    /// OACK: the options the server accepted, with their agreed values
    /// (RFC 2347).
    OptionAck {
        /// The accepted options, in order.
        options: Vec<TftpOption>,
    },
}

/// Why bytes are not a TFTP packet. A server answers most of these with
/// an ERROR packet with [`ErrorCode::IllegalOperation`], or drops the
/// datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The packet ends before its fixed fields do.
    Short,
    /// The packet is longer than [`MAX_PACKET`]. It holds the length.
    TooLong(usize),
    /// A read or write request is longer than [`MAX_REQUEST`]. It holds
    /// the length.
    RequestTooLong(usize),
    /// The opcode is not one of the six. It holds the opcode.
    UnknownOpcode(u16),
    /// A string has no closing NUL.
    Unterminated,
    /// A string is longer than [`MAX_STRING`].
    StringTooLong,
    /// A string is not valid UTF-8.
    NotUtf8,
    /// A request names a mode other than netascii, octet or mail.
    UnknownMode,
    /// A request or OACK carries more than [`MAX_OPTIONS`] options.
    TooManyOptions,
    /// An option name has no value after it.
    MissingValue,
    /// A request or OACK names the same option twice, in any case.
    DuplicateOption,
    /// An ACK or ERROR packet has bytes after its last field.
    TrailingBytes,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Short => write!(f, "packet ends before its fixed fields"),
            Error::TooLong(n) => write!(f, "packet of {n} bytes, longer than {MAX_PACKET}"),
            Error::RequestTooLong(n) => write!(f, "request of {n} bytes, longer than {MAX_REQUEST}"),
            Error::UnknownOpcode(op) => write!(f, "unknown opcode {op}"),
            Error::Unterminated => write!(f, "string with no closing NUL"),
            Error::StringTooLong => write!(f, "string longer than {MAX_STRING} bytes"),
            Error::NotUtf8 => write!(f, "string is not UTF-8"),
            Error::UnknownMode => write!(f, "mode is not netascii, octet or mail"),
            Error::TooManyOptions => write!(f, "more than {MAX_OPTIONS} options"),
            Error::MissingValue => write!(f, "option name with no value"),
            Error::DuplicateOption => write!(f, "option named twice"),
            Error::TrailingBytes => write!(f, "bytes after the packet's last field"),
        }
    }
}

impl std::error::Error for Error {}

impl Packet {
    /// An ERROR packet with the code's standard message.
    pub fn error(code: ErrorCode) -> Packet {
        Packet::Error { code, message: code.message().to_string() }
    }

    /// The packet's opcode.
    pub fn opcode(&self) -> u16 {
        match self {
            Packet::ReadRequest(_) => opcode::RRQ,
            Packet::WriteRequest(_) => opcode::WRQ,
            Packet::Data { .. } => opcode::DATA,
            Packet::Ack { .. } => opcode::ACK,
            Packet::Error { .. } => opcode::ERROR,
            Packet::OptionAck { .. } => opcode::OACK,
        }
    }
}

/// Reads an option value as a decimal number: digits only, no sign or
/// spaces, at most [`MAX_DIGITS`] of them, and no larger than `u64::MAX`.
pub fn parse_number(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > MAX_DIGITS {
        return None;
    }
    s.bytes().try_fold(0u64, |n, c| {
        if c.is_ascii_digit() { n.checked_mul(10)?.checked_add(u64::from(c - b'0')) } else { None }
    })
}

/// What [`negotiate`] agreed for one transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// The block size: [`DEFAULT_BLOCK_SIZE`] unless a `blksize` option
    /// was accepted.
    pub block_size: u16,
    /// The timeout in seconds the client asked for, if it was in range.
    /// The caller uses it to time its resends.
    pub timeout: Option<u8>,
    /// The transfer size, if the client sent `tsize`.
    pub transfer_size: Option<u64>,
    /// The options to send back in an OACK, in the order the client sent
    /// them. Empty when none were accepted; the server then sends no OACK.
    pub oack: Vec<TftpOption>,
}

/// Answers a request's options as a server, following RFC 2347 to 2349.
///
/// - `blksize` is accepted if it is a number from [`MIN_BLOCK_SIZE`] to
///   [`MAX_BLOCK_SIZE`], and lowered to `max_block_size` (itself clamped
///   to that range) if it asks for more.
/// - `timeout` is accepted if it is a number from [`MIN_TIMEOUT`] to
///   [`MAX_TIMEOUT`], and echoed.
/// - `tsize` is answered with `size` when that is given (the file's size,
///   for a read), and otherwise echoed (the client's size, for a write).
///
/// Unknown options, values that are not numbers, values out of range and
/// repeats of an option already seen (whether or not the first was
/// accepted) are left out, as RFC 2347 lets a server do. Option names in
/// the OACK are written in lower case.
///
/// For a read whose size the server does not know, leave `tsize` out of
/// `options`: echoing the client's `0` would claim an empty file.
pub fn negotiate(options: &[TftpOption], size: Option<u64>, max_block_size: u16) -> Negotiated {
    let max = max_block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
    let mut n = Negotiated { block_size: DEFAULT_BLOCK_SIZE, timeout: None, transfer_size: None, oack: Vec::new() };
    let (mut blksize, mut timeout, mut tsize) = (false, false, false);
    for o in options.iter().take(MAX_OPTIONS) {
        let value = parse_number(&o.value);
        if o.name.eq_ignore_ascii_case(option::BLKSIZE) {
            if std::mem::replace(&mut blksize, true) {
                continue;
            }
            if let Some(v) = value
                && (u64::from(MIN_BLOCK_SIZE)..=u64::from(MAX_BLOCK_SIZE)).contains(&v)
            {
                // Both are at most MAX_BLOCK_SIZE, which fits in a u16.
                n.block_size = u16::try_from(v.min(u64::from(max))).unwrap_or(max);
                n.oack.push(TftpOption::new(option::BLKSIZE, &n.block_size.to_string()));
            }
        } else if o.name.eq_ignore_ascii_case(option::TIMEOUT) {
            if std::mem::replace(&mut timeout, true) {
                continue;
            }
            if let Some(t) = value.and_then(|v| u8::try_from(v).ok())
                && t >= MIN_TIMEOUT
            {
                n.timeout = Some(t);
                n.oack.push(TftpOption::new(option::TIMEOUT, &t.to_string()));
            }
        } else if o.name.eq_ignore_ascii_case(option::TSIZE) {
            if std::mem::replace(&mut tsize, true) {
                continue;
            }
            if let Some(v) = value {
                let total = size.unwrap_or(v);
                n.transfer_size = Some(total);
                n.oack.push(TftpOption::new(option::TSIZE, &total.to_string()));
            }
        }
    }
    n
}

/// What a [`ReadTransfer`] makes of a packet from the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The ACK was for the packet in flight. Send this packet next.
    Send(Packet),
    /// An ACK for the packet before the one in flight, or for the last
    /// block again after the transfer finished. Send nothing: answering
    /// duplicates would double every later packet (the "Sorcerer's
    /// Apprentice" bug that RFC 1123 section 4.2.3.1 describes).
    Duplicate,
    /// The ACK for the last block came. The transfer is over.
    Complete,
    /// The client sent an ERROR packet. The transfer is over.
    Aborted(ErrorCode),
    /// A packet that does not belong in this transfer: an ACK for some
    /// other block, a packet that is not an ACK or ERROR, or anything
    /// after the transfer ended. Send nothing. A server may answer a
    /// stray packet with an ERROR packet if it likes.
    Unexpected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Running,
    Complete,
    Aborted,
}

/// The server's side of one read transfer: the file's bytes, the agreed
/// block size, and which packet is in flight.
///
/// The transfer starts with an OACK if options were agreed, and with
/// DATA block 1 if not. Each ACK for the packet in flight moves it on to
/// the next block, until the ACK for the last block, which is shorter
/// than the block size (and empty if the file's size is a multiple of
/// it). Block numbers wrap from 65535 to 0, as most servers do, so files
/// of more than 65535 blocks can be sent.
///
/// For netascii mode, encode each [`NetasciiByte`] first, and use
/// their length as the `tsize`.
#[derive(Clone, Debug)]
pub struct ReadTransfer {
    data: Vec<u8>,
    block_size: u16,
    oack: Option<Vec<TftpOption>>,
    /// The number of the block in flight, counting from 1 without
    /// wrapping. 0 is the OACK.
    in_flight: u64,
    blocks: u64,
    state: State,
}

impl ReadTransfer {
    /// A transfer with no options: it starts with block 1, in blocks of
    /// [`DEFAULT_BLOCK_SIZE`] bytes, the only size a client expects
    /// without an OACK (RFC 1350). Another block size takes an agreed
    /// `blksize` option; use [`ReadTransfer::negotiated`] for that.
    pub fn new(data: Vec<u8>) -> ReadTransfer {
        ReadTransfer::start(data, DEFAULT_BLOCK_SIZE, None)
    }

    /// A transfer with what [`negotiate`] agreed. It starts with an OACK
    /// when there are options to acknowledge, and with block 1 if not.
    ///
    /// The OACK keeps the options from `agreed.oack` that fit, with
    /// strings clipped and repeats left out. A `blksize`
    /// option whose value is not a number from [`MIN_BLOCK_SIZE`] to
    /// [`MAX_BLOCK_SIZE`] is left out too. The block size is the one the
    /// OACK's `blksize` gives the client, or [`DEFAULT_BLOCK_SIZE`] when
    /// it has none, so `agreed.block_size` is not used and the client and
    /// server always agree on it.
    pub fn negotiated(data: Vec<u8>, agreed: &Negotiated) -> ReadTransfer {
        let mut block_size = DEFAULT_BLOCK_SIZE;
        let mut oack = Vec::new();
        for (name, value) in clipped_options(&agreed.oack, 2, MAX_PACKET) {
            if name.eq_ignore_ascii_case(option::BLKSIZE) {
                match parse_number(value).and_then(|v| u16::try_from(v).ok()) {
                    Some(v) if (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&v) => block_size = v,
                    _ => continue,
                }
            }
            oack.push(TftpOption::new(name, value));
        }
        let oack = if oack.is_empty() { None } else { Some(oack) };
        ReadTransfer::start(data, block_size, oack)
    }

    fn start(data: Vec<u8>, block_size: u16, oack: Option<Vec<TftpOption>>) -> ReadTransfer {
        let block_size = block_size.clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE);
        // A usize always fits in a u64 on the targets Rust supports.
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let blocks = (len / u64::from(block_size)).saturating_add(1);
        let in_flight = if oack.is_some() { 0 } else { 1 };
        ReadTransfer { data, block_size, oack, in_flight, blocks, state: State::Running }
    }

    /// The packet in flight: the one to send first, and to send again
    /// when the caller's timer runs out. `None` once the transfer is over.
    pub fn current(&self) -> Option<Packet> {
        if self.state != State::Running {
            return None;
        }
        if self.in_flight == 0 {
            return Some(Packet::OptionAck { options: self.oack.clone().unwrap_or_default() });
        }
        let size = usize::from(self.block_size);
        let start = usize::try_from(self.in_flight - 1).ok().and_then(|k| k.checked_mul(size)).unwrap_or(usize::MAX);
        let end = start.saturating_add(size).min(self.data.len());
        let data = self.data.get(start..end).unwrap_or(&[]).to_vec();
        Some(Packet::Data { block: wire(self.in_flight), data })
    }

    /// Takes an ACK from the client and says what to do next.
    pub fn on_ack(&mut self, block: u16) -> Event {
        match self.state {
            State::Aborted => Event::Unexpected,
            State::Complete if block == wire(self.blocks) => Event::Duplicate,
            State::Complete => Event::Unexpected,
            State::Running if block == wire(self.in_flight) => {
                if self.in_flight >= self.blocks {
                    self.state = State::Complete;
                    Event::Complete
                } else {
                    self.in_flight += 1;
                    self.current().map_or(Event::Unexpected, Event::Send)
                }
            }
            State::Running if self.in_flight > 0 && block == wire(self.in_flight - 1) => Event::Duplicate,
            State::Running => Event::Unexpected,
        }
    }

    /// Takes any packet from the client: an ACK moves the transfer on, an
    /// ERROR ends it, and anything else is [`Event::Unexpected`].
    pub fn on_packet(&mut self, packet: &Packet) -> Event {
        match packet {
            Packet::Ack { block } => self.on_ack(*block),
            Packet::Error { code, .. } if self.state == State::Running => {
                self.state = State::Aborted;
                Event::Aborted(*code)
            }
            _ => Event::Unexpected,
        }
    }

    /// The block size in use.
    pub fn block_size(&self) -> u16 {
        self.block_size
    }

    /// How many DATA blocks the file takes, counting the short last one.
    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    /// The block in flight, counting from 1 without wrapping. 0 means the
    /// OACK is in flight. After the transfer completes it is the last
    /// block.
    pub fn in_flight(&self) -> u64 {
        self.in_flight
    }

    /// Whether the client acknowledged the last block.
    pub fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    /// Whether the client ended the transfer with an ERROR packet.
    pub fn is_aborted(&self) -> bool {
        self.state == State::Aborted
    }
}

/// One decoded text byte. LF writes as CR LF and CR writes as CR NUL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetasciiByte(
    /// The decoded byte. LF and CR each write as a two-byte pair.
    pub u8,
);

impl Wire for NetasciiByte {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one netascii byte. Refuses empty input or more than one character.
    /// A lone CR is kept, as are bytes other than CR LF and CR NUL pairs.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match b {
            [b'\r', b'\n'] => Ok(Self(b'\n')),
            [b'\r', 0] => Ok(Self(b'\r')),
            [byte] => Ok(Self(*byte)),
            [] => Err(Error::Short),
            _ => Err(Error::TrailingBytes),
        }
    }

    /// Appends one encoded character. Refuses no values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        match self.0 {
            b'\n' => dst.extend_from_slice(b"\r\n"),
            b'\r' => dst.extend_from_slice(b"\r\0"),
            byte => dst.push(byte),
        }
        Ok(())
    }
}

/// Reads netascii characters across DATA blocks.
/// Use [`Stream<NetasciiBytes>`](fictionet::stdlib::codec::Stream) to retain a split CR pair.
/// Its input buffer holds at most two bytes, and it holds no private bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetasciiBytes;

impl Decode for NetasciiBytes {
    type Item = NetasciiByte;
    type Error = Error;
    const NAME: &'static str = "netascii";

    /// Two bytes suffice for one encoded character.
    fn capacity(&self) -> usize { 2 }

    /// No input bytes are held outside the driver.
    fn held(&self) -> usize { 0 }

    /// Reads one character. A final lone CR is kept; no byte value is refused.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let Some(&first) = input.first() else {
            return Ok(if eof { Step::End } else { Step::Need });
        };
        if first == b'\r' {
            match input.get(1) {
                Some(b'\n') => return Ok(Step::Item(NetasciiByte(b'\n'), 2)),
                Some(0) => return Ok(Step::Item(NetasciiByte(b'\r'), 2)),
                None if !eof => return Ok(Step::Need),
                _ => {}
            }
        }
        Ok(Step::Item(NetasciiByte(first), 1))
    }
}

/// The wire block number for block `k`, counting from 1 without
/// wrapping.
fn wire(k: u64) -> u16 {
    (k & 0xffff) as u16
}

/// Reads the NUL-terminated string at `*pos` and moves past it.
fn take_str<'a>(b: &'a [u8], pos: &mut usize) -> Result<&'a str, Error> {
    let rest = b.get(*pos..).unwrap_or(&[]);
    let end = rest.iter().position(|&c| c == 0).ok_or(Error::Unterminated)?;
    if end > MAX_STRING {
        return Err(Error::StringTooLong);
    }
    let s = std::str::from_utf8(&rest[..end]).map_err(|_| Error::NotUtf8)?;
    *pos += end + 1;
    Ok(s)
}

/// Reads name and value pairs from `pos` to the end of `b`.
fn take_options(b: &[u8], mut pos: usize) -> Result<Vec<TftpOption>, Error> {
    let mut options = Vec::new();
    let mut names = std::collections::HashSet::new();
    while pos < b.len() {
        if options.len() >= MAX_OPTIONS {
            return Err(Error::TooManyOptions);
        }
        let name = take_str(b, &mut pos)?;
        if pos >= b.len() {
            return Err(Error::MissingValue);
        }
        let value = take_str(b, &mut pos)?;
        if !names.insert(name.to_ascii_lowercase()) {
            return Err(Error::DuplicateOption);
        }
        options.push(TftpOption::new(name, value));
    }
    Ok(options)
}

/// `s` cut at its first NUL and to [`MAX_STRING`] bytes, at a character
/// boundary.
fn clipped_string(s: &str) -> &str {
    clipped_utf8(s.split('\0').next().unwrap_or(""), MAX_STRING)
}

/// `s` cut to at most `max` bytes, at a character boundary.
fn clipped_utf8(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), Error> {
    if s.len() > MAX_STRING || s.contains('\0') {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    Ok(())
}

/// Options retained by the transfer constructor after `start` bytes: the first
/// [`MAX_OPTIONS`], clipped, leaving out repeats of a name already
/// written, and stopping at the first that would go past `limit` bytes.
fn clipped_options(options: &[TftpOption], start: usize, limit: usize) -> Vec<(&str, &str)> {
    let mut written: Vec<(&str, &str)> = Vec::new();
    let mut len = start;
    let mut names = std::collections::HashSet::new();
    for o in options.iter().take(MAX_OPTIONS) {
        let (name, value) = (clipped_string(&o.name), clipped_string(&o.value));
        if !names.insert(name.to_ascii_lowercase()) {
            continue;
        }
        let next = len + name.len() + value.len() + 2;
        if next > limit {
            break;
        }
        len = next;
        written.push((name, value));
    }
    written
}

fn put_options(out: &mut Vec<u8>, options: &[TftpOption], limit: usize) -> Result<(), Error> {
    if options.len() > MAX_OPTIONS {
        return Err(Error::Unwritable);
    }
    let mut names = std::collections::HashSet::new();
    for option in options {
        if option.name.len() > MAX_STRING || option.value.len() > MAX_STRING {
            return Err(Error::Unwritable);
        }
        if !names.insert(option.name.to_ascii_lowercase()) {
            return Err(Error::Unwritable);
        }
        put_str(out, &option.name)?;
        put_str(out, &option.value)?;
        if out.len() > limit {
            return Err(Error::Unwritable);
        }
    }
    if out.len() > limit {
        return Err(Error::Unwritable);
    }
    Ok(())
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one packet: the whole of a UDP datagram's payload.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Packet, Error> {
        if b.len() > MAX_PACKET {
            return Err(Error::TooLong(b.len()));
        }
        if b.len() < 2 {
            return Err(Error::Short);
        }
        let op = be16(b, 0);
        match op {
            opcode::RRQ | opcode::WRQ => {
                if b.len() > MAX_REQUEST {
                    return Err(Error::RequestTooLong(b.len()));
                }
                let mut pos = 2;
                let filename = take_str(b, &mut pos)?.to_string();
                let mode = Mode::from_name(take_str(b, &mut pos)?).ok_or(Error::UnknownMode)?;
                let options = take_options(b, pos)?;
                let request = Request { filename, mode, options };
                Ok(if op == opcode::RRQ { Packet::ReadRequest(request) } else { Packet::WriteRequest(request) })
            }
            opcode::DATA => {
                if b.len() < 4 {
                    return Err(Error::Short);
                }
                Ok(Packet::Data { block: be16(b, 2), data: b[4..].to_vec() })
            }
            opcode::ACK => match b.len() {
                0..4 => Err(Error::Short),
                4 => Ok(Packet::Ack { block: be16(b, 2) }),
                _ => Err(Error::TrailingBytes),
            },
            opcode::ERROR => {
                if b.len() < 4 {
                    return Err(Error::Short);
                }
                let mut pos = 4;
                let message = take_str(b, &mut pos)?.to_string();
                if pos != b.len() {
                    return Err(Error::TrailingBytes);
                }
                Ok(Packet::Error { code: ErrorCode::from_code(be16(b, 2)), message })
            }
            opcode::OACK => Ok(Packet::OptionAck { options: take_options(b, 2)? }),
            other => Err(Error::UnknownOpcode(other)),
        }
    }

    /// Appends the complete packet. Refuses NULs or oversized strings, repeated options,
    /// requests above [`MAX_REQUEST`] and DATA above [`MAX_BLOCK_SIZE`].
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::new();
        match self {
            Packet::ReadRequest(r) | Packet::WriteRequest(r) => {
                let op = if matches!(self, Packet::ReadRequest(_)) { opcode::RRQ } else { opcode::WRQ };
                out.extend_from_slice(&op.to_be_bytes());
                let mode = r.mode.name();
                put_str(&mut out, &r.filename)?;
                put_str(&mut out, mode)?;
                put_options(&mut out, &r.options, MAX_REQUEST)?;
            }
            Packet::Data { block, data } => {
                if data.len() > usize::from(MAX_BLOCK_SIZE) {
                    return Err(Error::Unwritable);
                }
                out.reserve(4 + data.len());
                out.extend_from_slice(&opcode::DATA.to_be_bytes());
                out.extend_from_slice(&block.to_be_bytes());
                out.extend_from_slice(data);
            }
            Packet::Ack { block } => {
                out.extend_from_slice(&opcode::ACK.to_be_bytes());
                out.extend_from_slice(&block.to_be_bytes());
            }
            Packet::Error { code, message } => {
                out.extend_from_slice(&opcode::ERROR.to_be_bytes());
                out.extend_from_slice(&code.code().to_be_bytes());
                put_str(&mut out, message)?;
            }
            Packet::OptionAck { options } => {
                out.extend_from_slice(&opcode::OACK.to_be_bytes());
                put_options(&mut out, options, MAX_PACKET)?;
            }
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Lcg, contract, test_support::mutate};

    fn rrq_example() -> Vec<u8> {
        b"\x00\x01boot.img\x00octet\x00blksize\x001024\x00tsize\x000\x00".to_vec()
    }

    // RFC 1350 section 5: an RRQ for a file in netascii mode.
    #[test]
    fn rfc1350_read_request() {
        let p = Packet::parse(b"\x00\x01foo\x00netascii\x00").unwrap();
        assert_eq!(p, Packet::ReadRequest(Request { filename: "foo".into(), mode: Mode::NetAscii, options: vec![] }));
        assert_eq!(p.to_bytes().unwrap(), b"\x00\x01foo\x00netascii\x00");
        assert_eq!(p.opcode(), opcode::RRQ);
        // Modes in any case.
        let p = Packet::parse(b"\x00\x02bar\x00OcTeT\x00").unwrap();
        assert_eq!(p, Packet::WriteRequest(Request { filename: "bar".into(), mode: Mode::Octet, options: vec![] }));
        assert_eq!(p.to_bytes().unwrap(), b"\x00\x02bar\x00octet\x00");
        assert_eq!(Packet::parse(b"\x00\x01m\x00MAIL\x00").unwrap().to_bytes().unwrap(), b"\x00\x01m\x00mail\x00");
    }

    // RFC 2347 section "Packet Formats" and RFC 2349's example: a request
    // with options, and an OACK.
    #[test]
    fn rfc2347_options() {
        let p = Packet::parse(&rrq_example()).unwrap();
        let Packet::ReadRequest(r) = &p else { panic!() };
        assert_eq!(r.options, [TftpOption::new("blksize", "1024"), TftpOption::new("tsize", "0")]);
        assert_eq!(p.to_bytes().unwrap(), rrq_example());
        let oack = b"\x00\x06blksize\x001024\x00tsize\x00673312\x00";
        let p = Packet::parse(oack).unwrap();
        assert_eq!(
            p,
            Packet::OptionAck { options: vec![TftpOption::new("blksize", "1024"), TftpOption::new("tsize", "673312")] }
        );
        assert_eq!(p.to_bytes().unwrap(), oack);
        // An OACK with no options reads as one.
        assert_eq!(Packet::parse(&[0, 6]), Ok(Packet::OptionAck { options: vec![] }));
    }

    #[test]
    fn data_ack_and_error() {
        let p = Packet::parse(&[0, 3, 0, 1, b'h', b'i']).unwrap();
        assert_eq!(p, Packet::Data { block: 1, data: b"hi".to_vec() });
        assert_eq!(p.to_bytes().unwrap(), [0, 3, 0, 1, b'h', b'i']);
        assert_eq!(Packet::parse(&[0, 3, 0xff, 0xff]), Ok(Packet::Data { block: 65535, data: vec![] }));
        assert_eq!(Packet::parse(&[0, 4, 0x12, 0x34]), Ok(Packet::Ack { block: 0x1234 }));
        assert_eq!(Packet::Ack { block: 7 }.to_bytes().unwrap(), [0, 4, 0, 7]);
        let e = Packet::parse(b"\x00\x05\x00\x01File not found\x00").unwrap();
        assert_eq!(e, Packet::error(ErrorCode::FileNotFound));
        assert_eq!(e.to_bytes().unwrap(), b"\x00\x05\x00\x01File not found\x00");
        assert_eq!(
            Packet::parse(b"\x00\x05\x00\x08\x00"),
            Ok(Packet::Error { code: ErrorCode::OptionNegotiation, message: String::new() })
        );
        assert_eq!(
            Packet::parse(b"\x00\x05\x01\x00x\x00"),
            Ok(Packet::Error { code: ErrorCode::Other(256), message: "x".into() })
        );
    }

    #[test]
    fn error_codes() {
        for c in 0..=u16::MAX {
            assert_eq!(ErrorCode::from_code(c).code(), c);
        }
        assert_eq!(ErrorCode::from_code(5), ErrorCode::UnknownTransferId);
        assert_eq!(ErrorCode::Other(99).message(), "Not defined");
    }

    #[test]
    fn each_parse_error() {
        assert_eq!(Packet::parse(&[]), Err(Error::Short));
        assert_eq!(Packet::parse(&[0]), Err(Error::Short));
        assert_eq!(Packet::parse(&vec![0; MAX_PACKET + 1]), Err(Error::TooLong(MAX_PACKET + 1)));
        assert_eq!(Packet::parse(&[0, 7]), Err(Error::UnknownOpcode(7)));
        assert_eq!(Packet::parse(&[0, 0, 1, 2]), Err(Error::UnknownOpcode(0)));
        assert_eq!(Packet::parse(b"\x00\x01foo"), Err(Error::Unterminated));
        assert_eq!(Packet::parse(b"\x00\x01foo\x00octet"), Err(Error::Unterminated));
        let mut long = b"\x00\x05\x00\x00".to_vec();
        long.extend_from_slice(&[b'a'; MAX_STRING + 1]);
        long.push(0);
        assert_eq!(Packet::parse(&long), Err(Error::StringTooLong));
        assert_eq!(Packet::parse(b"\x00\x01\xff\x00octet\x00"), Err(Error::NotUtf8));
        assert_eq!(Packet::parse(b"\x00\x01foo\x00binary\x00"), Err(Error::UnknownMode));
        let mut many = b"\x00\x06".to_vec();
        for i in 0..=MAX_OPTIONS {
            many.extend_from_slice(format!("a{i}\x001\x00").as_bytes());
        }
        assert_eq!(Packet::parse(&many), Err(Error::TooManyOptions));
        assert_eq!(Packet::parse(b"\x00\x06blksize\x00"), Err(Error::MissingValue));
        assert_eq!(Packet::parse(b"\x00\x06blksize\x0010"), Err(Error::Unterminated));
        assert_eq!(Packet::parse(&[0, 4, 0, 1, 0]), Err(Error::TrailingBytes));
        assert_eq!(Packet::parse(b"\x00\x05\x00\x00hi\x00x"), Err(Error::TrailingBytes));
        assert_eq!(Packet::parse(&[0, 3, 0]), Err(Error::Short));
        assert_eq!(Packet::parse(&[0, 4, 0]), Err(Error::Short));
        assert_eq!(Packet::parse(&[0, 5, 0, 1]), Err(Error::Unterminated));
        assert_eq!(Packet::parse(&[0, 5, 0]), Err(Error::Short));
        // Every error has a message.
        for e in [
            Error::Short,
            Error::TooLong(9),
            Error::RequestTooLong(9),
            Error::UnknownOpcode(9),
            Error::MissingValue,
            Error::DuplicateOption,
        ] {
            assert!(!e.to_string().is_empty());
        }
        // The largest DATA packet reads.
        let mut largest = vec![0x03; MAX_PACKET];
        largest[0] = 0;
        assert!(Packet::parse(&largest).is_ok());
    }

    #[test]
    fn every_truncated_prefix() {
        let valid: Vec<Vec<u8>> = vec![
            rrq_example(),
            b"\x00\x02up.bin\x00octet\x00tsize\x00999\x00".to_vec(),
            b"\x00\x05\x00\x02Access violation\x00".to_vec(),
            b"\x00\x06blksize\x001428\x00timeout\x005\x00".to_vec(),
            vec![0, 4, 0, 9],
            vec![0, 3, 0, 1, 1, 2, 3],
        ];
        for packet in &valid {
            let full = Packet::parse(packet).unwrap();
            for n in 0..packet.len() {
                let prefix = &packet[..n];
                if let Ok(p) = Packet::parse(prefix) {
                    // A prefix can be a shorter valid packet only at a
                    // field boundary: DATA bytes, or whole options.
                    assert!(matches!(p, Packet::Data { .. } | Packet::OptionAck { .. }) || p.opcode() <= 2);
                    assert_eq!(Packet::parse(&p.to_bytes().unwrap()), Ok(p.clone()));
                    assert_ne!(p, full, "prefix {n} of {packet:?}");
                }
            }
        }
        // Requests and errors cut before their last NUL never read.
        let rrq = b"\x00\x01foo\x00octet\x00";
        for n in 0..rrq.len() {
            assert!(Packet::parse(&rrq[..n]).is_err(), "{n} bytes");
        }
        let err = b"\x00\x05\x00\x01gone\x00";
        for n in 0..err.len() {
            assert!(Packet::parse(&err[..n]).is_err(), "{n} bytes");
        }
        for n in 0..4 {
            assert!(Packet::parse(&[0, 4, 0, 1][..n]).is_err());
        }
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        let long = "é".repeat(MAX_STRING);
        let options = (0..40).map(|i| TftpOption::new(&format!("{i}{long}"), "1")).collect();
        for packet in [
            Packet::ReadRequest(Request { filename: format!("a\0b{long}"), mode: Mode::Octet, options: vec![] }),
            Packet::OptionAck { options },
            Packet::Data { block: 1, data: vec![1; MAX_PACKET * 2] },
            Packet::Error { code: ErrorCode::NotDefined, message: "x".repeat(5000) },
        ] {
            assert_eq!(packet.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&packet);
        }
    }

    #[test]
    fn writers_refuse_strings_with_nul() {
        // Each string is short, so only the NUL rule applies. Mode is an
        // enum whose names hold no NUL.
        let request = |filename: &str, options| Request { filename: filename.to_string(), mode: Mode::Octet, options };
        for packet in [
            Packet::ReadRequest(request("a\0b", vec![])),
            Packet::WriteRequest(request("\0", vec![])),
            Packet::ReadRequest(request("a", vec![TftpOption::new("bl\0ksize", "512")])),
            Packet::WriteRequest(request("a", vec![TftpOption::new("blksize", "512\0")])),
            Packet::OptionAck { options: vec![TftpOption::new("tsize\0", "1")] },
            Packet::OptionAck { options: vec![TftpOption::new("tsize", "1\0")] },
            Packet::Error { code: ErrorCode::NotDefined, message: "no\0pe".to_string() },
        ] {
            assert_eq!(packet.to_bytes(), Err(Error::Unwritable), "{packet:?}");
            contract::check_wire_value(&packet);
        }
        let fine = Packet::ReadRequest(request("a", vec![TftpOption::new("blksize", "512")]));
        assert_eq!(Packet::parse(&fine.to_bytes().unwrap()), Ok(fine));
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_number("0"), Some(0));
        assert_eq!(parse_number("1024"), Some(1024));
        assert_eq!(parse_number("18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_number("18446744073709551616"), None);
        assert_eq!(parse_number("000000000000000000001"), None);
        assert_eq!(parse_number(""), None);
        assert_eq!(parse_number("-1"), None);
        assert_eq!(parse_number(" 1"), None);
        assert_eq!(parse_number("1e3"), None);
    }

    #[test]
    fn negotiation() {
        let opts = |list: &[(&str, &str)]| list.iter().map(|(n, v)| TftpOption::new(n, v)).collect::<Vec<_>>();
        // RFC 2348: blksize, clamped to the server's limit.
        let n = negotiate(&opts(&[("BLKSIZE", "1428")]), None, MAX_BLOCK_SIZE);
        assert_eq!(n.block_size, 1428);
        assert_eq!(n.oack, opts(&[("blksize", "1428")]));
        let n = negotiate(&opts(&[("blksize", "65464")]), None, 1024);
        assert_eq!(n.block_size, 1024);
        let n = negotiate(&opts(&[("blksize", "65464")]), None, MAX_BLOCK_SIZE);
        assert_eq!(n.block_size, MAX_BLOCK_SIZE);
        // Too small, not a number: ignored.
        let n = negotiate(&opts(&[("blksize", "7"), ("blksize", "x")]), None, 0);
        assert_eq!((n.block_size, n.oack.len()), (DEFAULT_BLOCK_SIZE, 0));
        // A server limit below the minimum still allows the minimum.
        let n = negotiate(&opts(&[("blksize", "8")]), None, 0);
        assert_eq!(n.block_size, 8);
        // RFC 2349: timeout in 1..=255, tsize answered with the size.
        for bad in ["0", "256"] {
            assert_eq!(negotiate(&opts(&[("timeout", bad)]), None, 512).oack, []);
        }
        let n = negotiate(&opts(&[("timeout", "3")]), None, 512);
        assert_eq!(n.timeout, Some(3));
        assert_eq!(n.oack, opts(&[("timeout", "3")]));
        let n = negotiate(&opts(&[("tsize", "0")]), Some(673312), 512);
        assert_eq!(n.transfer_size, Some(673312));
        assert_eq!(n.oack, opts(&[("tsize", "673312")]));
        let n = negotiate(&opts(&[("tsize", "42")]), None, 512);
        assert_eq!(n.oack, opts(&[("tsize", "42")]));
        // Unknown options and repeats are left out; order is kept.
        let n = negotiate(
            &opts(&[("windowsize", "4"), ("tsize", "0"), ("blksize", "1024"), ("blksize", "2048"), ("tsize", "1")]),
            Some(5),
            MAX_BLOCK_SIZE,
        );
        assert_eq!(n.block_size, 1024);
        assert_eq!(n.oack, opts(&[("tsize", "5"), ("blksize", "1024")]));
        assert_eq!(negotiate(&[], Some(1), 512).oack, []);
    }

    /// Runs a transfer to the end with in-order ACKs, and returns the
    /// bytes it sent.
    fn run(mut t: ReadTransfer) -> Vec<u8> {
        let mut got = Vec::new();
        let mut packet = t.current().unwrap();
        loop {
            let ack = match &packet {
                Packet::OptionAck { .. } => 0,
                Packet::Data { block, data } => {
                    got.extend_from_slice(data);
                    *block
                }
                other => panic!("sent {other:?}"),
            };
            match t.on_ack(ack) {
                Event::Send(p) => packet = p,
                Event::Complete => return got,
                other => panic!("got {other:?}"),
            }
        }
    }

    #[test]
    fn transfer_without_options() {
        let mut t = ReadTransfer::new(b"hello".to_vec());
        assert_eq!(t.blocks(), 1);
        assert_eq!(t.current(), Some(Packet::Data { block: 1, data: b"hello".to_vec() }));
        // ACK 0 is the block before: a duplicate.
        assert_eq!(t.on_ack(0), Event::Duplicate);
        assert_eq!(t.on_ack(9), Event::Unexpected);
        assert_eq!(t.on_ack(1), Event::Complete);
        assert!(t.is_complete());
        assert_eq!(t.on_ack(1), Event::Duplicate);
        assert_eq!(t.on_ack(2), Event::Unexpected);
        assert_eq!(t.current(), None);
    }

    #[test]
    fn exact_multiple_ends_with_an_empty_block() {
        let t = ReadTransfer::new(vec![7; 1024]);
        assert_eq!(t.blocks(), 3);
        assert_eq!(run(t.clone()), vec![7; 1024]);
        let mut t = t;
        t.on_ack(1);
        t.on_ack(2);
        assert_eq!(t.current(), Some(Packet::Data { block: 3, data: vec![] }));
        // An empty file is one empty block.
        let t = ReadTransfer::new(vec![]);
        assert_eq!(t.current(), Some(Packet::Data { block: 1, data: vec![] }));
    }

    #[test]
    fn block_numbers_wrap() {
        let data: Vec<u8> = (0..70_000u32 * 8 + 3).map(|i| i as u8).collect();
        let t = ReadTransfer::negotiated(data.clone(), &negotiate(&[TftpOption::new("blksize", "8")], None, 8));
        assert_eq!(t.blocks(), 70_001);
        assert_eq!(run(t.clone()), data);
        let mut t = t;
        assert!(matches!(t.on_ack(0), Event::Send(Packet::Data { block: 1, .. })));
        for k in 1..=65535u16 {
            assert!(matches!(t.on_ack(k), Event::Send(_)));
        }
        assert!(matches!(t.current(), Some(Packet::Data { block: 0, .. })));
        assert_eq!(t.on_ack(65535), Event::Duplicate);
        assert!(matches!(t.on_ack(0), Event::Send(Packet::Data { block: 1, .. })));
        assert_eq!(t.in_flight(), 65537);
    }

    #[test]
    fn errors_and_strays() {
        let agreed = negotiate(&[TftpOption::new("blksize", "8")], Some(20), 512);
        let mut t = ReadTransfer::negotiated(vec![1; 20], &agreed);
        assert_eq!(t.block_size(), 8);
        assert!(matches!(t.current(), Some(Packet::OptionAck { .. })));
        // With the OACK in flight, 65535 is not a duplicate.
        assert_eq!(t.on_ack(65535), Event::Unexpected);
        assert_eq!(t.on_packet(&Packet::Data { block: 1, data: vec![] }), Event::Unexpected);
        assert!(matches!(t.on_packet(&Packet::Ack { block: 0 }), Event::Send(Packet::Data { block: 1, .. })));
        let error = Packet::error(ErrorCode::DiskFull);
        assert_eq!(t.on_packet(&error), Event::Aborted(ErrorCode::DiskFull));
        assert!(t.is_aborted());
        assert_eq!(t.on_packet(&error), Event::Unexpected);
        assert_eq!(t.on_ack(1), Event::Unexpected);
        assert_eq!(t.current(), None);
        // RFC 1350: with no options, blocks are 512 bytes.
        let t = ReadTransfer::new(vec![1; 1000]);
        assert_eq!(t.block_size(), DEFAULT_BLOCK_SIZE);
        assert_eq!(t.current(), Some(Packet::Data { block: 1, data: vec![1; 512] }));
    }

    // RFC 2347: "The maximum size of a request packet is 512 octets."
    #[test]
    fn requests_are_at_most_512_bytes() {
        let mut rrq = b"\x00\x01".to_vec();
        rrq.extend_from_slice(&[b'f'; 400]);
        rrq.extend_from_slice(b"\x00octet\x00");
        // 409 bytes so far. An option of 104 more bytes takes it past 512.
        rrq.extend_from_slice(b"x\x00");
        rrq.extend_from_slice(&[b'1'; 101]);
        rrq.push(0);
        assert_eq!(rrq.len(), 513);
        assert_eq!(Packet::parse(&rrq), Err(Error::RequestTooLong(513)));
        rrq.truncate(512);
        *rrq.last_mut().unwrap() = 0;
        assert!(Packet::parse(&rrq).is_ok());
        let long = "é".repeat(MAX_STRING);
        let options: Vec<TftpOption> = (0..40).map(|i| TftpOption::new(&format!("o{i}"), &"9".repeat(60))).collect();
        for filename in [long, "a".into()] {
            let p = Packet::WriteRequest(Request { filename, mode: Mode::NetAscii, options: options.clone() });
            assert_eq!(p.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&p);
        }
        let bounded = Packet::WriteRequest(Request {
            filename: "a".into(), mode: Mode::Octet, options: options[..7].to_vec(),
        });
        assert!(bounded.to_bytes().unwrap().len() <= MAX_REQUEST);
        contract::check_wire_value(&bounded);
    }

    // RFC 2347: "An option may only be specified once."
    #[test]
    fn repeated_options_are_rejected() {
        assert_eq!(
            Packet::parse(b"\x00\x01f\x00octet\x00blksize\x001024\x00BlkSize\x00512\x00"),
            Err(Error::DuplicateOption)
        );
        assert_eq!(Packet::parse(b"\x00\x06tsize\x001\x00tsize\x002\x00"), Err(Error::DuplicateOption));
        // The writer refuses repeated options.
        let p = Packet::OptionAck { options: vec![TftpOption::new("tsize", "1"), TftpOption::new("TSIZE", "2")] };
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&p);
        // negotiate() ignores every repeat, even after a first value it
        // could not accept, as its doc says.
        let n = negotiate(&[TftpOption::new("blksize", "7"), TftpOption::new("blksize", "1024")], None, MAX_BLOCK_SIZE);
        assert_eq!((n.block_size, n.oack.len()), (DEFAULT_BLOCK_SIZE, 0));
        let n = negotiate(&[TftpOption::new("timeout", "x"), TftpOption::new("timeout", "3")], None, MAX_BLOCK_SIZE);
        assert_eq!(n.timeout, None);
    }

    // RFC 2348: blksize values range from 8 to 65464. Larger ones are not
    // valid, so they are left out like smaller ones.
    #[test]
    fn blksize_above_the_range_is_ignored() {
        let n = negotiate(&[TftpOption::new("blksize", "65465")], None, MAX_BLOCK_SIZE);
        assert_eq!((n.block_size, n.oack.len()), (DEFAULT_BLOCK_SIZE, 0));
        let n = negotiate(&[TftpOption::new("blksize", "65464")], None, 1024);
        assert_eq!(n.block_size, 1024);
    }

    // An Other code that has a name of its own writes and reads back as
    // the same packet.
    #[test]
    fn other_error_codes_compare_by_number() {
        let p = Packet::Error { code: ErrorCode::Other(1), message: "x".into() };
        assert_eq!(Packet::parse(&p.to_bytes().unwrap()), Ok(p));
        assert_eq!(ErrorCode::Other(8), ErrorCode::OptionNegotiation);
        assert_ne!(ErrorCode::Other(9), ErrorCode::OptionNegotiation);
    }

    // RFC 1350: with no blksize in the OACK, blocks are 512 bytes. A
    // Negotiated whose block_size and oack disagree must follow the oack,
    // which is what the client sees.
    #[test]
    fn negotiated_block_size_follows_the_oack() {
        let quiet = Negotiated { block_size: 8, timeout: None, transfer_size: None, oack: vec![] };
        let t = ReadTransfer::negotiated(vec![1; 1000], &quiet);
        assert_eq!(t.block_size(), DEFAULT_BLOCK_SIZE);
        assert_eq!(t.current(), Some(Packet::Data { block: 1, data: vec![1; 512] }));
        let loud = Negotiated {
            block_size: 1024,
            timeout: None,
            transfer_size: None,
            oack: vec![TftpOption::new("BlkSize", "8")],
        };
        assert_eq!(ReadTransfer::negotiated(vec![1; 1000], &loud).block_size(), 8);
        // A blksize the client could not accept is not sent, and the
        // default holds.
        let bad = Negotiated {
            block_size: 7,
            timeout: None,
            transfer_size: None,
            oack: vec![TftpOption::new("blksize", "7")],
        };
        let t = ReadTransfer::negotiated(vec![], &bad);
        assert_eq!((t.block_size(), t.current()), (DEFAULT_BLOCK_SIZE, Some(Packet::Data { block: 1, data: vec![] })));
        // A repeat is not what the client sees, so it does not count.
        let twice = Negotiated {
            block_size: 16,
            timeout: None,
            transfer_size: None,
            oack: vec![TftpOption::new("blksize", "8"), TftpOption::new("blksize", "16")],
        };
        let t = ReadTransfer::negotiated(vec![], &twice);
        assert_eq!(t.block_size(), 8);
        let Some(oack) = t.current() else { panic!() };
        assert_eq!(Packet::parse(&oack.to_bytes().unwrap()), Ok(oack));
    }

    // What a transfer keeps of a caller's OACK is bounded by what can be
    // written, not by the caller's list.
    #[test]
    fn negotiated_keeps_a_bounded_oack() {
        let big = "x".repeat(100_000);
        let mut oack: Vec<TftpOption> = (0..100_000).map(|i| TftpOption::new(&format!("o{i}"), "1")).collect();
        oack.insert(0, TftpOption::new(&big, &big));
        let agreed = Negotiated { block_size: 512, timeout: None, transfer_size: None, oack };
        let t = ReadTransfer::negotiated(vec![], &agreed);
        let Some(Packet::OptionAck { options }) = t.current() else { panic!() };
        assert!(options.len() <= MAX_OPTIONS);
        assert!(options.iter().all(|o| o.name.len() <= MAX_STRING && o.value.len() <= MAX_STRING));
        let p = Packet::OptionAck { options };
        assert_eq!(Packet::parse(&p.to_bytes().unwrap()), Ok(p));
    }

    // RFC 2347 bounds a request only by its 512 bytes. Seventeen small
    // options fit easily, and a server ignores the ones it does not know.
    #[test]
    fn requests_with_many_small_options_read() {
        let mut rrq = b"\x00\x01f\x00octet\x00".to_vec();
        for i in 0..=16 {
            rrq.extend_from_slice(format!("x{i}\x001\x00").as_bytes());
        }
        assert_eq!(rrq.len(), 102);
        let p = Packet::parse(&rrq).unwrap();
        let Packet::ReadRequest(r) = &p else { panic!() };
        assert_eq!(r.options.len(), 17);
        assert_eq!(p.to_bytes().unwrap(), rrq);
        assert_eq!(negotiate(&r.options, Some(1), 512).oack, []);
    }

    #[test]
    fn netascii() {
        let mut out = Vec::new();
        for &byte in b"a\nb\rc" { NetasciiByte(byte).write(&mut out).unwrap(); }
        assert_eq!(out, b"a\r\nb\r\0c");
        for byte in 0..=u8::MAX {
            contract::check_wire_value(&NetasciiByte(byte));
        }
    }

    // RFC 764 pairs can span DATA blocks. The shared contract exercises
    // splits and EOF, including a final CR.
    #[test]
    fn netascii_across_blocks() {
        use fictionet::stdlib::codec::test_support::decode_all;
        for (wire, text) in [
            (&b"1234567\r\0X"[..], &b"1234567\rX"[..]),
            (&b"1234567\r\nX"[..], &b"1234567\nX"[..]),
            (&b"a\r\rb\r"[..], &b"a\r\rb\r"[..]),
            (&b"x\r\0\r\n\r\n\r\0y\r\0\r\0\0\r\0\rz\r\r\n\r"[..], &b"x\r\n\n\ry\r\r\0\r\rz\r\n\r"[..]),
        ] {
            contract::check_decode_with_alloc_limit(|| NetasciiBytes, wire, 4);
            let (items, error) = decode_all(|| NetasciiBytes, wire);
            assert_eq!(error, None);
            assert_eq!(items.into_iter().map(|c| c.0).collect::<Vec<_>>(), text);
        }
    }

    #[test]
    fn fuzz_parse_and_round_trip() {
        let mut rng = Lcg::new(0x7f7f_1350);
        let seeds = [
            rrq_example(),
            b"\x00\x06blksize\x001428\x00".to_vec(),
            b"\x00\x05\x00\x01nope\x00".to_vec(),
            vec![0, 4, 0, 1],
            vec![0, 3, 0, 1, 9, 9],
        ];
        for i in 0..4000 {
            let buf: Vec<u8> = if i % 2 == 0 {
                // A seed with a few bytes changed, cut or added.
                let mut b = seeds[rng.index(seeds.len())].clone();
                for _ in 0..=rng.index(3) { mutate(&mut rng, &mut b); }
                b
            } else {
                let len = rng.index(64);
                let mut b = vec![0; len];
                rng.fill(&mut b);
                if len >= 2 {
                    b[0] = 0;
                    b[1] = rng.index(8) as u8;
                }
                b
            };
            contract::check_wire::<Packet>(&buf);
            if let Ok(p) = Packet::parse(&buf) {
                assert_eq!(Packet::parse(&p.to_bytes().unwrap()), Ok(p.clone()), "{buf:?}");
                let options = match &p {
                    Packet::ReadRequest(r) | Packet::WriteRequest(r) => Some(&r.options),
                    Packet::OptionAck { options } => Some(options),
                    _ => None,
                };
                if let Some(options) = options {
                    let n = negotiate(options, Some(buf.len() as u64), rng.next() as u16);
                    assert!((MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&n.block_size));
                    let oack = Packet::OptionAck { options: n.oack.clone() };
                    assert_eq!(Packet::parse(&oack.to_bytes().unwrap()), Ok(oack));
                    assert_eq!(run(ReadTransfer::negotiated(buf.clone(), &n)), buf);
                }
            }
            // A transfer given random ACKs never panics, and only sends
            // DATA blocks of the right size.
            let blksize = negotiate(&[TftpOption::new("blksize", &rng.index(40).to_string())], None, 40);
            let mut t = ReadTransfer::negotiated(buf.clone(), &blksize);
            for _ in 0..rng.index(20) {
                let ack = if rng.coin() { wire(t.in_flight()) } else { rng.next() as u16 };
                if let Event::Send(Packet::Data { data, .. }) = t.on_ack(ack) {
                    assert!(data.len() <= usize::from(t.block_size()));
                }
            }
            let mut encoded = Vec::new();
            for &byte in &buf { NetasciiByte(byte).write(&mut encoded).unwrap(); }
            let (text, error) = fictionet::stdlib::codec::test_support::decode_all(|| NetasciiBytes, &encoded);
            assert_eq!(error, None);
            assert_eq!(text.into_iter().map(|c| c.0).collect::<Vec<_>>(), buf);
            contract::check_decode_with_alloc_limit(|| NetasciiBytes, &buf, 4);
        }
    }
}
