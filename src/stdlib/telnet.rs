//! Telnet: separating data from commands, negotiating options, and reading
//! and writing the terminal type and window size, with no I/O.
//!
//! `Event` and `BinaryEvent` implement `Wire`, `Events` decodes the stream, and
//! `Negotiation` tracks option state with the Q method. There is no login
//! session, terminal emulator, `Service`, or live transport.
//!
//! Telnet is the oldest remote login protocol, and many routers, switches,
//! PLCs and embedded boards still offer it on TCP port 23. Both ends send
//! text, and mix commands into it: each command starts with the byte 255,
//! IAC ("interpret as command"). Four commands (WILL, WONT, DO and DONT)
//! turn options such as echo or binary mode on and off, and a
//! subnegotiation (IAC SB ... IAC SE) carries an option's own data. This
//! module follows RFC 854 (the protocol), RFC 855 (options), RFC 1091
//! (terminal type) and RFC 1073 (window size), and negotiates options with
//! the Q method of RFC 1143, which never loops.
//!
//! A world pushes connection bytes to [`Stream<Events>`](fictionet::stdlib::codec::Stream),
//! reads one [`Event`] at a time, and hands negotiations to [`Negotiation`].
//! It writes each returned reply event and changes binary mode between items.
//! The default delivers each data byte immediately. Batch readers can use
//! [`Events::with_limit`] to wait for larger runs. [`Event`] uses NVT
//! encoding; [`BinaryEvent`] carries an event in binary mode.
//! Unknown commands and interrupted or oversized subnegotiations produce
//! [`Event::Error`] items. The stream then continues.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::telnet::{option, Change, Events, Event, Negotiation, Side, Subnegotiation, Verb};
//!
//! // The server agrees to let the client send its terminal type.
//! let mut options = Negotiation::new();
//! options.allow_remote(option::TERMINAL_TYPE, true);
//! // It asks the client to: IAC DO TERMINAL-TYPE.
//! let ask = options.enable_remote(option::TERMINAL_TYPE);
//! assert_eq!(ask.send, Some(Event::Negotiation { verb: Verb::Do, option: option::TERMINAL_TYPE }));
//!
//! // The client agrees (IAC WILL TERMINAL-TYPE) and types "ls", CR LF.
//! let mut stream = Stream::new(Events::new());
//! assert_eq!(stream.push(&[255, 251, 24, b'l', b's', 13, 10]), 7);
//! assert_eq!(stream.next(), Some(Ok(Event::Negotiation { verb: Verb::Will, option: option::TERMINAL_TYPE })));
//! for &byte in b"ls\r\n" {
//!     assert_eq!(stream.next(), Some(Ok(Event::Data(vec![byte]))));
//! }
//!
//! // The WILL answers the DO, so nothing more is sent, and the option is on.
//! let reaction = options.receive(Verb::Will, option::TERMINAL_TYPE);
//! assert_eq!(reaction.send, None);
//! assert_eq!(reaction.change, Some(Change { side: Side::Remote, option: option::TERMINAL_TYPE, enabled: true }));
//!
//! // The server asks for the name, and the client sends it.
//! assert_eq!(Wire::to_bytes(&Subnegotiation::TerminalTypeSend).unwrap(), [255, 250, 24, 1, 255, 240]);
//! assert_eq!(stream.push(b"\xff\xfa\x18\x00VT100\xff\xf0"), 11);
//! let Some(Ok(Event::Subnegotiation { option, data })) = stream.next() else { panic!() };
//! let name = Subnegotiation::parse_data(option, &data).unwrap();
//! assert_eq!(name, Subnegotiation::TerminalTypeIs("VT100".to_string()));
//! ```

use fictionet::stdlib::codec::{self, Decode, Step, Wire};

/// The TCP port Telnet servers listen on.
pub const PORT: u16 = 23;
/// The most data bytes one subnegotiation may carry, after IAC escapes are
/// undone. Longer ones are dropped and reported.
pub const MAX_SUBNEGOTIATION: usize = 1024;
/// The longest terminal type name, from RFC 1091.
pub const MAX_TERMINAL_TYPE: usize = 40;

/// "Interpret as command": the byte that starts every command. In data it
/// is sent twice.
pub const IAC: u8 = 255;
/// Carriage return. Outside binary mode it is followed by LF or NUL.
pub const CR: u8 = 13;
/// Line feed.
pub const LF: u8 = 10;
/// The NUL byte, which follows a CR that is not part of a new line.
pub const NUL: u8 = 0;

/// The command bytes that follow IAC.
pub mod cmd {
    /// End of file, from RFC 1184.
    pub const EOF: u8 = 236;
    /// Suspend the running process, from RFC 1184.
    pub const SUSP: u8 = 237;
    /// Abort the running process, from RFC 1184.
    pub const ABORT: u8 = 238;
    /// End of record, from RFC 885.
    pub const EOR: u8 = 239;
    /// End of subnegotiation.
    pub const SE: u8 = 240;
    /// No operation.
    pub const NOP: u8 = 241;
    /// Data mark, the end of a Synch.
    pub const DM: u8 = 242;
    /// Break.
    pub const BRK: u8 = 243;
    /// Interrupt process.
    pub const IP: u8 = 244;
    /// Abort output.
    pub const AO: u8 = 245;
    /// Are you there.
    pub const AYT: u8 = 246;
    /// Erase character.
    pub const EC: u8 = 247;
    /// Erase line.
    pub const EL: u8 = 248;
    /// Go ahead.
    pub const GA: u8 = 249;
    /// Start of subnegotiation.
    pub const SB: u8 = 250;
    /// The sender will do an option.
    pub const WILL: u8 = 251;
    /// The sender will not do an option.
    pub const WONT: u8 = 252;
    /// The sender asks the receiver to do an option.
    pub const DO: u8 = 253;
    /// The sender asks the receiver not to do an option.
    pub const DONT: u8 = 254;
}

/// Option codes, from the IANA Telnet options registry.
pub mod option {
    /// Binary transmission, RFC 856.
    pub const BINARY: u8 = 0;
    /// Echo, RFC 857.
    pub const ECHO: u8 = 1;
    /// Suppress go ahead, RFC 858.
    pub const SUPPRESS_GO_AHEAD: u8 = 3;
    /// Status, RFC 859.
    pub const STATUS: u8 = 5;
    /// Timing mark, RFC 860.
    pub const TIMING_MARK: u8 = 6;
    /// Terminal type, RFC 1091.
    pub const TERMINAL_TYPE: u8 = 24;
    /// End of record, RFC 885.
    pub const END_OF_RECORD: u8 = 25;
    /// Negotiate about window size, RFC 1073.
    pub const NAWS: u8 = 31;
    /// Terminal speed, RFC 1079.
    pub const TERMINAL_SPEED: u8 = 32;
    /// Remote flow control, RFC 1372.
    pub const TOGGLE_FLOW_CONTROL: u8 = 33;
    /// Line mode, RFC 1184.
    pub const LINEMODE: u8 = 34;
    /// New environment, RFC 1572.
    pub const NEW_ENVIRON: u8 = 39;
}

/// The codes at the start of a terminal type subnegotiation.
pub mod terminal_type {
    /// The client's answer: IS and a name.
    pub const IS: u8 = 0;
    /// The server's question: SEND.
    pub const SEND: u8 = 1;
}

/// The four option negotiation commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verb {
    /// The sender will do the option, or offers to.
    Will,
    /// The sender will not do the option.
    Wont,
    /// The sender asks the receiver to do the option.
    Do,
    /// The sender asks the receiver not to do the option.
    Dont,
}

impl Verb {
    /// The command byte.
    pub fn byte(self) -> u8 {
        match self {
            Verb::Will => cmd::WILL,
            Verb::Wont => cmd::WONT,
            Verb::Do => cmd::DO,
            Verb::Dont => cmd::DONT,
        }
    }

    /// The verb for command byte `b`, if it is one.
    pub fn from_byte(b: u8) -> Option<Verb> {
        match b {
            cmd::WILL => Some(Verb::Will),
            cmd::WONT => Some(Verb::Wont),
            cmd::DO => Some(Verb::Do),
            cmd::DONT => Some(Verb::Dont),
            _ => None,
        }
    }
}

/// A command with no option: IAC and one byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Command {
    /// End of file (RFC 1184).
    EndOfFile,
    /// Suspend the running process (RFC 1184).
    Suspend,
    /// Abort the running process (RFC 1184).
    Abort,
    /// End of record (RFC 885).
    EndOfRecord,
    /// No operation.
    Nop,
    /// Data mark: where a Synch ends.
    DataMark,
    /// The break or attention key.
    Break,
    /// Interrupt the running process.
    InterruptProcess,
    /// Discard output that has not been shown yet.
    AbortOutput,
    /// Ask whether the other end is still there.
    AreYouThere,
    /// Erase the last character typed.
    EraseCharacter,
    /// Erase the line being typed.
    EraseLine,
    /// Go ahead: the other end may send now.
    GoAhead,
}

impl Command {
    /// The command byte.
    pub fn byte(self) -> u8 {
        match self {
            Command::EndOfFile => cmd::EOF,
            Command::Suspend => cmd::SUSP,
            Command::Abort => cmd::ABORT,
            Command::EndOfRecord => cmd::EOR,
            Command::Nop => cmd::NOP,
            Command::DataMark => cmd::DM,
            Command::Break => cmd::BRK,
            Command::InterruptProcess => cmd::IP,
            Command::AbortOutput => cmd::AO,
            Command::AreYouThere => cmd::AYT,
            Command::EraseCharacter => cmd::EC,
            Command::EraseLine => cmd::EL,
            Command::GoAhead => cmd::GA,
        }
    }

    /// The command for byte `b`, if it is one of these.
    pub fn from_byte(b: u8) -> Option<Command> {
        match b {
            cmd::EOF => Some(Command::EndOfFile),
            cmd::SUSP => Some(Command::Suspend),
            cmd::ABORT => Some(Command::Abort),
            cmd::EOR => Some(Command::EndOfRecord),
            cmd::NOP => Some(Command::Nop),
            cmd::DM => Some(Command::DataMark),
            cmd::BRK => Some(Command::Break),
            cmd::IP => Some(Command::InterruptProcess),
            cmd::AO => Some(Command::AbortOutput),
            cmd::AYT => Some(Command::AreYouThere),
            cmd::EC => Some(Command::EraseCharacter),
            cmd::EL => Some(Command::EraseLine),
            cmd::GA => Some(Command::GoAhead),
            _ => None,
        }
    }
}

/// What [`Events`] found in the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Data, with IAC escapes undone and, outside binary mode, each CR NUL
    /// turned back into a CR. A CR LF stays as it is.
    Data(Vec<u8>),
    /// A command with no option.
    Command(Command),
    /// WILL, WONT, DO or DONT for an option.
    Negotiation {
        /// Which of the four.
        verb: Verb,
        /// The option code.
        option: u8,
    },
    /// A whole subnegotiation. [`Subnegotiation::parse_data`] reads the ones
    /// this module knows.
    Subnegotiation {
        /// The option code.
        option: u8,
        /// The bytes between the option code and IAC SE, with IAC escapes
        /// undone.
        data: Vec<u8>,
    },
    /// Bytes that break the protocol. The decoder skips them and goes on.
    Error(Error),
}

/// Why Telnet bytes break the protocol, or a value cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// IAC was followed by a byte that is no command (below 236).
    UnknownCommand(u8),
    /// IAC SE came with no subnegotiation open.
    StraySubnegotiationEnd,
    /// A subnegotiation for `option` carried more than
    /// [`MAX_SUBNEGOTIATION`] bytes. It was dropped.
    SubnegotiationTooLong {
        /// The option code.
        option: u8,
    },
    /// A subnegotiation for `option` was cut off by a command other than
    /// IAC SE. It was dropped, and the command was read.
    SubnegotiationInterrupted {
        /// The option code.
        option: u8,
    },
    /// The stream ended in the middle of a command or subnegotiation.
    Truncated,
    /// A terminal type subnegotiation with no data.
    Empty,
    /// A terminal type code other than IS (0) or SEND (1).
    UnknownCode(u8),
    /// SEND followed by more bytes.
    TrailingAfterSend,
    /// A terminal type name that is empty or longer than
    /// [`MAX_TERMINAL_TYPE`].
    NameLength(usize),
    /// A terminal type name with a byte that is not printable ASCII or a
    /// space.
    NameByte(u8),
    /// A window size whose data is not exactly 4 bytes long.
    WindowSizeLength(usize),
    /// Data for another option longer than [`MAX_SUBNEGOTIATION`] bytes,
    /// which [`Events`] never returns and the writer could not send
    /// whole.
    DataTooLong(usize),
    /// The slice has no complete event.
    Incomplete,
    /// The slice contains bytes after the first event.
    Trailing,
    /// The input exceeds [`MAX_DATA`], [`MAX_SUBNEGOTIATION`], or [`MAX_EVENT_WIRE`].
    TooLong,
    /// An event of another kind was read where a typed subnegotiation was required.
    UnexpectedEvent,
    /// The value cannot be written without changing it.
    Unwritable,
    /// The output could not be allocated.
    Allocation,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownCommand(b) => write!(f, "IAC followed by {b}, which is no command"),
            Error::StraySubnegotiationEnd => f.write_str("IAC SE with no subnegotiation open"),
            Error::SubnegotiationTooLong { option } => {
                write!(f, "subnegotiation for option {option} longer than {MAX_SUBNEGOTIATION} bytes")
            }
            Error::SubnegotiationInterrupted { option } => {
                write!(f, "subnegotiation for option {option} cut off by another command")
            }
            Error::Truncated => f.write_str("stream ended inside a command"),
            Error::Empty => f.write_str("terminal type subnegotiation with no data"),
            Error::UnknownCode(c) => write!(f, "terminal type code {c}, not IS or SEND"),
            Error::TrailingAfterSend => f.write_str("bytes after terminal type SEND"),
            Error::NameLength(n) => {
                write!(f, "terminal type name of {n} bytes, outside 1..={MAX_TERMINAL_TYPE}")
            }
            Error::NameByte(b) => write!(f, "byte {b} in a terminal type name"),
            Error::WindowSizeLength(n) => write!(f, "window size of {n} bytes, not 4"),
            Error::DataTooLong(n) => {
                write!(f, "subnegotiation data of {n} bytes, more than {MAX_SUBNEGOTIATION}")
            }
            Error::Incomplete => f.write_str("incomplete Telnet event"),
            Error::Trailing => f.write_str("bytes after Telnet event"),
            Error::TooLong => f.write_str("Telnet event exceeds its wire limit"),
            Error::UnexpectedEvent => f.write_str("expected a Telnet subnegotiation"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Allocation => f.write_str("Telnet output allocation failed"),
        }
    }
}

impl std::error::Error for Error {}

/// A subnegotiation this module reads and writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subnegotiation {
    /// The server asks for the terminal type (RFC 1091): SEND.
    TerminalTypeSend,
    /// The client names its terminal type (RFC 1091): IS and a name of 1
    /// to [`MAX_TERMINAL_TYPE`] printable ASCII characters or spaces, such
    /// as "VT100", "XTERM" or "MTTS 137". Names are case-insensitive.
    TerminalTypeIs(String),
    /// The client's window size in characters (RFC 1073). Zero means the
    /// size is not known.
    WindowSize {
        /// Columns.
        width: u16,
        /// Rows.
        height: u16,
    },
    /// Any other option, with its data unread. [`Subnegotiation::parse_data`]
    /// never returns it for [`option::TERMINAL_TYPE`] or [`option::NAWS`].
    /// The writer refuses this variant for either known option.
    Other {
        /// The option code.
        option: u8,
        /// The data, with IAC escapes undone.
        data: Vec<u8>,
    },
}

impl Subnegotiation {
    /// Reads the data of a subnegotiation for `option`, as an
    /// [`Event::Subnegotiation`] carries it.
    pub fn parse_data(option: u8, data: &[u8]) -> Result<Subnegotiation, Error> {
        match option {
            option::TERMINAL_TYPE => {
                let (&code, rest) = data.split_first().ok_or(Error::Empty)?;
                match code {
                    terminal_type::SEND if rest.is_empty() => Ok(Subnegotiation::TerminalTypeSend),
                    terminal_type::SEND => Err(Error::TrailingAfterSend),
                    terminal_type::IS => {
                        if rest.is_empty() || rest.len() > MAX_TERMINAL_TYPE {
                            return Err(Error::NameLength(rest.len()));
                        }
                        if let Some(&b) = rest.iter().find(|b| !is_name_byte(b)) {
                            return Err(Error::NameByte(b));
                        }
                        // Every byte is ASCII, so this is one char per byte.
                        Ok(Subnegotiation::TerminalTypeIs(rest.iter().map(|&b| char::from(b)).collect()))
                    }
                    c => Err(Error::UnknownCode(c)),
                }
            }
            option::NAWS => match *data {
                [w0, w1, h0, h1] => Ok(Subnegotiation::WindowSize {
                    width: u16::from_be_bytes([w0, w1]),
                    height: u16::from_be_bytes([h0, h1]),
                }),
                _ => Err(Error::WindowSizeLength(data.len())),
            },
            _ if data.len() > MAX_SUBNEGOTIATION => Err(Error::DataTooLong(data.len())),
            _ => Ok(Subnegotiation::Other { option, data: data.to_vec() }),
        }
    }

    /// The option this subnegotiation is for.
    pub fn option(&self) -> u8 {
        match self {
            Subnegotiation::TerminalTypeSend | Subnegotiation::TerminalTypeIs(_) => option::TERMINAL_TYPE,
            Subnegotiation::WindowSize { .. } => option::NAWS,
            Subnegotiation::Other { option, .. } => *option,
        }
    }
}

/// Whether `b` may be in a terminal type name: printable ASCII or a space.
/// RFC 1091 allows any NVT ASCII string, and MTTS clients send names such
/// as "MTTS 137".
fn is_name_byte(b: &u8) -> bool {
    (0x20..=0x7e).contains(b)
}

/// The largest configurable data run from [`Events`], and the most data
/// bytes in one [`Wire`] event. [`Events::new`] uses a limit of 1.
pub const MAX_DATA: usize = 1024;
/// The most encoded bytes needed for a data run or subnegotiation,
/// including doubled IAC bytes, framing, or detection of an oversized payload.
pub const MAX_EVENT_WIRE: usize = 2 * MAX_SUBNEGOTIATION + 5;

/// Reads one Telnet event per call without retaining input bytes.
///
/// By default, each data byte is delivered as its own event, so interactive
/// sessions receive input without waiting for a command or EOF. Batch readers
/// can use [`Self::with_limit`]: data runs then end at a command, the
/// configured limit, or EOF, waiting across chunk boundaries so partitioning
/// never changes the items.
/// A trailing NVT CR waits for its next byte or EOF. Scan cursors keep
/// bytewise input linear. All payload storage belongs to returned items.
///
/// Recoverable failures are [`Event::Error`] items. An oversized subnegotiation
/// is discarded through IAC SE and reported as
/// [`Error::SubnegotiationTooLong`]. An interrupting command yields
/// [`Error::SubnegotiationInterrupted`] first, then the command on
/// the next call. Discarding holds only an option code, with no byte buffer.
/// Partial commands and subnegotiations return [`Step::Need`] at EOF for
/// [`codec::Fail::Truncated`]. EOF during an oversized discarded unit is
/// terminal [`Error::Truncated`], since its prefix was consumed.
///
/// Change binary mode only between items. The session owns negotiation:
///
/// ```
/// use fictionet::stdlib::{codec::Stream, telnet::{self, Event, Negotiation, Side}};
/// let mut stream = Stream::new(telnet::Events::new());
/// let mut options = Negotiation::new();
/// options.allow_remote(telnet::option::BINARY, true);
/// assert_eq!(stream.push(&[255, 251, 0, 13, 0]), 5);
/// if let Some(Ok(Event::Negotiation { verb, option })) = stream.next() {
///     let reaction = options.receive(verb, option);
///     // The session sends reaction.send, if present.
///     if let Some(change) = reaction.change {
///         if change.side == Side::Remote && change.option == telnet::option::BINARY {
///             stream.decoder().set_binary(change.enabled);
///         }
///     }
/// }
/// assert_eq!(stream.next(), Some(Ok(Event::Data(vec![13]))));
/// assert_eq!(stream.next(), Some(Ok(Event::Data(vec![0]))));
/// ```
#[derive(Clone, Debug)]
pub struct Events {
    binary: bool,
    data_limit: usize,
    scanned: usize,
    count: usize,
    cr_nul: bool,
    dropping: Option<u8>,
}

impl Default for Events {
    fn default() -> Self {
        Self::new()
    }
}

impl Events {
    /// Starts in NVT mode, delivering one data byte per event.
    pub fn new() -> Self {
        Self::with_limit(1)
    }

    /// Sets the decoded data run limit, clamped to 1 through [`MAX_DATA`].
    /// Limits above 1 batch data until a command, the limit, or EOF.
    /// Subnegotiations keep their separate [`MAX_SUBNEGOTIATION`] limit.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            binary: false,
            data_limit: limit.clamp(1, MAX_DATA),
            scanned: 0,
            count: 0,
            cr_nul: false,
            dropping: None,
        }
    }

    /// Changes receive mode between items, before reading the next item.
    /// A NUL owed to an earlier NVT CR is still dropped across commands,
    /// even if a negotiation has since enabled binary mode.
    pub fn set_binary(&mut self, binary: bool) {
        self.binary = binary;
        self.scanned = 0;
        self.count = 0;
    }

    /// Whether received data is in binary mode.
    pub fn binary(&self) -> bool {
        self.binary
    }

    /// The most decoded bytes in each data item.
    pub fn limit(&self) -> usize {
        self.data_limit
    }

    fn reset_scan(&mut self) {
        self.scanned = 0;
        self.count = 0;
    }

    fn data_item(&mut self, input: &[u8]) -> Step<Event> {
        let used = self.scanned;
        let raw = input.get(..used).unwrap_or_default();
        let mut data = Vec::with_capacity(self.count);
        let mut at = 0usize;
        while let Some((byte, n)) = data_byte(raw, at, self.binary, true) {
            data.push(byte);
            at = at.saturating_add(n);
        }
        self.cr_nul = !self.binary && raw.last() == Some(&CR);
        self.reset_scan();
        Step::Item(Event::Data(data), used)
    }

    fn data(&mut self, input: &[u8], eof: bool) -> Step<Event> {
        loop {
            if self.count == self.data_limit {
                return self.data_item(input);
            }
            if let Some((_, n)) = data_byte(input, self.scanned, self.binary, eof) {
                self.scanned = self.scanned.saturating_add(n);
                self.count += 1; // Bounded by data_limit.
                continue;
            }
            let command =
                input.get(self.scanned) == Some(&IAC) && (input.get(self.scanned.saturating_add(1)).is_some() || eof);
            if self.count > 0 && (command || eof && self.scanned == input.len()) {
                return self.data_item(input);
            }
            return Step::Need;
        }
    }

    fn subnegotiation(&mut self, input: &[u8], option: u8) -> Step<Event> {
        self.scanned = self.scanned.max(3);
        loop {
            let Some(&byte) = input.get(self.scanned) else { return Step::Need };
            if byte == IAC {
                let Some(&next) = input.get(self.scanned.saturating_add(1)) else { return Step::Need };
                if next != IAC {
                    let end = self.scanned;
                    self.reset_scan();
                    if next != cmd::SE {
                        return Step::Item(Event::Error(Error::SubnegotiationInterrupted { option }), end);
                    }
                    let raw = input.get(3..end).unwrap_or_default();
                    let mut data = Vec::new();
                    let mut at = 0usize;
                    while let Some(&b) = raw.get(at) {
                        data.push(b);
                        at = at.saturating_add(if b == IAC { 2 } else { 1 });
                    }
                    return Step::Item(Event::Subnegotiation { option, data }, end.saturating_add(2));
                }
            }
            self.scanned = self.scanned.saturating_add(if byte == IAC { 2 } else { 1 });
            self.count += 1; // Stop at MAX_SUBNEGOTIATION + 1.
            if self.count > MAX_SUBNEGOTIATION {
                let used = self.scanned;
                self.reset_scan();
                self.dropping = Some(option);
                return Step::Skip(used);
            }
        }
    }

    fn discard(&mut self, input: &[u8], eof: bool, option: u8) -> Result<Step<Event>, Error> {
        let mut at = 0usize;
        while let Some(&byte) = input.get(at) {
            if byte == IAC {
                let Some(&next) = input.get(at.saturating_add(1)) else { break };
                if next != IAC {
                    self.dropping = None;
                    return Ok(if next == cmd::SE {
                        Step::Item(Event::Error(Error::SubnegotiationTooLong { option }), at.saturating_add(2))
                    } else {
                        Step::Item(Event::Error(Error::SubnegotiationInterrupted { option }), at)
                    });
                }
            }
            at = at.saturating_add(if byte == IAC { 2 } else { 1 });
        }
        if at > 0 {
            Ok(Step::Skip(at))
        } else if eof {
            Err(Error::Truncated)
        } else {
            Ok(Step::Need)
        }
    }
}

// One data byte and its wire width. Commands and partial escapes stop the scan.
fn data_byte(input: &[u8], at: usize, binary: bool, eof: bool) -> Option<(u8, usize)> {
    let &byte = input.get(at)?;
    let next = input.get(at.saturating_add(1));
    match byte {
        IAC => (next == Some(&IAC)).then_some((IAC, 2)),
        CR if !binary => match next {
            Some(&NUL) => Some((CR, 2)),
            None if !eof => None,
            _ => Some((CR, 1)),
        },
        _ => Some((byte, 1)),
    }
}

impl codec::Decode for Events {
    type Item = Event;
    type Error = Error;
    const NAME: &'static str = "Telnet";

    fn capacity(&self) -> usize {
        MAX_EVENT_WIRE.max(2 * self.data_limit)
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Event>, Error> {
        if let Some(option) = self.dropping {
            return self.discard(input, eof, option);
        }
        let Some(&first) = input.first() else { return Ok(Step::Need) };
        if first != IAC && self.cr_nul {
            self.cr_nul = false;
            if first == NUL {
                return Ok(Step::Skip(1));
            }
        }
        if first != IAC || input.get(1) == Some(&IAC) {
            return Ok(self.data(input, eof));
        }
        let Some(&command) = input.get(1) else { return Ok(Step::Need) };
        if let Some(verb) = Verb::from_byte(command) {
            let Some(&option) = input.get(2) else { return Ok(Step::Need) };
            return Ok(Step::Item(Event::Negotiation { verb, option }, 3));
        }
        if command == cmd::SB {
            let Some(&option) = input.get(2) else { return Ok(Step::Need) };
            return Ok(self.subnegotiation(input, option));
        }
        let event = if let Some(command) = Command::from_byte(command) {
            Event::Command(command)
        } else if command == cmd::SE {
            Event::Error(Error::StraySubnegotiationEnd)
        } else {
            Event::Error(Error::UnknownCommand(command))
        };
        Ok(Step::Item(event, 2))
    }
}

impl Event {
    fn parse_with(bytes: &[u8], binary: bool) -> Result<Self, Error> {
        if bytes.len() > MAX_EVENT_WIRE {
            return Err(Error::TooLong);
        }
        let mut decoder = Events::with_limit(MAX_DATA);
        decoder.set_binary(binary);
        match decoder.decode(bytes, true)? {
            Step::Item(Event::Error(e), _) => Err(e),
            Step::Item(event, used) if used == bytes.len() => Ok(event),
            Step::Item(_, _) => Err(Error::Trailing),
            Step::Skip(_) => Err(Error::TooLong),
            _ => Err(Error::Incomplete),
        }
    }

    fn write_with(&self, out: &mut Vec<u8>, binary: bool) -> Result<(), Error> {
        let limit = match self {
            Self::Data(data) if !data.is_empty() && data.len() <= MAX_DATA => data.len().checked_mul(2),
            Self::Command(_) => Some(2),
            Self::Negotiation { .. } => Some(3),
            Self::Subnegotiation { data, .. } if data.len() <= MAX_SUBNEGOTIATION => {
                data.len().checked_mul(2).and_then(|n| n.checked_add(5))
            }
            _ => return Err(Error::Unwritable),
        }
        .ok_or(Error::Unwritable)?;
        out.try_reserve(limit).map_err(|_| Error::Allocation)?;
        match self {
            Self::Data(data) => {
                for (i, &byte) in data.iter().enumerate() {
                    out.push(byte);
                    if byte == IAC {
                        out.push(IAC);
                    } else if byte == CR && !binary && data.get(i.saturating_add(1)) != Some(&LF) {
                        out.push(NUL);
                    }
                }
            }
            Self::Command(command) => out.extend_from_slice(&[IAC, command.byte()]),
            Self::Negotiation { verb, option } => out.extend_from_slice(&[IAC, verb.byte(), *option]),
            Self::Subnegotiation { option, data } => {
                out.extend_from_slice(&[IAC, cmd::SB, *option]);
                for &byte in data {
                    out.push(byte);
                    if byte == IAC {
                        out.push(IAC);
                    }
                }
                out.extend_from_slice(&[IAC, cmd::SE]);
            }
            Self::Error(_) => return Err(Error::Unwritable),
        }
        Ok(())
    }
}

impl Wire for Event {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one NVT event. Refuses diagnostics, partial units,
    /// trailing bytes, and values over [`MAX_DATA`] or [`MAX_SUBNEGOTIATION`].
    /// Input is bounded by [`MAX_EVENT_WIRE`]; use [`Events`] for longer streams.
    /// IAC escapes are undone. CR NUL becomes CR; CR LF stays unchanged.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse_with(bytes, false)
    }

    /// Writes one NVT event. Doubles IAC and follows a bare CR with NUL.
    /// Refuses empty data, diagnostics, and oversized payloads. Leaves
    /// `out` unchanged on refusal or allocation failure.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.write_with(out, false)
    }
}

/// One event encoded in Telnet binary mode. CR and NUL stay unchanged.
/// IAC escaping and command framing are the same as in NVT mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryEvent(
    /// The event carried in binary mode.
    pub Event,
);

impl Wire for BinaryEvent {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one binary event. Refuses diagnostics, partial units, trailing
    /// bytes, and values over [`MAX_DATA`] or [`MAX_SUBNEGOTIATION`].
    /// Input is bounded by [`MAX_EVENT_WIRE`]; use [`Events`] for longer streams.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Event::parse_with(bytes, true).map(Self)
    }

    /// Writes a binary event with doubled IAC bytes. Refuses empty data,
    /// diagnostics, and oversized payloads without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.0.write_with(out, true)
    }
}

impl Subnegotiation {
    /// Builds the event carrying this typed value. Refuses invalid names,
    /// known options in `Other`, and data over [`MAX_SUBNEGOTIATION`].
    pub fn to_event(&self) -> Result<Event, Error> {
        let data = match self {
            Self::TerminalTypeSend => vec![terminal_type::SEND],
            Self::TerminalTypeIs(name) => {
                if name.is_empty() || name.len() > MAX_TERMINAL_TYPE || !name.as_bytes().iter().all(is_name_byte) {
                    return Err(Error::Unwritable);
                }
                let mut data = vec![terminal_type::IS];
                data.extend_from_slice(name.as_bytes());
                data
            }
            Self::WindowSize { width, height } => {
                let [w0, w1] = width.to_be_bytes();
                let [h0, h1] = height.to_be_bytes();
                vec![w0, w1, h0, h1]
            }
            Self::Other { option, data } => {
                if matches!(*option, option::TERMINAL_TYPE | option::NAWS) || data.len() > MAX_SUBNEGOTIATION {
                    return Err(Error::Unwritable);
                }
                data.clone()
            }
        };
        Ok(Event::Subnegotiation {
            option: self.option(),
            data,
        })
    }
}

impl Wire for Subnegotiation {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete IAC SB ... IAC SE unit. Refuses other event kinds,
    /// trailing or partial units, invalid terminal names, wrong window size
    /// lengths, and oversized payloads.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Event::parse(bytes)? {
            Event::Subnegotiation { option, data } => {
                Self::parse_data(option, &data)
            }
            _ => Err(Error::UnexpectedEvent),
        }
    }

    /// Writes the typed value without changing it. Refuses known options
    /// in `Other`, invalid names, and oversized payloads. Leaves `out`
    /// unchanged on error. Temporary storage is at most [`MAX_SUBNEGOTIATION`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.to_event()?.write(out)
    }
}

/// Which end of the connection an option is about. Each option is
/// negotiated twice, once for each end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// This end does the option: DO and DONT come in, WILL and WONT go out.
    Local,
    /// The peer does the option: WILL and WONT come in, DO and DONT go out.
    Remote,
}

/// One end of one option, in the Q method of RFC 1143.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum OptionState {
    /// Off.
    #[default]
    No,
    /// On.
    Yes,
    /// This end asked to turn it off and waits for the answer. If
    /// `opposite`, it will ask to turn it on again once answered.
    WantNo {
        /// A request to turn the option back on is queued.
        opposite: bool,
    },
    /// This end asked to turn it on and waits for the answer. If
    /// `opposite`, it will ask to turn it off again once answered.
    WantYes {
        /// A request to turn the option off is queued.
        opposite: bool,
    },
}

/// An option turned on or off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Change {
    /// Which end does the option.
    pub side: Side,
    /// The option code.
    pub option: u8,
    /// Whether it is on now.
    pub enabled: bool,
}

/// What a [`Negotiation`] does in answer to a request or a command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reaction {
    /// A negotiation event to write to the connection, if any.
    pub send: Option<Event>,
    /// The option that turned on or off, if one did.
    pub change: Option<Change>,
}

/// The state of every option at both ends, negotiated with the Q method
/// of RFC 1143. It answers each WILL, WONT, DO and DONT the way RFC 854
/// asks, and never answers in a way that makes the two ends loop.
///
/// An option counts as enabled where it is in effect on the wire. This
/// end's option is enabled only in [`OptionState::Yes`]: it stops as soon
/// as it sends WONT. The peer's option is enabled in [`OptionState::Yes`]
/// and in [`OptionState::WantNo`]: after this end sends DONT, the peer
/// goes on doing the option until its WONT arrives. So a [`Change`] for
/// the remote side comes with the peer's command, at the place in the
/// stream where it takes effect.
///
/// [`option::TIMING_MARK`] is not a mode (RFC 860). Each DO TIMING-MARK
/// is answered, with WILL if this end allows it and WONT if not, and a
/// WILL that answers this end's DO ends the request. The option goes
/// back to [`OptionState::No`] each time and reports no [`Change`]. A
/// world writes the WILL after the output that came before the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiation {
    local: [OptionState; 256],
    remote: [OptionState; 256],
    allow_local: [bool; 256],
    allow_remote: [bool; 256],
}

impl Default for Negotiation {
    fn default() -> Negotiation {
        Negotiation::new()
    }
}

impl Negotiation {
    /// Every option off at both ends, and none allowed.
    pub fn new() -> Negotiation {
        Negotiation {
            local: [OptionState::No; 256],
            remote: [OptionState::No; 256],
            allow_local: [false; 256],
            allow_remote: [false; 256],
        }
    }

    /// Sets whether this end agrees to do `option` when the peer sends DO.
    pub fn allow_local(&mut self, option: u8, allow: bool) {
        self.allow_local[usize::from(option)] = allow;
    }

    /// Sets whether this end agrees to let the peer do `option` when the
    /// peer sends WILL.
    pub fn allow_remote(&mut self, option: u8, allow: bool) {
        self.allow_remote[usize::from(option)] = allow;
    }

    /// Where `option` stands for `side`.
    pub fn state(&self, side: Side, option: u8) -> OptionState {
        match side {
            Side::Local => self.local[usize::from(option)],
            Side::Remote => self.remote[usize::from(option)],
        }
    }

    /// Whether this end does `option`.
    pub fn local(&self, option: u8) -> bool {
        self.state(Side::Local, option) == OptionState::Yes
    }

    /// Whether the peer does `option`: in [`OptionState::Yes`], or in
    /// [`OptionState::WantNo`] while this end waits for its WONT.
    pub fn remote(&self, option: u8) -> bool {
        enabled(Side::Remote, self.state(Side::Remote, option))
    }

    /// Answers a negotiation command from the peer.
    pub fn receive(&mut self, verb: Verb, option: u8) -> Reaction {
        let i = usize::from(option);
        let (side, on, allowed) = match verb {
            Verb::Will => (Side::Remote, true, self.allow_remote[i]),
            Verb::Wont => (Side::Remote, false, false),
            Verb::Do => (Side::Local, true, self.allow_local[i]),
            Verb::Dont => (Side::Local, false, false),
        };
        let state = *self.slot(side, option);
        let (next, reply) = if option == option::TIMING_MARK && side == Side::Remote && on && state == OptionState::No {
            // A WILL TIMING-MARK this end did not ask for is ignored. A DO
            // in answer could make the peer send another WILL.
            (OptionState::No, Some(false))
        } else {
            received(state, on, allowed)
        };
        self.update(side, option, next, reply)
    }

    /// Asks for this end to do `option` (sends WILL), if it does not
    /// already and has not asked.
    pub fn enable_local(&mut self, option: u8) -> Reaction {
        self.ask(Side::Local, option, true)
    }

    /// Asks for this end to stop doing `option` (sends WONT).
    pub fn disable_local(&mut self, option: u8) -> Reaction {
        self.ask(Side::Local, option, false)
    }

    /// Asks the peer to do `option` (sends DO).
    pub fn enable_remote(&mut self, option: u8) -> Reaction {
        self.ask(Side::Remote, option, true)
    }

    /// Asks the peer to stop doing `option` (sends DONT).
    pub fn disable_remote(&mut self, option: u8) -> Reaction {
        self.ask(Side::Remote, option, false)
    }

    fn ask(&mut self, side: Side, option: u8, on: bool) -> Reaction {
        let state = self.slot(side, option);
        let (next, send) = asked(*state, on);
        self.update(side, option, next, send)
    }

    fn slot(&mut self, side: Side, option: u8) -> &mut OptionState {
        match side {
            Side::Local => &mut self.local[usize::from(option)],
            Side::Remote => &mut self.remote[usize::from(option)],
        }
    }

    /// Moves `side`'s `option` to `next`, and says what to send and what
    /// changed. `send` is whether to ask for the option on (`Some(true)`)
    /// or off (`Some(false)`).
    fn update(&mut self, side: Side, option: u8, next: OptionState, send: Option<bool>) -> Reaction {
        // A timing mark is never left on, so the next request is answered.
        let next = if option == option::TIMING_MARK && next == OptionState::Yes { OptionState::No } else { next };
        let slot = self.slot(side, option);
        let was = enabled(side, *slot);
        *slot = next;
        let now = enabled(side, next);
        let verb = |on: bool| match (side, on) {
            (Side::Local, true) => Verb::Will,
            (Side::Local, false) => Verb::Wont,
            (Side::Remote, true) => Verb::Do,
            (Side::Remote, false) => Verb::Dont,
        };
        Reaction {
            send: send.map(|on| Event::Negotiation { verb: verb(on), option }),
            change: (was != now).then_some(Change { side, option, enabled: now }),
        }
    }
}

/// Whether an option in `state` is in effect for `side`: see
/// [`Negotiation`].
fn enabled(side: Side, state: OptionState) -> bool {
    match side {
        Side::Local => state == OptionState::Yes,
        Side::Remote => matches!(state, OptionState::Yes | OptionState::WantNo { .. }),
    }
}

/// RFC 1143, section 7: the next state, and what to send, when the peer
/// says the option is on (`on`, WILL or DO) or off (WONT or DONT).
/// `allowed` says whether this end agrees to a new request to turn it on.
fn received(state: OptionState, on: bool, allowed: bool) -> (OptionState, Option<bool>) {
    use OptionState::*;
    match (state, on) {
        (No, true) if allowed => (Yes, Some(true)),
        (No, true) => (No, Some(false)),
        (Yes, true) => (Yes, None),
        // "DONT answered by WILL": an error the RFC settles this way.
        (WantNo { opposite: false }, true) => (No, None),
        (WantNo { opposite: true }, true) => (Yes, None),
        (WantYes { opposite: false }, true) => (Yes, None),
        (WantYes { opposite: true }, true) => (WantNo { opposite: false }, Some(false)),
        (No, false) => (No, None),
        (Yes, false) => (No, Some(false)),
        (WantNo { opposite: false }, false) => (No, None),
        (WantNo { opposite: true }, false) => (WantYes { opposite: false }, Some(true)),
        (WantYes { .. }, false) => (No, None),
    }
}

/// RFC 1143, section 7: the next state, and what to send, when this end
/// wants the option on (`on`) or off.
fn asked(state: OptionState, on: bool) -> (OptionState, Option<bool>) {
    use OptionState::*;
    match (state, on) {
        (No, true) => (WantYes { opposite: false }, Some(true)),
        (Yes, false) => (WantNo { opposite: false }, Some(false)),
        (WantNo { .. }, true) => (WantNo { opposite: true }, None),
        (WantNo { .. }, false) => (WantNo { opposite: false }, None),
        (WantYes { .. }, true) => (WantYes { opposite: false }, None),
        (WantYes { .. }, false) => (WantYes { opposite: true }, None),
        (s, _) => (s, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream, contract, finish, pump,
        test_support::{decode_all, mutate},
    };

    /// Adjacent data events joined, so streams split in different places
    /// compare equal.
    fn merged(events: Vec<Event>) -> Vec<Event> {
        let mut out: Vec<Event> = Vec::new();
        for e in events {
            if let (Event::Data(d), Some(Event::Data(last))) = (&e, out.last_mut()) {
                last.extend_from_slice(d);
                continue;
            }
            out.push(e);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Vec<Event> {
        let (events, failure) = decode_all(|| Events::with_limit(MAX_DATA), bytes);
        assert_eq!(failure, None);
        merged(events)
    }

    fn data(b: &[u8]) -> Event {
        Event::Data(b.to_vec())
    }

    // RFC 854: IAC in data is sent twice.
    #[test]
    fn iac_escaping() {
        assert_eq!(decode(&[b'a', 255, 255, b'b']), [data(&[b'a', 255, b'b'])]);
        assert_eq!(data(&[b'a', 255, b'b']).to_bytes().unwrap(), [b'a', 255, 255, b'b']);
        assert_eq!(BinaryEvent(data(&[255, 255])).to_bytes().unwrap(), [255, 255, 255, 255]);
    }

    // RFC 854: CR is followed by LF (new line) or NUL (a bare CR).
    #[test]
    fn cr_rules() {
        assert_eq!(decode(b"a\r\nb"), [data(b"a\r\nb")]);
        assert_eq!(decode(b"a\r\0b"), [data(b"a\rb")]);
        assert_eq!(decode(b"a\rb"), [data(b"a\rb")]);
        assert_eq!(decode(&[13, 255, 241]), [data(b"\r"), Event::Command(Command::Nop)]);
        let mut stream = Stream::new(Events::new());
        assert_eq!(stream.push(b"x\r"), 2);
        assert_eq!(stream.next(), Some(Ok(data(b"x"))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(b"\0"), 1);
        assert_eq!(stream.next(), Some(Ok(data(b"\r"))));
        assert_eq!(stream.push(b"\r"), 1);
        assert_eq!(stream.next(), None);
        stream.end();
        assert_eq!(stream.next(), Some(Ok(data(b"\r"))));
        assert_eq!(data(b"a\rb\r\n\r").to_bytes().unwrap(), b"a\r\0b\r\n\r\0");
        assert_eq!(BinaryEvent(data(b"\r")).to_bytes().unwrap(), b"\r");
        let mut events = Events::with_limit(MAX_DATA);
        events.set_binary(true);
        assert!(events.binary());
        assert_eq!(decode_all(|| events, b"\r\0"), (vec![data(b"\r\0")], None));
    }

    #[test]
    fn commands() {
        for b in 0..=255u8 {
            match Command::from_byte(b) {
                Some(c) => {
                    assert_eq!(c.byte(), b);
                    assert_eq!(decode(&Event::Command(c).to_bytes().unwrap()), [Event::Command(c)]);
                }
                None => assert!(b < 236 || b == cmd::SE || b >= cmd::SB, "{b}"),
            }
        }
        assert_eq!(Command::from_byte(cmd::SB), None);
        assert_eq!(
            decode(b"hi\xff\xf4there"),
            [data(b"hi"), Event::Command(Command::InterruptProcess), data(b"there")]
        );
    }

    // RFC 1184 adds EOF (236), SUSP (237) and ABORT (238), which line mode
    // clients send. They are commands, not errors.
    #[test]
    fn linemode_commands() {
        assert_eq!(decode(&[255, 236]), [Event::Command(Command::EndOfFile)]);
        assert_eq!(decode(&[255, 237]), [Event::Command(Command::Suspend)]);
        assert_eq!(decode(&[255, 238]), [Event::Command(Command::Abort)]);
        for c in [Command::EndOfFile, Command::Suspend, Command::Abort] {
            assert_eq!(Command::from_byte(c.byte()), Some(c));
        }
        assert_eq!(decode(&[255, 235]), [Event::Error(Error::UnknownCommand(235))]);
    }

    // A CR read outside binary mode drops its NUL, even if binary mode is
    // turned on before the NUL arrives.
    #[test]
    fn cr_nul_across_mode_switch() {
        let mut stream = Stream::new(Events::new());
        assert_eq!(stream.push(b"a\r\xff\xfb\0"), 5);
        assert_eq!(stream.next(), Some(Ok(data(b"a"))));
        assert_eq!(stream.next(), Some(Ok(data(b"\r"))));
        assert_eq!(
            stream.next(),
            Some(Ok(Event::Negotiation {
                verb: Verb::Will,
                option: 0
            }))
        );
        stream.decoder().set_binary(true);
        assert_eq!(stream.push(b"\0b"), 2);
        assert_eq!(stream.next(), Some(Ok(data(b"b"))));
        assert_eq!(stream.next(), None);
    }

    // Known options require their typed variants.
    #[test]
    fn other_for_typed_options() {
        for (option, data) in [
            (24, &[5][..]),
            (24, &[]),
            (24, &[1, 9]),
            (24, b"\0vt\t100"),
            (31, &[0, 80]),
            (31, &[0, 80, 0, 24, 9]),
            (24, b"\0VT100"),
        ] {
            let sub = Subnegotiation::Other { option, data: data.to_vec() };
            let mut out = vec![7];
            assert_eq!(sub.write(&mut out), Err(Error::Unwritable));
            assert_eq!(out, [7]);
            contract::check_wire_value(&sub);
        }
    }

    // EOF reports a partial subnegotiation once. A new stream starts fresh.
    #[test]
    fn eof_reports_truncation_once() {
        let mut events = Events::new();
        events.set_binary(true);
        let mut stream = Stream::new(events);
        assert_eq!(stream.push(&[255, 250, 24, 1, 2]), 5);
        stream.end();
        let failure = Fail::Truncated { unread: 5 };
        assert_eq!(stream.next(), Some(Err(failure.clone())));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&failure));
        assert!(stream.decoder().binary());
        let mut events = Events::new();
        events.set_binary(true);
        assert_eq!(
            decode_all(|| events, &[255, 250, 31, 0, 1, 0, 2, 255, 240]),
            (
                vec![Event::Subnegotiation {
                    option: 31,
                    data: vec![0, 1, 0, 2]
                }],
                None
            )
        );
    }

    #[test]
    fn negotiations() {
        for verb in [Verb::Will, Verb::Wont, Verb::Do, Verb::Dont] {
            assert_eq!(Verb::from_byte(verb.byte()), Some(verb));
            for option in [0, 1, 24, 31, 255] {
                assert_eq!(
                    decode(&Event::Negotiation { verb, option }.to_bytes().unwrap()),
                    [Event::Negotiation { verb, option }]
                );
            }
        }
        assert_eq!(Verb::from_byte(250), None);
        assert_eq!(
            Event::Negotiation {
                verb: Verb::Do,
                option: option::ECHO
            }
            .to_bytes()
            .unwrap(),
            [255, 253, 1]
        );
    }

    // RFC 1091's exchange.
    #[test]
    fn terminal_type_example() {
        let send = [255, 250, 24, 1, 255, 240];
        assert_eq!(Subnegotiation::TerminalTypeSend.to_bytes().unwrap(), send);
        assert_eq!(decode(&send), [Event::Subnegotiation { option: 24, data: vec![1] }]);
        let is = b"\xff\xfa\x18\x00DEC-VT52\xff\xf0";
        let [Event::Subnegotiation { option, data }] = &decode(is)[..] else { panic!() };
        let sub = Subnegotiation::parse_data(*option, data).unwrap();
        assert_eq!(sub, Subnegotiation::TerminalTypeIs("DEC-VT52".to_string()));
        assert_eq!(sub.to_bytes().unwrap(), is);
    }

    // RFC 1073's example: 80 by 24, then a width of 255, which is escaped.
    #[test]
    fn window_size_example() {
        let bytes = [255, 250, 31, 0, 80, 0, 24, 255, 240];
        assert_eq!(Subnegotiation::WindowSize { width: 80, height: 24 }.to_bytes().unwrap(), bytes);
        assert_eq!(decode(&bytes), [Event::Subnegotiation { option: 31, data: vec![0, 80, 0, 24] }]);
        let wide = Subnegotiation::WindowSize { width: 255, height: 0xff00 };
        let bytes = wide.to_bytes().unwrap();
        assert_eq!(bytes, [255, 250, 31, 0, 255, 255, 255, 255, 0, 255, 240]);
        let [Event::Subnegotiation { option, data }] = &decode(&bytes)[..] else { panic!() };
        assert_eq!(Subnegotiation::parse_data(*option, data), Ok(wide));
    }

    #[test]
    fn subnegotiation_parse_errors() {
        use Error::*;
        let tt = option::TERMINAL_TYPE;
        assert_eq!(Subnegotiation::parse_data(tt, &[]), Err(Empty));
        assert_eq!(Subnegotiation::parse_data(tt, &[2]), Err(UnknownCode(2)));
        assert_eq!(Subnegotiation::parse_data(tt, &[1, 0]), Err(TrailingAfterSend));
        assert_eq!(Subnegotiation::parse_data(tt, &[0]), Err(NameLength(0)));
        assert_eq!(
            Subnegotiation::parse_data(tt, &[b'A'; 42][..]).map(|_| ()),
            Err(UnknownCode(b'A'))
        );
        let mut long = vec![0];
        long.extend_from_slice(&[b'A'; 41]);
        assert_eq!(Subnegotiation::parse_data(tt, &long), Err(NameLength(41)));
        assert!(Subnegotiation::parse_data(tt, &long[..41]).is_ok());
        assert_eq!(Subnegotiation::parse_data(tt, b"\0VT\t100"), Err(NameByte(b'\t')));
        assert_eq!(Subnegotiation::parse_data(tt, b"\0VT\xc3\xa9"), Err(NameByte(0xc3)));
        assert_eq!(
            Subnegotiation::parse_data(option::NAWS, &[0, 80, 0]),
            Err(WindowSizeLength(3))
        );
        assert_eq!(
            Subnegotiation::parse_data(option::NAWS, &[0; 5]),
            Err(WindowSizeLength(5))
        );
        assert_eq!(
            Subnegotiation::parse_data(option::LINEMODE, &[1, 2]),
            Ok(Subnegotiation::Other { option: option::LINEMODE, data: vec![1, 2] })
        );
        for e in [Empty, UnknownCode(2), TrailingAfterSend, NameLength(0), NameByte(1), WindowSizeLength(3), DataTooLong(1025)]
        {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        for name in ["xterm\t256color", "", "é", &"A".repeat(100)] {
            let sub = Subnegotiation::TerminalTypeIs(name.into());
            contract::check_wire_value(&sub);
            assert_eq!(sub.to_bytes(), Err(Error::Unwritable));
        }
        let sub = Subnegotiation::TerminalTypeIs("MTTS 137".into());
        assert_eq!(Subnegotiation::parse(&sub.to_bytes().unwrap()), Ok(sub));
        let sub = Subnegotiation::Other { option: 99, data: vec![IAC; 5000] };
        assert_eq!(sub.to_bytes(), Err(Error::Unwritable));
        assert_eq!(
            Event::Error(Error::Truncated).to_bytes(),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn decode_errors() {
        use Error::*;
        assert_eq!(decode(&[b'a', 255, 7, b'b']), [data(b"a"), Event::Error(UnknownCommand(7)), data(b"b")]);
        assert_eq!(decode(&[255, 240]), [Event::Error(StraySubnegotiationEnd)]);
        // Too long: dropped, and the stream goes on.
        let mut long = vec![255, 250, 99];
        long.extend(std::iter::repeat_n(b'x', MAX_SUBNEGOTIATION + 1));
        long.extend_from_slice(&[255, 240, b'k']);
        assert_eq!(decode(&long), [Event::Error(SubnegotiationTooLong { option: 99 }), data(b"k")]);
        // Exactly the limit is fine.
        let mut fits = vec![255, 250, 99];
        fits.extend(std::iter::repeat_n(b'x', MAX_SUBNEGOTIATION));
        fits.extend_from_slice(&[255, 240]);
        assert!(matches!(&decode(&fits)[..], [Event::Subnegotiation { option: 99, .. }]));
        // Cut off by another command, which is then read.
        assert_eq!(
            decode(&[255, 250, 24, 1, 255, 241, b'z']),
            [Event::Error(SubnegotiationInterrupted { option: 24 }), Event::Command(Command::Nop), data(b"z")]
        );
        assert_eq!(
            decode(&[255, 250, 24, 1, 255, 253, 1]),
            [Event::Error(SubnegotiationInterrupted { option: 24 }), Event::Negotiation { verb: Verb::Do, option: 1 }]
        );
        // A new subnegotiation can cut off the old one.
        assert_eq!(
            decode(&[255, 250, 24, 1, 255, 250, 31, 0, 1, 0, 2, 255, 240]),
            [
                Event::Error(SubnegotiationInterrupted { option: 24 }),
                Event::Subnegotiation { option: 31, data: vec![0, 1, 0, 2] }
            ]
        );
        // Truncated, at every point inside a command.
        for bytes in [&[255][..], &[255, 251], &[255, 250], &[255, 250, 24], &[255, 250, 24, 1], &[255, 250, 24, 255]] {
            assert_eq!(decode_all(Events::new, bytes), (vec![], Some(Fail::Truncated { unread: bytes.len() })), "{bytes:?}");
        }
        for e in [UnknownCommand(1), StraySubnegotiationEnd, SubnegotiationTooLong { option: 1 }, Truncated] {
            assert!(!e.to_string().is_empty());
        }
    }

    /// A stream with one of everything.
    fn sample() -> Vec<u8> {
        let mut s = b"login: \r\n".to_vec();
        Event::Negotiation {
            verb: Verb::Will,
            option: option::ECHO,
        }
        .write(&mut s)
        .unwrap();
        s.extend_from_slice(&[b'a', 255, 255, 13, 0, b'b']);
        Subnegotiation::WindowSize { width: 255, height: 13 }
            .write(&mut s)
            .unwrap();
        Event::Command(Command::AreYouThere).write(&mut s).unwrap();
        Subnegotiation::TerminalTypeIs("VT100".into()).write(&mut s).unwrap();
        s.extend_from_slice(&[255, 7, 255, 240, 13]);
        s
    }

    #[test]
    fn partitions_and_prefixes_obey_contract() {
        let bytes = sample();
        contract::check_decode_with_alloc_limit(Events::new, &bytes, 2 * MAX_EVENT_WIRE);
        contract::check_decode_with_alloc_limit(|| Events::with_limit(MAX_DATA), &bytes, 2 * MAX_EVENT_WIRE);
        let whole = decode(&bytes);
        for cut in 0..=bytes.len() {
            let (part, _) = decode_all(|| Events::with_limit(MAX_DATA), &bytes[..cut]);
            let mut part = merged(part);
            if let Some(Event::Data(a)) = part.last() {
                let Some(Event::Data(b)) = whole.get(part.len() - 1) else { panic!("prefix {cut}") };
                assert!(b.starts_with(a), "prefix {cut}");
                part.pop();
            }
            assert_eq!(&whole[..part.len()], &part[..], "prefix {cut}");
        }
    }

    #[test]
    fn events_round_trip() {
        let events = decode(&sample());
        for binary in [false, true] {
            let mut bytes = Vec::new();
            let expected: Vec<_> = events
                .iter()
                .filter(|e| !matches!(e, Event::Error(_)))
                .cloned()
                .collect();
            for event in &expected {
                if binary {
                    BinaryEvent(event.clone()).write(&mut bytes).unwrap();
                } else {
                    event.write(&mut bytes).unwrap();
                }
            }
            let mut decoder = Events::with_limit(MAX_DATA);
            decoder.set_binary(binary);
            let (back, failure) = decode_all(|| decoder, &bytes);
            assert_eq!(failure, None);
            assert_eq!(merged(back), merged(expected));
        }
    }

    #[test]
    fn q_method_tables() {
        use OptionState::*;
        // Received WILL (or DO), allowed and not.
        assert_eq!(received(No, true, true), (Yes, Some(true)));
        assert_eq!(received(No, true, false), (No, Some(false)));
        assert_eq!(received(Yes, true, false), (Yes, None));
        assert_eq!(received(WantNo { opposite: false }, true, true), (No, None));
        assert_eq!(received(WantNo { opposite: true }, true, true), (Yes, None));
        assert_eq!(received(WantYes { opposite: false }, true, false), (Yes, None));
        assert_eq!(received(WantYes { opposite: true }, true, true), (WantNo { opposite: false }, Some(false)));
        // Received WONT (or DONT).
        assert_eq!(received(No, false, true), (No, None));
        assert_eq!(received(Yes, false, true), (No, Some(false)));
        assert_eq!(received(WantNo { opposite: false }, false, true), (No, None));
        assert_eq!(received(WantNo { opposite: true }, false, true), (WantYes { opposite: false }, Some(true)));
        assert_eq!(received(WantYes { opposite: false }, false, true), (No, None));
        assert_eq!(received(WantYes { opposite: true }, false, true), (No, None));
        // Asked to enable.
        assert_eq!(asked(No, true), (WantYes { opposite: false }, Some(true)));
        assert_eq!(asked(Yes, true), (Yes, None));
        assert_eq!(asked(WantNo { opposite: false }, true), (WantNo { opposite: true }, None));
        assert_eq!(asked(WantNo { opposite: true }, true), (WantNo { opposite: true }, None));
        assert_eq!(asked(WantYes { opposite: false }, true), (WantYes { opposite: false }, None));
        assert_eq!(asked(WantYes { opposite: true }, true), (WantYes { opposite: false }, None));
        // Asked to disable.
        assert_eq!(asked(No, false), (No, None));
        assert_eq!(asked(Yes, false), (WantNo { opposite: false }, Some(false)));
        assert_eq!(asked(WantNo { opposite: false }, false), (WantNo { opposite: false }, None));
        assert_eq!(asked(WantNo { opposite: true }, false), (WantNo { opposite: false }, None));
        assert_eq!(asked(WantYes { opposite: false }, false), (WantYes { opposite: true }, None));
        assert_eq!(asked(WantYes { opposite: true }, false), (WantYes { opposite: true }, None));
    }

    #[test]
    fn negotiation_answers() {
        let mut n = Negotiation::default();
        // Refused: DO ECHO gets WONT ECHO, WILL ECHO gets DONT ECHO.
        assert_eq!(
            n.receive(Verb::Do, 1),
            Reaction {
                send: Some(Event::Negotiation {
                    verb: Verb::Wont,
                    option: 1
                }),
                change: None
            }
        );
        assert_eq!(
            n.receive(Verb::Will, 1).send,
            Some(Event::Negotiation {
                verb: Verb::Dont,
                option: 1
            })
        );
        // Allowed: answered once, then quiet.
        n.allow_local(1, true);
        let r = n.receive(Verb::Do, 1);
        assert_eq!(r.send, Some(Event::Negotiation { verb: Verb::Will, option: 1 }));
        assert_eq!(r.change, Some(Change { side: Side::Local, option: 1, enabled: true }));
        assert!(n.local(1));
        assert_eq!(n.receive(Verb::Do, 1), Reaction::default());
        // Turned off by the peer: acknowledged.
        let r = n.receive(Verb::Dont, 1);
        assert_eq!(r.send, Some(Event::Negotiation { verb: Verb::Wont, option: 1 }));
        assert_eq!(r.change, Some(Change { side: Side::Local, option: 1, enabled: false }));
        assert_eq!(n.receive(Verb::Dont, 1), Reaction::default());
        // This end asks; the peer's answer completes it.
        assert_eq!(
            n.enable_remote(3).send,
            Some(Event::Negotiation {
                verb: Verb::Do,
                option: 3
            })
        );
        assert_eq!(n.state(Side::Remote, 3), OptionState::WantYes { opposite: false });
        assert_eq!(n.enable_remote(3), Reaction::default());
        assert_eq!(n.receive(Verb::Will, 3).send, None);
        assert!(n.remote(3));
        assert_eq!(
            n.disable_remote(3).send,
            Some(Event::Negotiation {
                verb: Verb::Dont,
                option: 3
            })
        );
        assert!(n.remote(3));
        let off = Change { side: Side::Remote, option: 3, enabled: false };
        assert_eq!(n.receive(Verb::Wont, 3), Reaction { send: None, change: Some(off) });
        assert!(!n.remote(3));
        // Asked on, then off before the answer: the answer is turned down.
        n.enable_local(5);
        n.disable_local(5);
        assert_eq!(
            n.receive(Verb::Do, 5).send,
            Some(Event::Negotiation {
                verb: Verb::Wont,
                option: 5
            })
        );
        assert_eq!(n.state(Side::Local, 5), OptionState::WantNo { opposite: false });
        assert_eq!(n.receive(Verb::Dont, 5), Reaction::default());
        assert_eq!(n.state(Side::Local, 5), OptionState::No);
    }

    // Negotiation takes effect before the following data item.
    #[test]
    fn binary_switches_at_the_command() {
        let mut n = Negotiation::new();
        n.allow_remote(option::BINARY, true);
        n.enable_remote(option::BINARY);
        let mut stream = Stream::new(Events::new());
        let bytes = [b'a', 13, 0, 255, 251, 0, 13, 0, 255, 252, 0, 13, 0];
        assert_eq!(stream.push(&bytes), bytes.len());
        let mut events = Vec::new();
        while let Some(event) = stream.next() {
            let event = event.unwrap();
            if let Event::Negotiation { verb, option } = event
                && let Some(change) = n.receive(verb, option).change
                && change.side == Side::Remote
                && change.option == option::BINARY
            {
                stream.decoder().set_binary(change.enabled);
            }
            events.push(event);
        }
        finish(&mut stream, |event| events.push(event)).unwrap();
        assert_eq!(
            merged(events),
            [
                data(b"a\r"),
                Event::Negotiation {
                    verb: Verb::Will,
                    option: 0
                },
                data(b"\r\0"),
                Event::Negotiation {
                    verb: Verb::Wont,
                    option: 0
                },
                data(b"\r")
            ]
        );
    }

    // RFC 856 and RFC 854 rule 3(c): after this end sends DONT BINARY, the
    // peer goes on sending binary data until its WONT arrives.
    #[test]
    fn remote_option_stays_on_until_the_peer_answers() {
        let mut n = Negotiation::new();
        n.allow_remote(option::BINARY, true);
        n.receive(Verb::Will, option::BINARY);
        assert!(n.remote(option::BINARY));
        let r = n.disable_remote(option::BINARY);
        assert_eq!(
            r,
            Reaction {
                send: Some(Event::Negotiation {
                    verb: Verb::Dont,
                    option: 0
                }),
                change: None
            }
        );
        assert!(n.remote(option::BINARY));
        let r = n.receive(Verb::Wont, option::BINARY);
        assert_eq!(r.change, Some(Change { side: Side::Remote, option: 0, enabled: false }));
        assert!(!n.remote(option::BINARY));
        // This end stops doing a local option as soon as it says WONT.
        n.allow_local(option::BINARY, true);
        n.receive(Verb::Do, option::BINARY);
        let r = n.disable_local(option::BINARY);
        assert_eq!(r.change, Some(Change { side: Side::Local, option: 0, enabled: false }));
        assert!(!n.local(option::BINARY));
    }

    // RFC 860: each DO TIMING-MARK asks for a new mark, so each is answered.
    #[test]
    fn timing_mark_is_answered_every_time() {
        let tm = option::TIMING_MARK;
        let mut n = Negotiation::new();
        assert_eq!(
            n.receive(Verb::Do, tm).send,
            Some(Event::Negotiation {
                verb: Verb::Wont,
                option: tm
            })
        );
        n.allow_local(tm, true);
        for _ in 0..3 {
            assert_eq!(
                n.receive(Verb::Do, tm),
                Reaction {
                    send: Some(Event::Negotiation {
                        verb: Verb::Will,
                        option: tm
                    }),
                    change: None
                }
            );
            assert_eq!(n.state(Side::Local, tm), OptionState::No);
        }
        // Asking for a mark, again and again.
        n.allow_remote(tm, true);
        for _ in 0..3 {
            assert_eq!(
                n.enable_remote(tm).send,
                Some(Event::Negotiation {
                    verb: Verb::Do,
                    option: tm
                })
            );
            assert_eq!(n.receive(Verb::Will, tm), Reaction::default());
            assert_eq!(n.state(Side::Remote, tm), OptionState::No);
        }
        // A WILL that was not asked for is ignored with DONT, so the two
        // ends cannot loop.
        assert_eq!(
            n.receive(Verb::Will, tm).send,
            Some(Event::Negotiation {
                verb: Verb::Dont,
                option: tm
            })
        );
        assert_eq!(n.state(Side::Remote, tm), OptionState::No);
    }

    // RFC 854: a command between a CR and its NUL does not change the data,
    // which is CR NUL, a bare CR.
    #[test]
    fn cr_nul_around_a_command() {
        let will_echo = Event::Negotiation { verb: Verb::Will, option: 1 };
        assert_eq!(decode(&[13, 255, 251, 1, 0, b'a']), [data(b"\r"), will_echo.clone(), data(b"a")]);
        assert_eq!(
            decode(&[13, 255, 241, 255, 241, 0]),
            [data(b"\r"), Event::Command(Command::Nop), Event::Command(Command::Nop)]
        );
        // A data byte in between ends the wait: here an escaped IAC.
        assert_eq!(decode(&[13, 255, 255, 0]), [data(&[13, 255, 0])]);
        assert_eq!(decode(&[13, 255, 251, 1, 10]), [data(b"\r"), will_echo, data(b"\n")]);
    }

    // MTTS clients send names with a space, such as "MTTS 137"; RFC 1091
    // allows any NVT ASCII string.
    #[test]
    fn terminal_type_names_with_spaces() {
        let sub = Subnegotiation::parse_data(24, b"\0MTTS 137");
        assert_eq!(sub, Ok(Subnegotiation::TerminalTypeIs("MTTS 137".into())));
        assert_eq!(
            Subnegotiation::TerminalTypeIs("MTTS 137".into()).to_event().unwrap(),
            Event::Subnegotiation {
                option: 24,
                data: b"\0MTTS 137".to_vec()
            }
        );
    }

    // Data the writer could not send whole is refused by the parser, so
    // whatever parses writes back unchanged.
    #[test]
    fn long_other_data_is_refused() {
        for len in [MAX_SUBNEGOTIATION - 1, MAX_SUBNEGOTIATION] {
            let sub = Subnegotiation::parse_data(99, &vec![7; len]).unwrap();
            assert_eq!(Subnegotiation::parse(&sub.to_bytes().unwrap()), Ok(sub));
        }
        let len = MAX_SUBNEGOTIATION + 1;
        assert_eq!(
            Subnegotiation::parse_data(99, &vec![7; len]),
            Err(Error::DataTooLong(len))
        );
        assert!(!Error::DataTooLong(len).to_string().is_empty());
    }

    /// Two peers that each ask for options and answer the other, with the
    /// commands in flight queued, must agree and go quiet.
    fn converse(rng: &mut Lcg) {
        let mut ends = [Negotiation::new(), Negotiation::new()];
        let mut wires: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        for o in 0..4u8 {
            for end in &mut ends {
                end.allow_local(o, rng.coin());
                end.allow_remote(o, rng.coin());
            }
        }
        let mut decoders = [Stream::new(Events::new()), Stream::new(Events::new())];
        for round in 0..200 {
            let who = rng.index(2);
            if round < 60 && rng.below(3) == 0 {
                let o = rng.below(4) as u8;
                let r = match rng.below(4) {
                    0 => ends[who].enable_local(o),
                    1 => ends[who].disable_local(o),
                    2 => ends[who].enable_remote(o),
                    _ => ends[who].disable_remote(o),
                };
                if let Some(reply) = r.send {
                    reply.write(&mut wires[who]).unwrap();
                }
            }
            // Deliver some of what `who` sent to the other end.
            let n = (rng.index(4)).min(wires[who].len());
            let chunk: Vec<u8> = wires[who].drain(..n).collect();
            pump(&mut decoders[1 - who], &chunk, |e| {
                let Event::Negotiation { verb, option } = e else { panic!("{e:?}") };
                let r = ends[1 - who].receive(verb, option);
                if let Some(reply) = r.send {
                    reply.write(&mut wires[1 - who]).unwrap();
                }
            })
            .unwrap();
        }
        // Drain what is left, with no new requests.
        let mut quiet = 0;
        for _ in 0..10_000 {
            if wires[0].is_empty() && wires[1].is_empty() {
                quiet += 1;
                break;
            }
            for who in 0..2 {
                let chunk = std::mem::take(&mut wires[who]);
                pump(&mut decoders[1 - who], &chunk, |e| {
                    let Event::Negotiation { verb, option } = e else { panic!() };
                    let r = ends[1 - who].receive(verb, option);
                    if let Some(reply) = r.send {
                        reply.write(&mut wires[1 - who]).unwrap();
                    }
                })
                .unwrap();
            }
        }
        assert_eq!(quiet, 1, "the ends never went quiet");
        for o in 0..4u8 {
            // Once quiet, each side's view of each option agrees, and
            // nothing is left waiting.
            assert_eq!(ends[0].state(Side::Local, o), ends[1].state(Side::Remote, o));
            assert_eq!(ends[0].state(Side::Remote, o), ends[1].state(Side::Local, o));
            for end in &ends {
                for side in [Side::Local, Side::Remote] {
                    assert!(matches!(end.state(side, o), OptionState::Yes | OptionState::No));
                }
            }
        }
    }

    #[test]
    fn generated_streams_and_negotiations() {
        let mut rng = Lcg::new(0x7e1e7);
        for _ in 0..5000 {
            let mut bytes = if rng.coin() { rng.bytes(200) } else { sample() };
            mutate(&mut rng, &mut bytes);
            let binary = rng.coin();
            let make = || {
                let mut decoder = Events::with_limit(MAX_DATA);
                decoder.set_binary(binary);
                decoder
            };
            contract::check_decode_with_alloc_limit(make, &bytes, 2 * MAX_EVENT_WIRE);
            contract::check_decode_with_held_limit(make, &bytes, 0);
            contract::check_wire::<Event>(&bytes);
            contract::check_wire::<BinaryEvent>(&bytes);
            contract::check_wire::<Subnegotiation>(&bytes);
            let (events, _) = decode_all(make, &bytes);
            let kept: Vec<_> = events.into_iter().filter(|event| !matches!(event, Event::Error(_))).collect();
            let mut written = Vec::new();
            for event in &kept {
                if binary {
                    let event = BinaryEvent(event.clone());
                    contract::check_wire_value(&event);
                    event.write(&mut written).unwrap();
                } else {
                    contract::check_wire_value(event);
                    event.write(&mut written).unwrap();
                }
                if let Event::Subnegotiation { option, data } = event
                    && let Ok(sub) = Subnegotiation::parse_data(*option, data)
                {
                    assert_eq!(sub.to_event().unwrap(), *event);
                    contract::check_wire_value(&sub);
                }
            }
            let (back, failure) = decode_all(make, &written);
            assert_eq!(failure, None);
            assert_eq!(merged(back), merged(kept));
            for option in [option::TERMINAL_TYPE, option::NAWS, option::LINEMODE] {
                if let Ok(sub) = Subnegotiation::parse_data(option, &bytes) {
                    contract::check_wire_value(&sub);
                    assert_eq!(
                        sub.to_event().unwrap(),
                        Event::Subnegotiation {
                            option,
                            data: bytes.clone()
                        }
                    );
                }
                contract::check_wire_value(&Subnegotiation::Other {
                    option,
                    data: bytes.clone(),
                });
            }
            contract::check_wire_value(&Subnegotiation::TerminalTypeIs(
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
        for _ in 0..300 {
            converse(&mut rng);
        }
    }
}
