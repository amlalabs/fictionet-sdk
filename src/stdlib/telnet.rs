//! Telnet: separating data from commands, negotiating options, and reading
//! and writing the terminal type and window size, with no I/O.
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
//! Nothing here reads a socket. A world that plays a Telnet server pushes
//! the bytes a TCP connection reads to a [`codec::Stream`] of [`Events`],
//! gets [`Event`]s back, hands each negotiation to a [`Negotiation`], and
//! writes the bytes it returns to the connection. What the server says,
//! and which options it agrees to, is up to world code.
//!
//! New sessions use [`Events`] with [`codec::Stream`]. It yields one
//! event per call so negotiation can change binary mode between items.
//! The default delivers one data byte per event immediately; batch readers
//! can use [`Events::with_data_limit`] to wait for larger runs.
//! [`Wire`] for [`Event`] uses NVT mode; [`Event::write_with`] and
//! [`Event::parse_with`] accept an explicit binary mode. The legacy
//! [`Decoder`] keeps its original behavior.
//!
//! The legacy decoder takes any bytes. A command it does not know, or a
//! subnegotiation that is cut off or too long, becomes an
//! [`Event::Error`], and the stream goes on, as it does in real servers.
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
//! assert_eq!(ask.send, Some([255, 253, 24]));
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
//! let name = Subnegotiation::parse(option, &data).unwrap();
//! assert_eq!(name, Subnegotiation::TerminalTypeIs("VT100".to_string()));
//! ```

use super::codec::{self, Decode, Step, Wire};

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

    /// The three bytes that send this verb for `option`.
    pub fn to_bytes(self, option: u8) -> [u8; 3] {
        [IAC, self.byte(), option]
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

    /// The two bytes that send this command.
    pub fn to_bytes(self) -> [u8; 2] {
        [IAC, self.byte()]
    }
}

/// What [`Events`] or a legacy [`Decoder`] found in the stream.
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
    /// A whole subnegotiation. [`Subnegotiation::parse`] reads the ones
    /// this module knows.
    Subnegotiation {
        /// The option code.
        option: u8,
        /// The bytes between the option code and IAC SE, with IAC escapes
        /// undone.
        data: Vec<u8>,
    },
    /// Bytes that break the protocol. The decoder skips them and goes on.
    Error(DecodeError),
}

impl Event {
    /// The bytes that send this event, for a world playing either end.
    /// `binary` says whether data is sent in binary mode, as in
    /// [`escape_data`]. A subnegotiation's data past
    /// [`MAX_SUBNEGOTIATION`] bytes is left out, and an error is written
    /// as nothing, so a [`Decoder`] reads back what was written.
    pub fn to_bytes(&self, binary: bool) -> Vec<u8> {
        match self {
            Event::Data(d) => escape_data(d, binary),
            Event::Command(c) => c.to_bytes().to_vec(),
            Event::Negotiation { verb, option } => verb.to_bytes(*option).to_vec(),
            Event::Subnegotiation { option, data } => subnegotiation_bytes(*option, data),
            Event::Error(_) => Vec::new(),
        }
    }
}

/// How the bytes a [`Decoder`] read break the protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
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
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnknownCommand(b) => write!(f, "IAC followed by {b}, which is no command"),
            DecodeError::StraySubnegotiationEnd => f.write_str("IAC SE with no subnegotiation open"),
            DecodeError::SubnegotiationTooLong { option } => {
                write!(f, "subnegotiation for option {option} longer than {MAX_SUBNEGOTIATION} bytes")
            }
            DecodeError::SubnegotiationInterrupted { option } => {
                write!(f, "subnegotiation for option {option} cut off by another command")
            }
            DecodeError::Truncated => f.write_str("stream ended inside a command"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Where the decoder is in the stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    Data,
    Iac,
    Verb(Verb),
    SbOption,
    Sb(u8),
    SbIac(u8),
}

/// Splits a Telnet byte stream into data, commands, negotiations and
/// subnegotiations. Feed it the bytes a connection reads, in order. It
/// holds at most one subnegotiation's [`MAX_SUBNEGOTIATION`] bytes between
/// calls, so a peer cannot make it grow.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decoder {
    state: State,
    /// A CR outside binary mode waits for the next byte: a NUL after it is
    /// dropped.
    pending_cr: bool,
    /// A CR outside binary mode was followed by a command: a NUL as the
    /// next data byte still belongs to it and is dropped.
    cr_nul: bool,
    binary: bool,
    sb: Vec<u8>,
    sb_overflow: bool,
}

impl Decoder {
    /// A decoder at the start of a stream, not in binary mode.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Sets whether the data this end receives is in binary mode (RFC
    /// 856), where CR NUL is not undone. A world turns it on and off as
    /// [`Negotiation`] reports a [`Change`] for the peer's side of
    /// [`option::BINARY`], reading with [`Decoder::feed_next`] so the
    /// switch falls right after the command that made it.
    pub fn set_binary(&mut self, binary: bool) {
        self.binary = binary;
    }

    /// Whether the decoder reads data in binary mode.
    pub fn binary(&self) -> bool {
        self.binary
    }

    /// Reads bytes from the connection and returns what they hold, in
    /// order. Data that runs up to the end of `bytes` comes back as one
    /// [`Event::Data`], so data split across calls comes in several. A CR
    /// at the very end is held until the next byte shows whether a NUL
    /// follows it.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        let mut data = Vec::new();
        for &b in bytes {
            self.step(b, &mut data, &mut out);
        }
        flush(&mut data, &mut out);
        out
    }

    /// Reads bytes up to and including the first negotiation (WILL, WONT,
    /// DO or DONT), and returns the events and how many bytes it read.
    /// With no negotiation in `bytes`, it reads them all, as
    /// [`Decoder::feed`] does.
    ///
    /// A negotiation takes effect where it sits in the stream (RFC 854),
    /// so the bytes after a WILL BINARY or WONT BINARY are in the new
    /// mode. A world that switches binary mode calls this in a loop,
    /// handles each negotiation, and calls [`Decoder::set_binary`] before
    /// it feeds the rest.
    pub fn feed_next(&mut self, bytes: &[u8]) -> (Vec<Event>, usize) {
        let mut out = Vec::new();
        let mut data = Vec::new();
        for (i, &b) in bytes.iter().enumerate() {
            self.step(b, &mut data, &mut out);
            if matches!(out.last(), Some(Event::Negotiation { .. })) {
                return (out, i + 1);
            }
        }
        flush(&mut data, &mut out);
        (out, bytes.len())
    }

    /// Ends the stream: a held CR comes back as data, and a command or
    /// subnegotiation left open is a [`DecodeError::Truncated`]. The
    /// decoder is then ready for a new stream, still in the same mode.
    pub fn finish(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        if std::mem::take(&mut self.pending_cr) {
            out.push(Event::Data(vec![CR]));
        }
        self.cr_nul = false;
        if self.state != State::Data {
            out.push(Event::Error(DecodeError::Truncated));
        }
        self.state = State::Data;
        self.sb = Vec::new();
        self.sb_overflow = false;
        out
    }

    fn step(&mut self, b: u8, data: &mut Vec<u8>, out: &mut Vec<Event>) {
        match self.state {
            State::Data => {
                if std::mem::take(&mut self.pending_cr) {
                    data.push(CR);
                    // A CR is held only outside binary mode, so its NUL
                    // is dropped even if binary mode began since.
                    if b == NUL {
                        return;
                    }
                    // Commands are not data: a NUL after them still
                    // follows the CR (RFC 854, RFC 1123 3.2.6).
                    self.cr_nul = b == IAC;
                } else if b != IAC && std::mem::take(&mut self.cr_nul) && b == NUL {
                    return;
                }
                if b == IAC {
                    self.state = State::Iac;
                } else if b == CR && !self.binary {
                    self.pending_cr = true;
                } else {
                    data.push(b);
                }
            }
            State::Iac => self.command(b, data, out),
            State::Verb(verb) => {
                self.state = State::Data;
                flush(data, out);
                out.push(Event::Negotiation { verb, option: b });
            }
            State::SbOption => {
                self.sb.clear();
                self.sb_overflow = false;
                self.state = State::Sb(b);
            }
            State::Sb(option) => {
                if b == IAC {
                    self.state = State::SbIac(option);
                } else {
                    self.sb_push(b);
                }
            }
            State::SbIac(option) => {
                if b == IAC {
                    self.sb_push(IAC);
                    self.state = State::Sb(option);
                } else if b == cmd::SE {
                    self.state = State::Data;
                    flush(data, out);
                    let body = std::mem::take(&mut self.sb);
                    if std::mem::take(&mut self.sb_overflow) {
                        out.push(Event::Error(DecodeError::SubnegotiationTooLong { option }));
                    } else {
                        out.push(Event::Subnegotiation { option, data: body });
                    }
                } else {
                    // RFC 855 leaves this open; most servers end the
                    // subnegotiation and read the command.
                    flush(data, out);
                    out.push(Event::Error(DecodeError::SubnegotiationInterrupted { option }));
                    self.sb = Vec::new();
                    self.sb_overflow = false;
                    self.command(b, data, out);
                }
            }
        }
    }

    /// Reads the byte after an IAC, outside a subnegotiation.
    fn command(&mut self, b: u8, data: &mut Vec<u8>, out: &mut Vec<Event>) {
        self.state = State::Data;
        if b == IAC {
            self.cr_nul = false;
            data.push(IAC);
        } else if let Some(verb) = Verb::from_byte(b) {
            self.state = State::Verb(verb);
        } else if b == cmd::SB {
            self.state = State::SbOption;
        } else if b == cmd::SE {
            flush(data, out);
            out.push(Event::Error(DecodeError::StraySubnegotiationEnd));
        } else if let Some(c) = Command::from_byte(b) {
            flush(data, out);
            out.push(Event::Command(c));
        } else {
            flush(data, out);
            out.push(Event::Error(DecodeError::UnknownCommand(b)));
        }
    }

    fn sb_push(&mut self, b: u8) {
        if self.sb.len() < MAX_SUBNEGOTIATION {
            self.sb.push(b);
        } else {
            self.sb_overflow = true;
        }
    }
}

/// Moves collected data into the events, if there is any.
fn flush(data: &mut Vec<u8>, out: &mut Vec<Event>) {
    if !data.is_empty() {
        out.push(Event::Data(std::mem::take(data)));
    }
}

/// Data as it goes on the wire: each IAC sent twice and, outside binary
/// mode, each CR that is not followed by LF sent as CR NUL (RFC 854). A
/// [`Decoder`] in the same mode reads back exactly `data`.
pub fn escape_data(data: &[u8], binary: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, &b) in data.iter().enumerate() {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        } else if b == CR && !binary && data.get(i + 1) != Some(&LF) {
            out.push(NUL);
        }
    }
    out
}

/// The bytes of a subnegotiation for `option`: IAC SB, the option, `data`
/// with each IAC sent twice, and IAC SE. Data past
/// [`MAX_SUBNEGOTIATION`] bytes is left out, so a [`Decoder`] accepts it.
pub fn subnegotiation_bytes(option: u8, data: &[u8]) -> Vec<u8> {
    let data = &data[..data.len().min(MAX_SUBNEGOTIATION)];
    let mut out = Vec::with_capacity(data.len() + 5);
    out.extend_from_slice(&[IAC, cmd::SB, option]);
    for &b in data {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out.extend_from_slice(&[IAC, cmd::SE]);
    out
}

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
    /// Any other option, with its data unread. [`Subnegotiation::parse`]
    /// never returns it for [`option::TERMINAL_TYPE`] or [`option::NAWS`].
    /// If a world builds one for those options, [`Subnegotiation::data`]
    /// writes the typed form, so the parser still accepts it.
    Other {
        /// The option code.
        option: u8,
        /// The data, with IAC escapes undone.
        data: Vec<u8>,
    },
}

/// Why a subnegotiation's data is not what its option calls for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubnegotiationError {
    /// A terminal type subnegotiation with no data.
    Empty,
    /// A terminal type code other than IS (0) or SEND (1).
    UnknownCode(u8),
    /// SEND followed by more bytes.
    TrailingBytes,
    /// A terminal type name that is empty or longer than
    /// [`MAX_TERMINAL_TYPE`].
    NameLength(usize),
    /// A terminal type name with a byte that is not printable ASCII or a
    /// space.
    NameByte(u8),
    /// A window size whose data is not exactly 4 bytes long.
    WindowSizeLength(usize),
    /// Data for another option longer than [`MAX_SUBNEGOTIATION`] bytes,
    /// which a [`Decoder`] never returns and the writer could not send
    /// whole.
    TooLong(usize),
}

impl std::fmt::Display for SubnegotiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubnegotiationError::Empty => f.write_str("terminal type subnegotiation with no data"),
            SubnegotiationError::UnknownCode(c) => write!(f, "terminal type code {c}, not IS or SEND"),
            SubnegotiationError::TrailingBytes => f.write_str("bytes after terminal type SEND"),
            SubnegotiationError::NameLength(n) => {
                write!(f, "terminal type name of {n} bytes, outside 1..={MAX_TERMINAL_TYPE}")
            }
            SubnegotiationError::NameByte(b) => write!(f, "byte {b} in a terminal type name"),
            SubnegotiationError::WindowSizeLength(n) => write!(f, "window size of {n} bytes, not 4"),
            SubnegotiationError::TooLong(n) => {
                write!(f, "subnegotiation data of {n} bytes, more than {MAX_SUBNEGOTIATION}")
            }
        }
    }
}

impl std::error::Error for SubnegotiationError {}

impl Subnegotiation {
    /// Reads the data of a subnegotiation for `option`, as an
    /// [`Event::Subnegotiation`] carries it.
    pub fn parse(option: u8, data: &[u8]) -> Result<Subnegotiation, SubnegotiationError> {
        match option {
            option::TERMINAL_TYPE => {
                let (&code, rest) = data.split_first().ok_or(SubnegotiationError::Empty)?;
                match code {
                    terminal_type::SEND if rest.is_empty() => Ok(Subnegotiation::TerminalTypeSend),
                    terminal_type::SEND => Err(SubnegotiationError::TrailingBytes),
                    terminal_type::IS => {
                        if rest.is_empty() || rest.len() > MAX_TERMINAL_TYPE {
                            return Err(SubnegotiationError::NameLength(rest.len()));
                        }
                        if let Some(&b) = rest.iter().find(|b| !is_name_byte(b)) {
                            return Err(SubnegotiationError::NameByte(b));
                        }
                        // Every byte is ASCII, so this is one char per byte.
                        Ok(Subnegotiation::TerminalTypeIs(rest.iter().map(|&b| char::from(b)).collect()))
                    }
                    c => Err(SubnegotiationError::UnknownCode(c)),
                }
            }
            option::NAWS => match *data {
                [w0, w1, h0, h1] => Ok(Subnegotiation::WindowSize {
                    width: u16::from_be_bytes([w0, w1]),
                    height: u16::from_be_bytes([h0, h1]),
                }),
                _ => Err(SubnegotiationError::WindowSizeLength(data.len())),
            },
            _ if data.len() > MAX_SUBNEGOTIATION => Err(SubnegotiationError::TooLong(data.len())),
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

    /// The data between the option code and IAC SE, before IAC escapes.
    /// A terminal type name keeps only its printable ASCII characters and
    /// spaces, up to [`MAX_TERMINAL_TYPE`] of them, and is "UNKNOWN" if
    /// none are left. Other data is cut to [`MAX_SUBNEGOTIATION`] bytes,
    /// which [`Subnegotiation::parse`] never returns.
    ///
    /// A [`Subnegotiation::Other`] for a terminal type or window size is
    /// written in the typed form. Terminal type data that starts with IS
    /// is a name, cleaned up as above, and any other is SEND. Window size
    /// data is cut or padded with zeros to 4 bytes.
    pub fn data(&self) -> Vec<u8> {
        match self {
            Subnegotiation::TerminalTypeSend => vec![terminal_type::SEND],
            Subnegotiation::TerminalTypeIs(name) => terminal_type_is(name.bytes()),
            Subnegotiation::WindowSize { width, height } => {
                let mut out = width.to_be_bytes().to_vec();
                out.extend_from_slice(&height.to_be_bytes());
                out
            }
            Subnegotiation::Other { option: option::TERMINAL_TYPE, data } => match data.split_first() {
                Some((&terminal_type::IS, name)) => terminal_type_is(name.iter().copied()),
                _ => vec![terminal_type::SEND],
            },
            Subnegotiation::Other { option: option::NAWS, data } => {
                let mut out = [0; 4];
                for (o, &b) in out.iter_mut().zip(data) {
                    *o = b;
                }
                out.to_vec()
            }
            Subnegotiation::Other { data, .. } => data[..data.len().min(MAX_SUBNEGOTIATION)].to_vec(),
        }
    }

    /// The whole subnegotiation's bytes: IAC SB, the option, the data with
    /// IAC escaped, and IAC SE.
    pub fn to_bytes(&self) -> Vec<u8> {
        subnegotiation_bytes(self.option(), &self.data())
    }
}

/// Whether `b` may be in a terminal type name: printable ASCII or a space.
/// RFC 1091 allows any NVT ASCII string, and MTTS clients send names such
/// as "MTTS 137".
fn is_name_byte(b: &u8) -> bool {
    (0x20..=0x7e).contains(b)
}

/// IS and a terminal type name: only its printable ASCII bytes and spaces, at most
/// [`MAX_TERMINAL_TYPE`] of them, or "UNKNOWN" if none are left.
fn terminal_type_is(name: impl Iterator<Item = u8>) -> Vec<u8> {
    let mut out = vec![terminal_type::IS];
    out.extend(name.filter(is_name_byte).take(MAX_TERMINAL_TYPE));
    if out.len() == 1 {
        out.extend_from_slice(b"UNKNOWN");
    }
    out
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
/// can use [`Self::with_data_limit`]: data runs then end at a command, the
/// configured limit, or EOF, waiting across chunk boundaries so partitioning
/// never changes the items.
/// A trailing NVT CR waits for its next byte or EOF. Scan cursors keep
/// bytewise input linear. All payload storage belongs to returned items.
///
/// Recoverable failures remain [`Event::Error`] items. As in [`Decoder`],
/// an oversized subnegotiation is discarded through IAC SE and reported
/// as [`DecodeError::SubnegotiationTooLong`]. An interrupting command yields
/// [`DecodeError::SubnegotiationInterrupted`] first, then the command on
/// the next call. Discarding holds only an option code, with no byte buffer.
/// Partial commands and subnegotiations return [`Step::Need`] at EOF for
/// [`codec::Fail::Truncated`]. EOF during an oversized discarded unit is
/// terminal [`DecodeError::Truncated`], since its prefix was consumed.
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
        Self::with_data_limit(1)
    }

    /// Sets the decoded data run limit, clamped to 1 through [`MAX_DATA`].
    /// Limits above 1 batch data until a command, the limit, or EOF.
    /// Subnegotiations keep their separate [`MAX_SUBNEGOTIATION`] limit.
    pub fn with_data_limit(limit: usize) -> Self {
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
    pub fn data_limit(&self) -> usize {
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
                        return Step::Item(Event::Error(DecodeError::SubnegotiationInterrupted { option }), end);
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

    fn discard(&mut self, input: &[u8], eof: bool, option: u8) -> Result<Step<Event>, DecodeError> {
        let mut at = 0usize;
        while let Some(&byte) = input.get(at) {
            if byte == IAC {
                let Some(&next) = input.get(at.saturating_add(1)) else { break };
                if next != IAC {
                    self.dropping = None;
                    return Ok(if next == cmd::SE {
                        Step::Item(Event::Error(DecodeError::SubnegotiationTooLong { option }), at.saturating_add(2))
                    } else {
                        Step::Item(Event::Error(DecodeError::SubnegotiationInterrupted { option }), at)
                    });
                }
            }
            at = at.saturating_add(if byte == IAC { 2 } else { 1 });
        }
        if at > 0 {
            Ok(Step::Skip(at))
        } else if eof {
            Err(DecodeError::Truncated)
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
    type Error = DecodeError;
    const NAME: &'static str = "Telnet";

    fn capacity(&self) -> usize {
        MAX_EVENT_WIRE.max(2 * self.data_limit)
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Event>, DecodeError> {
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
            Event::Error(DecodeError::StraySubnegotiationEnd)
        } else {
            Event::Error(DecodeError::UnknownCommand(command))
        };
        Ok(Step::Item(event, 2))
    }
}

/// Why a byte slice is not exactly one event or typed subnegotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventParseError {
    /// A malformed event was found.
    Decode(DecodeError),
    /// The slice has no complete event.
    Truncated,
    /// The slice contains bytes after the first event.
    Trailing,
    /// The input exceeds [`MAX_DATA`], [`MAX_SUBNEGOTIATION`], or [`MAX_EVENT_WIRE`].
    TooLong,
    /// An event of another kind was read where a typed subnegotiation was required.
    UnexpectedEvent,
    /// A typed subnegotiation has invalid data.
    Subnegotiation(SubnegotiationError),
}

impl core::fmt::Display for EventParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode(e) => e.fmt(f),
            Self::Truncated => f.write_str("incomplete Telnet event"),
            Self::Trailing => f.write_str("bytes after Telnet event"),
            Self::TooLong => f.write_str("Telnet event exceeds its wire limit"),
            Self::UnexpectedEvent => f.write_str("expected a Telnet subnegotiation"),
            Self::Subnegotiation(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for EventParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::Subnegotiation(e) => Some(e),
            _ => None,
        }
    }
}

/// Why an event or typed subnegotiation cannot be written exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The payload exceeds [`MAX_DATA`] or [`MAX_SUBNEGOTIATION`].
    TooLong,
    /// The value has no exact representation: empty data, a diagnostic,
    /// an invalid terminal name, or a known option stored as `Other`.
    Unrepresentable,
}

impl core::fmt::Display for WriteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong => f.write_str("Telnet payload exceeds its wire limit"),
            Self::Unrepresentable => f.write_str("Telnet value has no exact wire form"),
        }
    }
}

impl core::error::Error for WriteError {}

impl Event {
    /// Reads exactly one event in the given binary mode. Diagnostic error
    /// items are refused because they have no exact wire representation.
    /// Data is bounded by [`MAX_DATA`]; use [`Events`] for longer streams.
    pub fn parse_with(bytes: &[u8], binary: bool) -> Result<Self, EventParseError> {
        if bytes.len() > MAX_EVENT_WIRE {
            return Err(EventParseError::TooLong);
        }
        let mut decoder = Events::with_data_limit(MAX_DATA);
        decoder.set_binary(binary);
        match decoder
            .decode(bytes, true)
            .map_err(EventParseError::Decode)?
        {
            Step::Item(Event::Error(e), _) => Err(EventParseError::Decode(e)),
            Step::Item(event, used) if used == bytes.len() => Ok(event),
            Step::Item(_, _) => Err(EventParseError::Trailing),
            Step::Skip(_) => Err(EventParseError::TooLong),
            _ => Err(EventParseError::Truncated),
        }
    }

    /// Appends an event in the given binary mode. IAC is doubled; NVT CR
    /// handling matches [`escape_data`]. Empty data, diagnostics, and
    /// oversized values are refused before changing `out`. Temporary
    /// encoded storage is bounded by [`MAX_EVENT_WIRE`].
    pub fn write_with(&self, out: &mut Vec<u8>, binary: bool) -> Result<(), WriteError> {
        match self {
            Event::Data(data) if data.len() > MAX_DATA => return Err(WriteError::TooLong),
            Event::Data(data) if data.is_empty() => return Err(WriteError::Unrepresentable),
            Event::Subnegotiation { data, .. } if data.len() > MAX_SUBNEGOTIATION => {
                return Err(WriteError::TooLong);
            }
            Event::Error(_) => return Err(WriteError::Unrepresentable),
            _ => {}
        }
        let bytes = self.to_bytes(binary);
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Event {
    type ParseError = EventParseError;
    type WriteError = WriteError;

    /// Reads exactly one NVT event. Use [`Event::parse_with`] for binary mode.
    fn parse(bytes: &[u8]) -> Result<Self, EventParseError> {
        Self::parse_with(bytes, false)
    }

    /// Writes one NVT event transactionally. Use [`Event::write_with`] for binary mode.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        self.write_with(out, false)
    }
}

impl Wire for Subnegotiation {
    type ParseError = EventParseError;
    type WriteError = WriteError;

    /// Reads exactly one complete IAC SB ... IAC SE unit, including its option.
    fn parse(bytes: &[u8]) -> Result<Self, EventParseError> {
        match <Event as Wire>::parse(bytes)? {
            Event::Subnegotiation { option, data } => {
                Self::parse(option, &data).map_err(EventParseError::Subnegotiation)
            }
            _ => Err(EventParseError::UnexpectedEvent),
        }
    }

    /// Writes the typed value without normalizing or clipping it. Known
    /// options in `Other`, invalid names, and oversized payloads are refused.
    /// Temporary storage is bounded by [`MAX_EVENT_WIRE`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::TerminalTypeIs(name)
                if name.is_empty()
                    || name.len() > MAX_TERMINAL_TYPE
                    || !name.as_bytes().iter().all(is_name_byte) =>
            {
                return Err(WriteError::Unrepresentable);
            }
            Self::Other {
                option: option::TERMINAL_TYPE | option::NAWS,
                ..
            } => {
                return Err(WriteError::Unrepresentable);
            }
            Self::Other { data, .. } if data.len() > MAX_SUBNEGOTIATION => {
                return Err(WriteError::TooLong);
            }
            _ => {}
        }
        out.extend_from_slice(&self.to_bytes());
        Ok(())
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Reaction {
    /// Bytes to write to the connection, if any: IAC, a verb and the
    /// option.
    pub send: Option<[u8; 3]>,
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
            send: send.map(|on| verb(on).to_bytes(option)),
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
        let mut d = Decoder::new();
        let mut events = d.feed(bytes);
        events.extend(d.finish());
        merged(events)
    }

    fn bytewise(bytes: &[u8], binary: bool) -> Vec<Event> {
        let mut d = Decoder::new();
        d.set_binary(binary);
        let mut events = Vec::new();
        for b in bytes {
            events.extend(d.feed(std::slice::from_ref(b)));
        }
        events.extend(d.finish());
        merged(events)
    }

    fn data(b: &[u8]) -> Event {
        Event::Data(b.to_vec())
    }

    // RFC 854: IAC in data is sent twice.
    #[test]
    fn iac_escaping() {
        assert_eq!(decode(&[b'a', 255, 255, b'b']), [data(&[b'a', 255, b'b'])]);
        assert_eq!(escape_data(&[b'a', 255, b'b'], false), [b'a', 255, 255, b'b']);
        assert_eq!(escape_data(&[255, 255], true), [255, 255, 255, 255]);
    }

    // RFC 854: CR is followed by LF (new line) or NUL (a bare CR).
    #[test]
    fn cr_rules() {
        assert_eq!(decode(b"a\r\nb"), [data(b"a\r\nb")]);
        assert_eq!(decode(b"a\r\0b"), [data(b"a\rb")]);
        // A CR followed by anything else is kept, with that byte.
        assert_eq!(decode(b"a\rb"), [data(b"a\rb")]);
        // A CR before a command comes out before it.
        assert_eq!(decode(&[13, 255, 241]), [data(b"\r"), Event::Command(Command::Nop)]);
        // A CR at the end is held until the next byte, or until finish.
        let mut d = Decoder::new();
        assert_eq!(d.feed(b"x\r"), [data(b"x")]);
        assert_eq!(d.feed(b"\0"), [data(b"\r")]);
        assert_eq!(d.feed(b"\r"), []);
        assert_eq!(d.finish(), [data(b"\r")]);
        // Writers send a bare CR as CR NUL, and leave CR LF alone.
        assert_eq!(escape_data(b"a\rb\r\n\r", false), b"a\r\0b\r\n\r\0");
        // Binary mode leaves CR NUL alone both ways.
        assert_eq!(escape_data(b"\r", true), b"\r");
        let mut d = Decoder::new();
        d.set_binary(true);
        assert!(d.binary());
        assert_eq!(d.feed(b"\r\0"), [data(b"\r\0")]);
    }

    #[test]
    fn commands() {
        for b in 0..=255u8 {
            match Command::from_byte(b) {
                Some(c) => {
                    assert_eq!(c.byte(), b);
                    assert_eq!(decode(&c.to_bytes()), [Event::Command(c)]);
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
        assert_eq!(decode(&[255, 235]), [Event::Error(DecodeError::UnknownCommand(235))]);
    }

    // A CR read outside binary mode drops its NUL, even if binary mode is
    // turned on before the NUL arrives.
    #[test]
    fn cr_nul_across_mode_switch() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(b"a\r"), [data(b"a")]);
        d.set_binary(true);
        assert_eq!(d.feed(b"\0b"), [data(b"\rb")]);
    }

    // An Other built for a typed option is written in the typed form, so
    // the parser takes it.
    #[test]
    fn other_for_typed_options() {
        let cases: [(u8, &[u8], Subnegotiation); 6] = [
            (24, &[5], Subnegotiation::TerminalTypeSend),
            (24, &[], Subnegotiation::TerminalTypeSend),
            (24, &[1, 9], Subnegotiation::TerminalTypeSend),
            (24, b"\0vt\t100", Subnegotiation::TerminalTypeIs("vt100".into())),
            (31, &[0, 80], Subnegotiation::WindowSize { width: 80, height: 0 }),
            (31, &[0, 80, 0, 24, 9], Subnegotiation::WindowSize { width: 80, height: 24 }),
        ];
        for (option, data, typed) in cases {
            let sub = Subnegotiation::Other { option, data: data.to_vec() };
            assert_eq!(Subnegotiation::parse(option, &sub.data()), Ok(typed));
        }
        // Data that already parses is written as it is.
        let sub = Subnegotiation::Other { option: 24, data: b"\0VT100".to_vec() };
        assert_eq!(sub.data(), b"\0VT100");
    }

    // After finish, the decoder starts a new stream in the same mode.
    #[test]
    fn finish_resets() {
        let mut d = Decoder::new();
        d.set_binary(true);
        assert_eq!(d.feed(&[255, 250, 24, 1, 2]), []);
        assert_eq!(d.finish(), [Event::Error(DecodeError::Truncated)]);
        assert!(d.binary());
        assert_eq!(
            d.feed(&[255, 250, 31, 0, 1, 0, 2, 255, 240]),
            [Event::Subnegotiation { option: 31, data: vec![0, 1, 0, 2] }]
        );
        assert_eq!(d.finish(), []);
        let mut fresh = Decoder::new();
        fresh.set_binary(true);
        assert_eq!(d, fresh);
    }

    #[test]
    fn negotiations() {
        for verb in [Verb::Will, Verb::Wont, Verb::Do, Verb::Dont] {
            assert_eq!(Verb::from_byte(verb.byte()), Some(verb));
            for option in [0, 1, 24, 31, 255] {
                assert_eq!(decode(&verb.to_bytes(option)), [Event::Negotiation { verb, option }]);
            }
        }
        assert_eq!(Verb::from_byte(250), None);
        assert_eq!(Verb::Do.to_bytes(option::ECHO), [255, 253, 1]);
    }

    // RFC 1091's exchange.
    #[test]
    fn terminal_type_example() {
        let send = [255, 250, 24, 1, 255, 240];
        assert_eq!(Subnegotiation::TerminalTypeSend.to_bytes(), send);
        assert_eq!(decode(&send), [Event::Subnegotiation { option: 24, data: vec![1] }]);
        let is = b"\xff\xfa\x18\x00DEC-VT52\xff\xf0";
        let [Event::Subnegotiation { option, data }] = &decode(is)[..] else { panic!() };
        let sub = Subnegotiation::parse(*option, data).unwrap();
        assert_eq!(sub, Subnegotiation::TerminalTypeIs("DEC-VT52".to_string()));
        assert_eq!(sub.to_bytes(), is);
    }

    // RFC 1073's example: 80 by 24, then a width of 255, which is escaped.
    #[test]
    fn window_size_example() {
        let bytes = [255, 250, 31, 0, 80, 0, 24, 255, 240];
        assert_eq!(Subnegotiation::WindowSize { width: 80, height: 24 }.to_bytes(), bytes);
        assert_eq!(decode(&bytes), [Event::Subnegotiation { option: 31, data: vec![0, 80, 0, 24] }]);
        let wide = Subnegotiation::WindowSize { width: 255, height: 0xff00 };
        let bytes = wide.to_bytes();
        assert_eq!(bytes, [255, 250, 31, 0, 255, 255, 255, 255, 0, 255, 240]);
        let [Event::Subnegotiation { option, data }] = &decode(&bytes)[..] else { panic!() };
        assert_eq!(Subnegotiation::parse(*option, data), Ok(wide));
    }

    #[test]
    fn subnegotiation_parse_errors() {
        use SubnegotiationError::*;
        let tt = option::TERMINAL_TYPE;
        assert_eq!(Subnegotiation::parse(tt, &[]), Err(Empty));
        assert_eq!(Subnegotiation::parse(tt, &[2]), Err(UnknownCode(2)));
        assert_eq!(Subnegotiation::parse(tt, &[1, 0]), Err(TrailingBytes));
        assert_eq!(Subnegotiation::parse(tt, &[0]), Err(NameLength(0)));
        assert_eq!(Subnegotiation::parse(tt, &[b'A'; 42][..]).map(|_| ()), Err(UnknownCode(b'A')));
        let mut long = vec![0];
        long.extend_from_slice(&[b'A'; 41]);
        assert_eq!(Subnegotiation::parse(tt, &long), Err(NameLength(41)));
        assert!(Subnegotiation::parse(tt, &long[..41]).is_ok());
        assert_eq!(Subnegotiation::parse(tt, b"\0VT\t100"), Err(NameByte(b'\t')));
        assert_eq!(Subnegotiation::parse(tt, b"\0VT\xc3\xa9"), Err(NameByte(0xc3)));
        assert_eq!(Subnegotiation::parse(option::NAWS, &[0, 80, 0]), Err(WindowSizeLength(3)));
        assert_eq!(Subnegotiation::parse(option::NAWS, &[0; 5]), Err(WindowSizeLength(5)));
        assert_eq!(
            Subnegotiation::parse(option::LINEMODE, &[1, 2]),
            Ok(Subnegotiation::Other { option: option::LINEMODE, data: vec![1, 2] })
        );
        for e in [Empty, UnknownCode(2), TrailingBytes, NameLength(0), NameByte(1), WindowSizeLength(3), TooLong(1025)]
        {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_make_what_the_parser_accepts() {
        // Names are cleaned up, cut, or replaced.
        let cases = [("xterm\t256color", "xterm256color"), ("MTTS 137", "MTTS 137"), ("", "UNKNOWN"), ("é", "UNKNOWN")];
        for (given, written) in cases {
            let sub = Subnegotiation::TerminalTypeIs(given.to_string());
            assert_eq!(Subnegotiation::parse(24, &sub.data()), Ok(Subnegotiation::TerminalTypeIs(written.into())));
        }
        let sub = Subnegotiation::TerminalTypeIs("A".repeat(100));
        assert_eq!(sub.data().len(), 1 + MAX_TERMINAL_TYPE);
        // Long data is cut to the limit, and the decoder takes it.
        let sub = Subnegotiation::Other { option: 99, data: vec![IAC; 5000] };
        let [Event::Subnegotiation { option: 99, data }] = &decode(&sub.to_bytes())[..] else { panic!() };
        assert_eq!(data.len(), MAX_SUBNEGOTIATION);
        assert_eq!(Event::Error(DecodeError::Truncated).to_bytes(false), []);
    }

    #[test]
    fn decode_errors() {
        use DecodeError::*;
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
            assert_eq!(decode(bytes), [Event::Error(Truncated)], "{bytes:?}");
        }
        for e in [UnknownCommand(1), StraySubnegotiationEnd, SubnegotiationTooLong { option: 1 }, Truncated] {
            assert!(!e.to_string().is_empty());
        }
    }

    /// A stream with one of everything.
    fn sample() -> Vec<u8> {
        let mut s = b"login: \r\n".to_vec();
        s.extend_from_slice(&Verb::Will.to_bytes(option::ECHO));
        s.extend_from_slice(&[b'a', 255, 255, 13, 0, b'b']);
        s.extend_from_slice(&Subnegotiation::WindowSize { width: 255, height: 13 }.to_bytes());
        s.extend_from_slice(&Command::AreYouThere.to_bytes());
        s.extend_from_slice(&Subnegotiation::TerminalTypeIs("VT100".into()).to_bytes());
        s.extend_from_slice(&[255, 7, 255, 240, 13]);
        s
    }

    #[test]
    fn every_split_and_prefix() {
        let s = sample();
        let whole = decode(&s);
        assert_eq!(bytewise(&s, false), whole);
        for cut in 0..=s.len() {
            // Split in two: the same events.
            let mut d = Decoder::new();
            let mut events = d.feed(&s[..cut]);
            events.extend(d.feed(&s[cut..]));
            events.extend(d.finish());
            assert_eq!(merged(events), whole, "cut at {cut}");
            // A prefix alone: no panic, and the events it has come first.
            let mut part = decode(&s[..cut]);
            if part.last() == Some(&Event::Error(DecodeError::Truncated)) {
                part.pop();
            }
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
            let bytes: Vec<u8> = events.iter().flat_map(|e| e.to_bytes(binary)).collect();
            let mut d = Decoder::new();
            d.set_binary(binary);
            let mut back = d.feed(&bytes);
            back.extend(d.finish());
            let expected: Vec<Event> = events.iter().filter(|e| !matches!(e, Event::Error(_))).cloned().collect();
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
        assert_eq!(n.receive(Verb::Do, 1), Reaction { send: Some([255, 252, 1]), change: None });
        assert_eq!(n.receive(Verb::Will, 1).send, Some([255, 254, 1]));
        // Allowed: answered once, then quiet.
        n.allow_local(1, true);
        let r = n.receive(Verb::Do, 1);
        assert_eq!(r.send, Some([255, 251, 1]));
        assert_eq!(r.change, Some(Change { side: Side::Local, option: 1, enabled: true }));
        assert!(n.local(1));
        assert_eq!(n.receive(Verb::Do, 1), Reaction::default());
        // Turned off by the peer: acknowledged.
        let r = n.receive(Verb::Dont, 1);
        assert_eq!(r.send, Some([255, 252, 1]));
        assert_eq!(r.change, Some(Change { side: Side::Local, option: 1, enabled: false }));
        assert_eq!(n.receive(Verb::Dont, 1), Reaction::default());
        // This end asks; the peer's answer completes it.
        assert_eq!(n.enable_remote(3).send, Some([255, 253, 3]));
        assert_eq!(n.state(Side::Remote, 3), OptionState::WantYes { opposite: false });
        assert_eq!(n.enable_remote(3), Reaction::default());
        assert_eq!(n.receive(Verb::Will, 3).send, None);
        assert!(n.remote(3));
        assert_eq!(n.disable_remote(3).send, Some([255, 254, 3]));
        assert!(n.remote(3));
        let off = Change { side: Side::Remote, option: 3, enabled: false };
        assert_eq!(n.receive(Verb::Wont, 3), Reaction { send: None, change: Some(off) });
        assert!(!n.remote(3));
        // Asked on, then off before the answer: the answer is turned down.
        n.enable_local(5);
        n.disable_local(5);
        assert_eq!(n.receive(Verb::Do, 5).send, Some([255, 252, 5]));
        assert_eq!(n.state(Side::Local, 5), OptionState::WantNo { opposite: false });
        assert_eq!(n.receive(Verb::Dont, 5), Reaction::default());
        assert_eq!(n.state(Side::Local, 5), OptionState::No);
    }

    /// Reads `bytes` the way a world should: a negotiation at a time,
    /// answering each and switching binary mode on the remote side's
    /// changes before the bytes after it are read.
    fn negotiated(n: &mut Negotiation, d: &mut Decoder, mut bytes: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        while !bytes.is_empty() {
            let (got, used) = d.feed_next(bytes);
            bytes = &bytes[used..];
            for e in &got {
                if let Event::Negotiation { verb, option } = e
                    && let Some(c) = n.receive(*verb, *option).change
                    && c.side == Side::Remote
                    && c.option == option::BINARY
                {
                    d.set_binary(c.enabled);
                }
            }
            events.extend(got);
        }
        events
    }

    // RFC 854 rule 3(c): a command takes effect where it sits in the
    // stream, so binary mode starts right after the peer's WILL BINARY,
    // even within one read, and ends right after its WONT.
    #[test]
    fn binary_switches_at_the_command() {
        let will = Event::Negotiation { verb: Verb::Will, option: option::BINARY };
        let wont = Event::Negotiation { verb: Verb::Wont, option: option::BINARY };
        let mut n = Negotiation::new();
        n.allow_remote(option::BINARY, true);
        n.enable_remote(option::BINARY);
        let mut d = Decoder::new();
        let bytes = [b'a', 13, 0, 255, 251, 0, 13, 0, 255, 252, 0, 13, 0];
        let whole = [data(b"a\r"), will.clone(), data(b"\r\0"), wont, data(b"\r")];
        let mut events = negotiated(&mut n, &mut d, &bytes);
        events.extend(d.finish());
        assert_eq!(merged(events), whole);
        // Every split gives the same events.
        for cut in 0..=bytes.len() {
            let mut n = Negotiation::new();
            n.allow_remote(option::BINARY, true);
            n.enable_remote(option::BINARY);
            let mut d = Decoder::new();
            let mut events = negotiated(&mut n, &mut d, &bytes[..cut]);
            events.extend(negotiated(&mut n, &mut d, &bytes[cut..]));
            events.extend(d.finish());
            assert_eq!(merged(events), whole, "cut at {cut}");
        }
        // feed_next stops right after a negotiation.
        let mut d = Decoder::new();
        assert_eq!(d.feed_next(&[b'x', 255, 251, 0, b'y']), (vec![data(b"x"), will], 4));
        assert_eq!(d.feed_next(b"yz"), (vec![data(b"yz")], 2));
        assert_eq!(d.feed_next(&[]), (vec![], 0));
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
        assert_eq!(r, Reaction { send: Some([255, 254, 0]), change: None });
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
        assert_eq!(n.receive(Verb::Do, tm).send, Some([255, 252, tm]));
        n.allow_local(tm, true);
        for _ in 0..3 {
            assert_eq!(n.receive(Verb::Do, tm), Reaction { send: Some([255, 251, tm]), change: None });
            assert_eq!(n.state(Side::Local, tm), OptionState::No);
        }
        // Asking for a mark, again and again.
        n.allow_remote(tm, true);
        for _ in 0..3 {
            assert_eq!(n.enable_remote(tm).send, Some([255, 253, tm]));
            assert_eq!(n.receive(Verb::Will, tm), Reaction::default());
            assert_eq!(n.state(Side::Remote, tm), OptionState::No);
        }
        // A WILL that was not asked for is ignored with DONT, so the two
        // ends cannot loop.
        assert_eq!(n.receive(Verb::Will, tm).send, Some([255, 254, tm]));
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
        let sub = Subnegotiation::parse(24, b"\0MTTS 137");
        assert_eq!(sub, Ok(Subnegotiation::TerminalTypeIs("MTTS 137".into())));
        assert_eq!(Subnegotiation::TerminalTypeIs("MTTS 137".into()).data(), b"\0MTTS 137");
    }

    // Data the writer could not send whole is refused by the parser, so
    // whatever parses writes back unchanged.
    #[test]
    fn long_other_data_is_refused() {
        for len in [MAX_SUBNEGOTIATION - 1, MAX_SUBNEGOTIATION] {
            let sub = Subnegotiation::parse(99, &vec![7; len]).unwrap();
            assert_eq!(sub.data().len(), len);
        }
        let len = MAX_SUBNEGOTIATION + 1;
        assert_eq!(Subnegotiation::parse(99, &vec![7; len]), Err(SubnegotiationError::TooLong(len)));
        assert!(!SubnegotiationError::TooLong(len).to_string().is_empty());
    }

    /// A small deterministic generator, so failures repeat.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }

        /// Bytes that lean toward the ones Telnet treats specially.
        fn bytes(&mut self, max: u32) -> Vec<u8> {
            const SPECIAL: [u8; 12] = [255, 255, 255, 250, 240, 251, 253, 13, 13, 10, 0, 24];
            let len = self.below(max);
            (0..len)
                .map(|_| if self.below(2) == 0 { SPECIAL[self.below(12) as usize] } else { self.below(256) as u8 })
                .collect()
        }
    }

    /// Two peers that each ask for options and answer the other, with the
    /// commands in flight queued, must agree and go quiet.
    fn converse(rng: &mut Lcg) {
        let mut ends = [Negotiation::new(), Negotiation::new()];
        let mut wires: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        for o in 0..4u8 {
            for end in &mut ends {
                end.allow_local(o, rng.below(2) == 0);
                end.allow_remote(o, rng.below(2) == 0);
            }
        }
        let mut decoders = [Decoder::new(), Decoder::new()];
        for round in 0..200 {
            let who = rng.below(2) as usize;
            if round < 60 && rng.below(3) == 0 {
                let o = rng.below(4) as u8;
                let r = match rng.below(4) {
                    0 => ends[who].enable_local(o),
                    1 => ends[who].disable_local(o),
                    2 => ends[who].enable_remote(o),
                    _ => ends[who].disable_remote(o),
                };
                wires[who].extend(r.send.into_iter().flatten());
            }
            // Deliver some of what `who` sent to the other end.
            let n = (rng.below(4) as usize).min(wires[who].len());
            let chunk: Vec<u8> = wires[who].drain(..n).collect();
            for e in decoders[1 - who].feed(&chunk) {
                let Event::Negotiation { verb, option } = e else { panic!("{e:?}") };
                let r = ends[1 - who].receive(verb, option);
                wires[1 - who].extend(r.send.into_iter().flatten());
            }
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
                for e in decoders[1 - who].feed(&chunk) {
                    let Event::Negotiation { verb, option } = e else { panic!() };
                    let r = ends[1 - who].receive(verb, option);
                    wires[1 - who].extend(r.send.into_iter().flatten());
                }
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
    fn lcg_fuzz() {
        let mut rng = Lcg(0x7e1e7);
        for _ in 0..5000 {
            let bytes = rng.bytes(200);
            let binary = rng.below(4) == 0;
            let mut d = Decoder::new();
            d.set_binary(binary);
            let mut whole = d.feed(&bytes);
            whole.extend(d.finish());
            let whole = merged(whole);
            assert_eq!(bytewise(&bytes, binary), whole);
            // Random chunks.
            let mut d = Decoder::new();
            d.set_binary(binary);
            let mut chunked = Vec::new();
            let mut rest = &bytes[..];
            while !rest.is_empty() {
                let n = (rng.below(8) as usize + 1).min(rest.len());
                chunked.extend(d.feed(&rest[..n]));
                rest = &rest[n..];
            }
            chunked.extend(d.finish());
            assert_eq!(merged(chunked), whole);
            // Written back, the events read back the same, less errors.
            let written: Vec<u8> = whole.iter().flat_map(|e| e.to_bytes(binary)).collect();
            let mut d = Decoder::new();
            d.set_binary(binary);
            let mut back = d.feed(&written);
            back.extend(d.finish());
            let expected: Vec<Event> = whole.iter().filter(|e| !matches!(e, Event::Error(_))).cloned().collect();
            assert_eq!(merged(back), merged(expected));
            // Typed subnegotiations write back what they read.
            let mut n = Negotiation::new();
            n.allow_local(1, true);
            n.allow_remote(3, true);
            for e in &whole {
                match e {
                    Event::Subnegotiation { option, data } => {
                        if let Ok(sub) = Subnegotiation::parse(*option, data) {
                            assert_eq!(&sub.data(), data);
                            let [Event::Subnegotiation { option: o2, data: d2 }] = &decode(&sub.to_bytes())[..] else {
                                panic!()
                            };
                            assert_eq!(Subnegotiation::parse(*o2, d2), Ok(sub));
                        }
                    }
                    Event::Negotiation { verb, option } => {
                        if let Some(reply) = n.receive(*verb, *option).send {
                            assert!(matches!(&decode(&reply)[..], [Event::Negotiation { .. }]));
                        }
                    }
                    _ => {}
                }
            }
            // Any bytes as subnegotiation data, read and written.
            for option in [option::TERMINAL_TYPE, option::NAWS, option::LINEMODE] {
                if let Ok(sub) = Subnegotiation::parse(option, &bytes) {
                    assert_eq!(sub.data(), bytes);
                }
                let other = Subnegotiation::Other { option, data: bytes.clone() };
                assert!(Subnegotiation::parse(option, &other.data()).is_ok());
                let name = Subnegotiation::TerminalTypeIs(String::from_utf8_lossy(&bytes).into_owned());
                assert!(Subnegotiation::parse(option::TERMINAL_TYPE, &name.data()).is_ok());
            }
        }
        for _ in 0..300 {
            converse(&mut rng);
        }
    }
}
