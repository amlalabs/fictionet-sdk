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
//! Nothing here reads a socket. A world that plays a Telnet server feeds
//! the bytes a TCP connection reads to a [`Decoder`], gets [`Event`]s back,
//! hands each negotiation to a [`Negotiation`], and writes the bytes it
//! returns to the connection. What the server says, and which options it
//! agrees to, is up to world code.
//!
//! The decoder takes any bytes. A command it does not know, or a
//! subnegotiation that is cut off or too long, becomes an
//! [`Event::Error`], and the stream goes on, as it does in real servers.
//!
//! ```
//! use fictionet::stdlib::telnet::{option, Change, Decoder, Event, Negotiation, Side, Subnegotiation, Verb};
//!
//! // The server agrees to let the client send its terminal type.
//! let mut options = Negotiation::new();
//! options.allow_remote(option::TERMINAL_TYPE, true);
//! // It asks the client to: IAC DO TERMINAL-TYPE.
//! let ask = options.enable_remote(option::TERMINAL_TYPE);
//! assert_eq!(ask.send, Some([255, 253, 24]));
//!
//! // The client agrees (IAC WILL TERMINAL-TYPE) and types "ls", CR LF.
//! let mut decoder = Decoder::new();
//! let events = decoder.feed(&[255, 251, 24, b'l', b's', 13, 10]);
//! assert_eq!(events[0], Event::Negotiation { verb: Verb::Will, option: option::TERMINAL_TYPE });
//! assert_eq!(events[1], Event::Data(b"ls\r\n".to_vec()));
//!
//! // The WILL answers the DO, so nothing more is sent, and the option is on.
//! let reaction = options.receive(Verb::Will, option::TERMINAL_TYPE);
//! assert_eq!(reaction.send, None);
//! assert_eq!(reaction.change, Some(Change { side: Side::Remote, option: option::TERMINAL_TYPE, enabled: true }));
//!
//! // The server asks for the name, and the client sends it.
//! assert_eq!(Subnegotiation::TerminalTypeSend.to_bytes(), [255, 250, 24, 1, 255, 240]);
//! let events = decoder.feed(b"\xff\xfa\x18\x00VT100\xff\xf0");
//! let Event::Subnegotiation { option, data } = &events[0] else { panic!() };
//! let name = Subnegotiation::parse(*option, data).unwrap();
//! assert_eq!(name, Subnegotiation::TerminalTypeIs("VT100".to_string()));
//! ```

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

/// What a [`Decoder`] found in the stream.
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
    /// 856), where CR NUL is not undone. A world turns it on when the
    /// peer's side of [`option::BINARY`] is enabled.
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

    /// Ends the stream: a held CR comes back as data, and a command or
    /// subnegotiation left open is a [`DecodeError::Truncated`]. The
    /// decoder is then ready for a new stream, still in the same mode.
    pub fn finish(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        if std::mem::take(&mut self.pending_cr) {
            out.push(Event::Data(vec![CR]));
        }
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
    /// to [`MAX_TERMINAL_TYPE`] printable ASCII characters, such as
    /// "VT100" or "XTERM". Names are case-insensitive.
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
    /// A terminal type name with a byte that is not printable ASCII.
    NameByte(u8),
    /// A window size whose data is not exactly 4 bytes long.
    WindowSizeLength(usize),
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
                        if let Some(&b) = rest.iter().find(|b| !b.is_ascii_graphic()) {
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
    /// A terminal type name keeps only its printable ASCII characters, up
    /// to [`MAX_TERMINAL_TYPE`] of them, and is "UNKNOWN" if none are
    /// left. Other data is cut to [`MAX_SUBNEGOTIATION`] bytes.
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

/// IS and a terminal type name: only its printable ASCII bytes, at most
/// [`MAX_TERMINAL_TYPE`] of them, or "UNKNOWN" if none are left.
fn terminal_type_is(name: impl Iterator<Item = u8>) -> Vec<u8> {
    let mut out = vec![terminal_type::IS];
    out.extend(name.filter(u8::is_ascii_graphic).take(MAX_TERMINAL_TYPE));
    if out.len() == 1 {
        out.extend_from_slice(b"UNKNOWN");
    }
    out
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
/// asks, and never answers in a way that makes the two ends loop. An
/// option counts as enabled only in [`OptionState::Yes`].
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

    /// Whether the peer does `option`.
    pub fn remote(&self, option: u8) -> bool {
        self.state(Side::Remote, option) == OptionState::Yes
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
        let state = self.slot(side, option);
        let (next, reply) = received(*state, on, allowed);
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
        let slot = self.slot(side, option);
        let was = *slot == OptionState::Yes;
        *slot = next;
        let now = next == OptionState::Yes;
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
            (24, b"\0vt 100", Subnegotiation::TerminalTypeIs("vt100".into())),
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
        assert_eq!(Subnegotiation::parse(tt, b"\0VT 100"), Err(NameByte(b' ')));
        assert_eq!(Subnegotiation::parse(tt, b"\0VT\xc3\xa9"), Err(NameByte(0xc3)));
        assert_eq!(Subnegotiation::parse(option::NAWS, &[0, 80, 0]), Err(WindowSizeLength(3)));
        assert_eq!(Subnegotiation::parse(option::NAWS, &[0; 5]), Err(WindowSizeLength(5)));
        assert_eq!(
            Subnegotiation::parse(option::LINEMODE, &[1, 2]),
            Ok(Subnegotiation::Other { option: option::LINEMODE, data: vec![1, 2] })
        );
        for e in [Empty, UnknownCode(2), TrailingBytes, NameLength(0), NameByte(1), WindowSizeLength(3)] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_make_what_the_parser_accepts() {
        // Names are cleaned up, cut, or replaced.
        let cases = [("xterm 256color", "xterm256color"), ("", "UNKNOWN"), ("é", "UNKNOWN")];
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
        assert_eq!(n.receive(Verb::Wont, 3), Reaction::default());
        assert!(!n.remote(3));
        // Asked on, then off before the answer: the answer is turned down.
        n.enable_local(5);
        n.disable_local(5);
        assert_eq!(n.receive(Verb::Do, 5).send, Some([255, 252, 5]));
        assert_eq!(n.state(Side::Local, 5), OptionState::WantNo { opposite: false });
        assert_eq!(n.receive(Verb::Dont, 5), Reaction::default());
        assert_eq!(n.state(Side::Local, 5), OptionState::No);
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
