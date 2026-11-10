//! Connection payloads for channels, forwarding and session requests.
//!
//! These codecs perform no I/O and grant no access. The caller owns channel
//! identifiers, window accounting and permission to execute or forward.

use super::auth::{Payload, name, reader, rest};
use super::{Error, MAX_PAYLOAD, Reader};
use fictionet::stdlib::codec::{Heap, HeapBound, Wire, most_list_places};

/// Extended channel data type for standard error.
pub const STDERR: u32 = 1;

/// A TCP endpoint pair carried by a forwarding channel open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpIp {
    /// Destination or listening address.
    pub host: String,
    /// Destination or listening port.
    pub port: u32,
    /// Originating address.
    pub originator: String,
    /// Originating port.
    pub originator_port: u32,
}

/// Channel type and its opening fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenKind {
    /// A shell, command or subsystem session.
    Session,
    /// A client requests a connection through the server.
    DirectTcpIp(TcpIp),
    /// A server reports a connection to a forwarded listener.
    ForwardedTcpIp(TcpIp),
    /// An extension interpreted by the caller.
    Other {
        /// Channel type name.
        name: String,
        /// Type specific fields.
        data: Vec<u8>,
    },
}

/// A request outside any channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GlobalRequest {
    /// Start listening on the requested address and port.
    TcpIpForward {
        /// Address to bind.
        address: String,
        /// Port, or zero to allocate one.
        port: u32,
    },
    /// Stop listening on a previously forwarded address and port.
    CancelTcpIpForward {
        /// Previously bound address.
        address: String,
        /// Previously bound port.
        port: u32,
    },
    /// An extension interpreted by the caller.
    Other {
        /// Request name.
        name: String,
        /// Request specific fields.
        data: Vec<u8>,
    },
}

/// A terminal mode opcode and its value. Opcodes one through one hundred
/// fifty nine carry values; zero terminates the mode list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalMode {
    /// Terminal mode opcode.
    pub opcode: u8,
    /// Mode setting or baud rate.
    pub value: u32,
}

/// Terminal dimensions shared by allocation and resize requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dimensions {
    /// Character columns.
    pub columns: u32,
    /// Character rows.
    pub rows: u32,
    /// Pixel width, or zero if unknown.
    pub pixel_width: u32,
    /// Pixel height, or zero if unknown.
    pub pixel_height: u32,
}

/// A typed session request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionRequest {
    /// Allocate a pseudo terminal.
    Pty {
        /// Terminal type.
        terminal: String,
        /// Initial terminal dimensions.
        dimensions: Dimensions,
        /// Terminal settings in wire order. Decoding stops at a terminator or
        /// an opcode whose encoding is not defined by the base protocol.
        modes: Vec<TerminalMode>,
    },
    /// Start the user's shell.
    Shell,
    /// Execute command bytes.
    Exec(Vec<u8>),
    /// Set an environment variable.
    Env {
        /// Variable name.
        name: Vec<u8>,
        /// Variable value.
        value: Vec<u8>,
    },
    /// Start a named subsystem.
    Subsystem(String),
    /// Resize the terminal.
    WindowChange(Dimensions),
    /// Deliver a signal, without a `SIG` prefix.
    Signal(String),
    /// Report process exit status.
    ExitStatus(u32),
    /// Report termination by signal.
    ExitSignal {
        /// Signal name without `SIG`.
        signal: String,
        /// Whether a core dump was produced.
        core_dumped: bool,
        /// Human readable detail.
        message: String,
        /// Language tag.
        language: String,
    },
    /// An extension interpreted by the caller.
    Other {
        /// Request name.
        name: String,
        /// Request specific fields.
        data: Vec<u8>,
    },
}

/// Connection messages represented as transport payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// A connection wide request.
    GlobalRequest {
        /// Whether a success or failure reply is required.
        want_reply: bool,
        /// Request fields.
        request: GlobalRequest,
    },
    /// A successful global request, with request specific response fields.
    RequestSuccess(Vec<u8>),
    /// A failed global request.
    RequestFailure,
    /// Ask to open a channel.
    ChannelOpen {
        /// Sender's channel identifier.
        sender: u32,
        /// Initial receive window.
        window: u32,
        /// Maximum received data packet length.
        max_packet: u32,
        /// Channel type and fields.
        kind: OpenKind,
    },
    /// Accept a channel.
    ChannelOpenConfirmation {
        /// Peer's channel identifier.
        recipient: u32,
        /// Sender's channel identifier.
        sender: u32,
        /// Initial receive window.
        window: u32,
        /// Maximum received data packet length.
        max_packet: u32,
        /// Channel type specific fields.
        data: Vec<u8>,
    },
    /// Refuse a channel.
    ChannelOpenFailure {
        /// Peer's channel identifier.
        recipient: u32,
        /// Reason code, including extension values.
        reason: u32,
        /// Human readable description.
        description: String,
        /// Language tag.
        language: String,
    },
    /// Add credit to a channel's send window.
    WindowAdjust {
        /// Peer's channel identifier.
        recipient: u32,
        /// Additional credit.
        bytes: u32,
    },
    /// Ordinary channel data.
    Data {
        /// Peer's channel identifier.
        recipient: u32,
        /// Data bytes.
        data: Vec<u8>,
    },
    /// Extended data, with kind one denoting standard error.
    ExtendedData {
        /// Peer's channel identifier.
        recipient: u32,
        /// Extended data type code.
        kind: u32,
        /// Data bytes.
        data: Vec<u8>,
    },
    /// No more data will be sent to this channel.
    Eof(u32),
    /// Close this channel, acknowledging a peer close if one arrived.
    Close(u32),
    /// A request within a channel.
    ChannelRequest {
        /// Peer's channel identifier.
        recipient: u32,
        /// Whether a success or failure reply is required.
        want_reply: bool,
        /// Request fields.
        request: SessionRequest,
    },
    /// Successful channel request for this recipient.
    ChannelSuccess(u32),
    /// Failed channel request for this recipient.
    ChannelFailure(u32),
}

fictionet::heap_of! {
    TcpIp { host, port, originator, originator_port }
    TerminalMode { opcode, value }
    Dimensions { columns, rows, pixel_width, pixel_height }
}

impl Heap for OpenKind {
    fn heap(&self) -> usize {
        match self {
            Self::Session => 0,
            Self::DirectTcpIp(ends) | Self::ForwardedTcpIp(ends) => ends.heap(),
            Self::Other { name, data } => name.heap() + data.heap(),
        }
    }
}

impl Heap for GlobalRequest {
    fn heap(&self) -> usize {
        match self {
            Self::TcpIpForward { address, port: _ }
            | Self::CancelTcpIpForward { address, port: _ } => address.heap(),
            Self::Other { name, data } => name.heap() + data.heap(),
        }
    }
}

impl Heap for SessionRequest {
    fn heap(&self) -> usize {
        match self {
            Self::Pty {
                terminal,
                dimensions,
                modes,
            } => terminal.heap() + dimensions.heap() + modes.heap(),
            Self::Shell | Self::WindowChange(_) | Self::ExitStatus(_) => 0,
            Self::Exec(command) => command.heap(),
            Self::Env { name, value } => name.heap() + value.heap(),
            Self::Subsystem(name) | Self::Signal(name) => name.heap(),
            Self::ExitSignal {
                signal,
                core_dumped: _,
                message,
                language,
            } => signal.heap() + message.heap() + language.heap(),
            Self::Other { name, data } => name.heap() + data.heap(),
        }
    }
}

impl Heap for Message {
    fn heap(&self) -> usize {
        match self {
            Self::GlobalRequest {
                want_reply: _,
                request,
            } => request.heap(),
            Self::RequestSuccess(data) => data.heap(),
            Self::ChannelOpen { kind, .. } => kind.heap(),
            Self::ChannelOpenConfirmation { data, .. } => data.heap(),
            Self::ChannelOpenFailure {
                description,
                language,
                ..
            } => description.heap() + language.heap(),
            Self::Data { data, .. } | Self::ExtendedData { data, .. } => data.heap(),
            Self::ChannelRequest { request, .. } => request.heap(),
            Self::RequestFailure
            | Self::WindowAdjust { .. }
            | Self::Eof(_)
            | Self::Close(_)
            | Self::ChannelSuccess(_)
            | Self::ChannelFailure(_) => 0,
        }
    }
}

/// Every string of a message, the request or channel type's name among
/// them while it is read, copies distinct bytes of the payload, made
/// whole: together at most the payload's length. A terminal request also
/// has places for its modes, each taking five bytes, in a vector grown by
/// pushes. Channel data holds only its bytes.
impl HeapBound for Message {
    fn most_heap(len: usize) -> usize {
        len + most_list_places::<TerminalMode>(len, 5)
    }
    fn most_heap_of(payload: &[u8]) -> usize {
        match payload.first() {
            Some(98) => Self::most_heap(payload.len()),
            Some(82 | 93 | 96 | 97 | 99 | 100) => 0,
            _ => payload.len(),
        }
    }
}

impl Dimensions {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            columns: r.uint32()?,
            rows: r.uint32()?,
            pixel_width: r.uint32()?,
            pixel_height: r.uint32()?,
        })
    }
    fn write(&self, w: &mut Payload<'_>) -> Result<(), Error> {
        w.uint32(self.columns)?;
        w.uint32(self.rows)?;
        w.uint32(self.pixel_width)?;
        w.uint32(self.pixel_height)
    }
}

impl TcpIp {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            host: r.text(MAX_PAYLOAD)?,
            port: r.uint32()?,
            originator: r.text(MAX_PAYLOAD)?,
            originator_port: r.uint32()?,
        })
    }
    fn write(&self, w: &mut Payload<'_>) -> Result<(), Error> {
        w.string(self.host.as_bytes())?;
        w.uint32(self.port)?;
        w.string(self.originator.as_bytes())?;
        w.uint32(self.originator_port)
    }
}

impl SessionRequest {
    fn name(&self) -> &str {
        match self {
            Self::Pty { .. } => "pty-req",
            Self::Shell => "shell",
            Self::Exec(_) => "exec",
            Self::Env { .. } => "env",
            Self::Subsystem(_) => "subsystem",
            Self::WindowChange(_) => "window-change",
            Self::Signal(_) => "signal",
            Self::ExitStatus(_) => "exit-status",
            Self::ExitSignal { .. } => "exit-signal",
            Self::Other { name, .. } => name,
        }
    }

    fn read(request: String, r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match request.as_str() {
            "pty-req" => {
                let terminal = r.text(MAX_PAYLOAD)?;
                let dimensions = Dimensions::read(r)?;
                let mut modes_reader = Reader::new(r.string()?);
                let mut modes = Vec::new();
                loop {
                    let opcode = modes_reader.byte()?;
                    if opcode == 0 || opcode >= 160 {
                        break;
                    }
                    modes.push(TerminalMode {
                        opcode,
                        value: modes_reader.uint32()?,
                    });
                }
                Self::Pty {
                    terminal,
                    dimensions,
                    modes,
                }
            }
            "shell" => Self::Shell,
            "exec" => Self::Exec(r.string()?.to_vec()),
            "env" => Self::Env {
                name: r.string()?.to_vec(),
                value: r.string()?.to_vec(),
            },
            "subsystem" => Self::Subsystem(r.text(MAX_PAYLOAD)?),
            "window-change" => Self::WindowChange(Dimensions::read(r)?),
            "signal" => Self::Signal(name(r)?),
            "exit-status" => Self::ExitStatus(r.uint32()?),
            "exit-signal" => Self::ExitSignal {
                signal: name(r)?,
                core_dumped: r.boolean()?,
                message: r.text(MAX_PAYLOAD)?,
                language: r.text(MAX_PAYLOAD)?,
            },
            _ => Self::Other {
                name: request,
                data: rest(r),
            },
        })
    }

    fn write(&self, w: &mut Payload<'_>) -> Result<(), Error> {
        match self {
            Self::Pty {
                terminal,
                dimensions,
                modes,
            } => {
                w.string(terminal.as_bytes())?;
                dimensions.write(w)?;
                if modes.len() > (MAX_PAYLOAD - 1) / 5
                    || modes
                        .iter()
                        .any(|mode| mode.opcode == 0 || mode.opcode >= 160)
                {
                    return Err(Error::Unwritable);
                }
                // The modes as one string, written in place: each opcode
                // and its value, then the terminator.
                w.uint32((modes.len() * 5 + 1) as u32)?;
                for mode in modes {
                    w.byte(mode.opcode)?;
                    w.uint32(mode.value)?;
                }
                w.byte(0)?;
            }
            Self::Shell => (),
            Self::Exec(command) => w.string(command)?,
            Self::Env { name, value } => {
                w.string(name)?;
                w.string(value)?;
            }
            Self::Subsystem(subsystem) => w.string(subsystem.as_bytes())?,
            Self::WindowChange(dimensions) => dimensions.write(w)?,
            Self::Signal(signal) => w.name(signal)?,
            Self::ExitStatus(status) => w.uint32(*status)?,
            Self::ExitSignal {
                signal,
                core_dumped,
                message,
                language,
            } => {
                w.name(signal)?;
                w.byte(u8::from(*core_dumped))?;
                w.string(message.as_bytes())?;
                w.string(language.as_bytes())?;
            }
            Self::Other { name, data } => {
                if matches!(
                    name.as_str(),
                    "pty-req"
                        | "shell"
                        | "exec"
                        | "env"
                        | "subsystem"
                        | "window-change"
                        | "signal"
                        | "exit-status"
                        | "exit-signal"
                ) {
                    return Err(Error::Unwritable);
                }
                w.raw(data)?;
            }
        }
        Ok(())
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(payload: &[u8]) -> Result<Self, Error> {
        let mut r = reader(payload)?;
        let message = match r.byte()? {
            80 => {
                let request = name(&mut r)?;
                let want_reply = r.boolean()?;
                let request = match request.as_str() {
                    "tcpip-forward" => GlobalRequest::TcpIpForward {
                        address: r.text(MAX_PAYLOAD)?,
                        port: r.uint32()?,
                    },
                    "cancel-tcpip-forward" => GlobalRequest::CancelTcpIpForward {
                        address: r.text(MAX_PAYLOAD)?,
                        port: r.uint32()?,
                    },
                    _ => GlobalRequest::Other {
                        name: request,
                        data: rest(&mut r),
                    },
                };
                Self::GlobalRequest {
                    want_reply,
                    request,
                }
            }
            81 => Self::RequestSuccess(rest(&mut r)),
            82 => Self::RequestFailure,
            90 => {
                let kind = name(&mut r)?;
                let sender = r.uint32()?;
                let window = r.uint32()?;
                let max_packet = r.uint32()?;
                let kind = match kind.as_str() {
                    "session" => OpenKind::Session,
                    "direct-tcpip" => OpenKind::DirectTcpIp(TcpIp::read(&mut r)?),
                    "forwarded-tcpip" => OpenKind::ForwardedTcpIp(TcpIp::read(&mut r)?),
                    _ => OpenKind::Other {
                        name: kind,
                        data: rest(&mut r),
                    },
                };
                Self::ChannelOpen {
                    sender,
                    window,
                    max_packet,
                    kind,
                }
            }
            91 => Self::ChannelOpenConfirmation {
                recipient: r.uint32()?,
                sender: r.uint32()?,
                window: r.uint32()?,
                max_packet: r.uint32()?,
                data: rest(&mut r),
            },
            92 => Self::ChannelOpenFailure {
                recipient: r.uint32()?,
                reason: r.uint32()?,
                description: r.text(MAX_PAYLOAD)?,
                language: r.text(MAX_PAYLOAD)?,
            },
            93 => Self::WindowAdjust {
                recipient: r.uint32()?,
                bytes: r.uint32()?,
            },
            94 => Self::Data {
                recipient: r.uint32()?,
                data: r.string()?.to_vec(),
            },
            95 => Self::ExtendedData {
                recipient: r.uint32()?,
                kind: r.uint32()?,
                data: r.string()?.to_vec(),
            },
            96 => Self::Eof(r.uint32()?),
            97 => Self::Close(r.uint32()?),
            98 => {
                let recipient = r.uint32()?;
                let request = name(&mut r)?;
                let want_reply = r.boolean()?;
                Self::ChannelRequest {
                    recipient,
                    want_reply,
                    request: SessionRequest::read(request, &mut r)?,
                }
            }
            99 => Self::ChannelSuccess(r.uint32()?),
            100 => Self::ChannelFailure(r.uint32()?),
            _ => return Err(Error::Unwritable),
        };
        r.finish()?;
        Ok(message)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = Payload::new(
            out,
            match self {
                Self::GlobalRequest { .. } => 80,
                Self::RequestSuccess(_) => 81,
                Self::RequestFailure => 82,
                Self::ChannelOpen { .. } => 90,
                Self::ChannelOpenConfirmation { .. } => 91,
                Self::ChannelOpenFailure { .. } => 92,
                Self::WindowAdjust { .. } => 93,
                Self::Data { .. } => 94,
                Self::ExtendedData { .. } => 95,
                Self::Eof(_) => 96,
                Self::Close(_) => 97,
                Self::ChannelRequest { .. } => 98,
                Self::ChannelSuccess(_) => 99,
                Self::ChannelFailure(_) => 100,
            },
        )?;
        match self {
            Self::GlobalRequest {
                want_reply,
                request,
            } => {
                w.name(match request {
                    GlobalRequest::TcpIpForward { .. } => "tcpip-forward",
                    GlobalRequest::CancelTcpIpForward { .. } => "cancel-tcpip-forward",
                    GlobalRequest::Other { name, .. } => name,
                })?;
                w.byte(u8::from(*want_reply))?;
                match request {
                    GlobalRequest::TcpIpForward { address, port }
                    | GlobalRequest::CancelTcpIpForward { address, port } => {
                        w.string(address.as_bytes())?;
                        w.uint32(*port)?;
                    }
                    GlobalRequest::Other { name, data } => {
                        if matches!(name.as_str(), "tcpip-forward" | "cancel-tcpip-forward") {
                            return Err(Error::Unwritable);
                        }
                        w.raw(data)?;
                    }
                }
            }
            Self::RequestSuccess(data) => w.raw(data)?,
            Self::RequestFailure => (),
            Self::ChannelOpen {
                sender,
                window,
                max_packet,
                kind,
            } => {
                w.name(match kind {
                    OpenKind::Session => "session",
                    OpenKind::DirectTcpIp(_) => "direct-tcpip",
                    OpenKind::ForwardedTcpIp(_) => "forwarded-tcpip",
                    OpenKind::Other { name, .. } => name,
                })?;
                w.uint32(*sender)?;
                w.uint32(*window)?;
                w.uint32(*max_packet)?;
                match kind {
                    OpenKind::Session => (),
                    OpenKind::DirectTcpIp(tcp) | OpenKind::ForwardedTcpIp(tcp) => {
                        tcp.write(&mut w)?
                    }
                    OpenKind::Other { name, data } => {
                        if matches!(
                            name.as_str(),
                            "session" | "direct-tcpip" | "forwarded-tcpip"
                        ) {
                            return Err(Error::Unwritable);
                        }
                        w.raw(data)?;
                    }
                }
            }
            Self::ChannelOpenConfirmation {
                recipient,
                sender,
                window,
                max_packet,
                data,
            } => {
                w.uint32(*recipient)?;
                w.uint32(*sender)?;
                w.uint32(*window)?;
                w.uint32(*max_packet)?;
                w.raw(data)?;
            }
            Self::ChannelOpenFailure {
                recipient,
                reason,
                description,
                language,
            } => {
                w.uint32(*recipient)?;
                w.uint32(*reason)?;
                w.string(description.as_bytes())?;
                w.string(language.as_bytes())?;
            }
            Self::WindowAdjust { recipient, bytes } => {
                w.uint32(*recipient)?;
                w.uint32(*bytes)?;
            }
            Self::Data { recipient, data } => {
                w.uint32(*recipient)?;
                w.string(data)?;
            }
            Self::ExtendedData {
                recipient,
                kind,
                data,
            } => {
                w.uint32(*recipient)?;
                w.uint32(*kind)?;
                w.string(data)?;
            }
            Self::Eof(recipient)
            | Self::Close(recipient)
            | Self::ChannelSuccess(recipient)
            | Self::ChannelFailure(recipient) => w.uint32(*recipient)?,
            Self::ChannelRequest {
                recipient,
                want_reply,
                request,
            } => {
                w.uint32(*recipient)?;
                w.name(request.name())?;
                w.byte(u8::from(*want_reply))?;
                request.write(&mut w)?;
            }
        }
        w.finish();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::{
        codec::{Lcg, assert_heap_bound},
        test_support::{assert_write, mutate, rounds},
    };

    fn dimensions(g: &mut Lcg) -> Dimensions {
        Dimensions {
            columns: g.next() as u32,
            rows: g.next() as u32,
            pixel_width: g.next() as u32,
            pixel_height: g.next() as u32,
        }
    }

    #[test]
    fn randomized_connection_roundtrips() {
        let mut g = Lcg::new(0x636f6e6e);
        for _ in 0..rounds(1000) {
            for message in messages(&mut g) {
                assert_write(&message).unwrap();
                let mut bytes = message.to_bytes().unwrap();
                mutate(&mut g, &mut bytes);
                if let Ok(parsed) = Message::parse(&bytes) {
                    assert_write(&parsed).unwrap();
                }
            }
        }
    }

    /// Each parsed message holds at most its type's bound: random ones of
    /// every kind, and terminal requests with as many modes as a payload
    /// holds and fewer, the shortest items there are.
    #[test]
    fn parsed_connection_messages_hold_at_most_their_bound() {
        let mut g = Lcg::new(0x68656170);
        let mut payloads = Vec::new();
        for _ in 0..200 {
            payloads.extend(messages(&mut g).iter().map(|m| m.to_bytes().unwrap()));
        }
        let most_modes = (MAX_PAYLOAD - 64) / 5;
        for count in [0, 1, 2, 3, 4, 5, 100, 1000, most_modes] {
            let request = Message::ChannelRequest {
                recipient: 0,
                want_reply: false,
                request: SessionRequest::Pty {
                    terminal: String::new(),
                    dimensions: Dimensions::default(),
                    modes: vec![
                        TerminalMode {
                            opcode: 1,
                            value: 0,
                        };
                        count
                    ],
                },
            };
            payloads.push(request.to_bytes().unwrap());
        }
        payloads.push(
            Message::Data {
                recipient: 0,
                data: vec![7; MAX_PAYLOAD - 9],
            }
            .to_bytes()
            .unwrap(),
        );
        assert_heap_bound(&payloads, Message::parse);
    }

    /// One of each message, with random fields.
    fn messages(g: &mut Lcg) -> Vec<Message> {
        let recipient = g.next() as u32;
        let requests = [
            SessionRequest::Pty {
                terminal: g.text(50),
                dimensions: dimensions(g),
                modes: (0..g.index(30))
                    .map(|_| TerminalMode {
                        opcode: (1 + g.index(159)) as u8,
                        value: g.next() as u32,
                    })
                    .collect(),
            },
            SessionRequest::Shell,
            SessionRequest::Exec(g.bytes(300)),
            SessionRequest::Env {
                name: g.bytes(50),
                value: g.bytes(200),
            },
            SessionRequest::Subsystem(g.text(50)),
            SessionRequest::WindowChange(dimensions(g)),
            SessionRequest::Signal("TERM".into()),
            SessionRequest::ExitStatus(g.next() as u32),
            SessionRequest::ExitSignal {
                signal: "HUP".into(),
                core_dumped: g.coin(),
                message: g.text(100),
                language: g.text(20),
            },
            SessionRequest::Other {
                name: "extension@example.com".into(),
                data: g.bytes(200),
            },
        ];
        let tcp = TcpIp {
            host: g.text(100),
            port: g.next() as u32,
            originator: g.text(100),
            originator_port: g.next() as u32,
        };
        let mut messages = vec![
            Message::RequestSuccess(g.bytes(200)),
            Message::RequestFailure,
            Message::ChannelOpenConfirmation {
                recipient,
                sender: g.next() as u32,
                window: g.next() as u32,
                max_packet: g.next() as u32,
                data: g.bytes(200),
            },
            Message::ChannelOpenFailure {
                recipient,
                reason: g.next() as u32,
                description: g.text(100),
                language: g.text(20),
            },
            Message::WindowAdjust {
                recipient,
                bytes: g.next() as u32,
            },
            Message::Data {
                recipient,
                data: g.bytes(400),
            },
            Message::ExtendedData {
                recipient,
                kind: g.next() as u32,
                data: g.bytes(400),
            },
            Message::Eof(recipient),
            Message::Close(recipient),
            Message::ChannelSuccess(recipient),
            Message::ChannelFailure(recipient),
        ];
        for kind in [
            OpenKind::Session,
            OpenKind::DirectTcpIp(tcp.clone()),
            OpenKind::ForwardedTcpIp(tcp),
            OpenKind::Other {
                name: "extension@example.com".into(),
                data: g.bytes(200),
            },
        ] {
            messages.push(Message::ChannelOpen {
                sender: g.next() as u32,
                window: g.next() as u32,
                max_packet: g.next() as u32,
                kind,
            });
        }
        for request in requests {
            messages.push(Message::ChannelRequest {
                recipient,
                want_reply: g.coin(),
                request,
            });
        }
        for request in [
            GlobalRequest::TcpIpForward {
                address: g.text(100),
                port: g.next() as u32,
            },
            GlobalRequest::CancelTcpIpForward {
                address: g.text(100),
                port: g.next() as u32,
            },
            GlobalRequest::Other {
                name: "extension@example.com".into(),
                data: g.bytes(200),
            },
        ] {
            messages.push(Message::GlobalRequest {
                want_reply: g.coin(),
                request,
            });
        }
        messages
    }
}
