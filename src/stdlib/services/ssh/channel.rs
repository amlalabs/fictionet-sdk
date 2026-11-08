//! Typed channel traffic, independent of the SSH connection transport.

use std::sync::Arc;

use crate::stdlib::layer::{
    Budget, Charge, Chunk, CreditReturn, Credited, Owned, Port, StreamCommand, StreamEvent,
};
use crate::stdlib::protocols::ssh::connection as wire;

/// Context supplied once when a peer opens a channel.
#[derive(Debug)]
pub struct Opening {
    /// Authenticated account.
    pub user: String,
    /// Server's wire channel number.
    pub channel: u32,
    /// Session or forwarding destination requested by the peer.
    pub kind: wire::OpenKind,
}

/// SSH channel semantics, including extended data and requests.
pub struct ChannelPort;
impl Port for ChannelPort {
    type Event = ChannelEvent;
    type Command = ChannelCommand;
}

/// Events on one SSH channel. Data consumes byte credit; controls have bounded
/// item slots and retain the reservation for their decoded fields.
#[derive(Debug)]
pub enum ChannelEvent {
    /// Ordinary channel bytes, write completion, EOF or transport reset.
    Stream(StreamEvent),
    /// Extended channel bytes with their protocol data type.
    Extended {
        /// Extended data type; one denotes stderr.
        kind: u32,
        /// Owned bytes, with receive credit returned on release.
        data: Chunk,
    },
    /// A channel request and whether its sender expects a reply.
    Request {
        /// Whether a success or failure response is required.
        want_reply: bool,
        /// Typed request and its allocation reservation.
        request: Owned<wire::SessionRequest>,
    },
    /// Reply to an outgoing request.
    Reply(bool),
}

/// Commands on one SSH channel.
#[derive(Debug)]
pub enum ChannelCommand {
    /// Accept or refuse the opening before sending anything else.
    Accept(bool),
    /// Ordinary channel output, EOF or reset.
    Stream(StreamCommand),
    /// Extended output, such as stderr.
    Extended {
        /// Protocol data type.
        kind: u32,
        /// Owned output bytes.
        data: Chunk,
    },
    /// Send a typed channel request.
    Request {
        /// Whether a reply is expected.
        want_reply: bool,
        /// Request fields and their reservation.
        request: Owned<wire::SessionRequest>,
    },
    /// Success or failure for an incoming request.
    Reply(bool),
    /// Complete the channel close handshake after preceding output.
    Close,
    /// Disconnect the entire SSH connection immediately.
    Disconnect,
    /// Silently close the connection after preceding output drains.
    Hangup,
}

fn with_stream(data: &mut Chunk, f: impl FnOnce(&mut StreamEvent) -> bool) -> bool {
    let mut event = StreamEvent::Data(std::mem::replace(data, Chunk::new(Vec::new())));
    let result = f(&mut event);
    let StreamEvent::Data(bytes) = event else {
        unreachable!()
    };
    *data = bytes;
    result
}

impl Credited for ChannelEvent {
    fn credit(&self) -> u64 {
        match self {
            Self::Stream(event) => event.credit(),
            Self::Extended { data, .. } => data.len() as u64,
            _ => 0,
        }
    }
    fn receive_bytes(window: u64) -> Option<usize> {
        StreamEvent::receive_bytes(window)
    }
    fn reserve_receive(&mut self, budget: &Budget, backing: &Arc<Charge>) -> bool {
        match self {
            Self::Stream(event) => event.reserve_receive(budget, backing),
            Self::Extended { data, .. } => {
                with_stream(data, |e| e.reserve_receive(budget, backing))
            }
            _ => true,
        }
    }
    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            Self::Stream(event) => event.reserve(budget),
            Self::Extended { data, .. } => with_stream(data, |e| e.reserve(budget)),
            _ => true,
        }
    }
    fn retain_credit(&mut self, credit: CreditReturn) -> bool {
        match self {
            Self::Stream(event) => event.retain_credit(credit),
            Self::Extended { data, .. } => with_stream(data, |e| e.retain_credit(credit)),
            _ => false,
        }
    }
    fn urgent(&self) -> bool {
        matches!(self, Self::Stream(e) if e.urgent())
    }
    fn terminal_reset(&self) -> bool {
        matches!(self, Self::Stream(StreamEvent::Reset))
    }
}

impl Credited for ChannelCommand {
    fn credit(&self) -> u64 {
        match self {
            Self::Stream(command) => command.credit(),
            Self::Extended { data, .. } => data.len() as u64,
            _ => 0,
        }
    }
    fn splittable(&self) -> bool {
        matches!(
            self,
            Self::Stream(StreamCommand::Write(_)) | Self::Extended { .. }
        )
    }
    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            Self::Stream(command) => command.reserve(budget),
            Self::Extended { data, .. } => with_stream(data, |e| e.reserve(budget)),
            _ => true,
        }
    }
    fn admit_credit(self, units: u64) -> Result<(Self, Option<Self>), Self> {
        match self {
            Self::Stream(command) => command
                .admit_credit(units)
                .map(|(first, rest)| (Self::Stream(first), rest.map(Self::Stream)))
                .map_err(Self::Stream),
            Self::Extended { kind, mut data } if data.len() as u64 > units && units > 0 => {
                let prefix = data.split_to(units as usize);
                Ok((
                    Self::Extended { kind, data: prefix },
                    Some(Self::Extended { kind, data }),
                ))
            }
            command if command.credit() <= units => Ok((command, None)),
            command => Err(command),
        }
    }
}
