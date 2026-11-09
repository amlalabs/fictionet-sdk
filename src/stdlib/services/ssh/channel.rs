//! Typed channel traffic, independent of the SSH connection transport.

use std::sync::Arc;

use crate::stdlib::layer::{
    Budget, ByteStream, Charge, Chunk, CreditLease, Credited, Env, Owned, Port, StreamCommand,
    StreamEvent,
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

    fn urgent(event: &ChannelEvent) -> bool {
        matches!(event, ChannelEvent::Stream(e) if ByteStream::urgent(e))
    }
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
    /// Silently close the connection after preceding output drains. Draining
    /// and immediate disconnection go on the connection's control
    /// ([`ConnectionControl`](super::ConnectionControl)), beside channel traffic.
    Hangup,
}

fn with_stream<R>(data: &mut Chunk, f: impl FnOnce(&mut StreamEvent) -> R) -> R {
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
    fn retain_lease(&mut self, lease: CreditLease) -> Option<CreditLease> {
        match self {
            Self::Stream(event) => event.retain_lease(lease),
            Self::Extended { data, .. } => with_stream(data, |e| e.retain_lease(lease)),
            _ => Some(lease),
        }
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

/// The ordinary byte stream of a channel, with other traffic delivered to an
/// explicit control policy. The policy receives requests, replies and extended
/// data and can return a response. It may retain owned events and their credit.
/// Compose this adapter with a byte-stream protocol inside `Children`.
pub struct Ordinary<F> {
    control: F,
    up: Option<StreamEvent>,
    urgent: Option<StreamEvent>,
    down: Option<ChannelCommand>,
}
impl<F> Ordinary<F> {
    /// Accept a channel and choose how its non-stream traffic is handled.
    pub fn new(control: F) -> Self {
        Self {
            control,
            up: None,
            urgent: None,
            down: Some(ChannelCommand::Accept(true)),
        }
    }
    /// Access the channel control policy, including any retained events.
    pub fn control_mut(&mut self) -> &mut F {
        &mut self.control
    }
}
impl<F: FnMut(ChannelEvent) -> Option<ChannelCommand>> crate::stdlib::layer::Layer for Ordinary<F> {
    type Lower = ChannelPort;
    type Upper = crate::stdlib::layer::ByteStream;
    type Report = core::convert::Infallible;
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = core::convert::Infallible;
    fn on_event(
        &mut self,
        _: &mut crate::stdlib::layer::Env<'_, Self::Report>,
        event: ChannelEvent,
    ) -> Result<crate::stdlib::layer::Admit<ChannelEvent>, Self::Error> {
        use crate::stdlib::layer::Admit;
        match event {
            ChannelEvent::Stream(event) if ByteStream::urgent(&event) => {
                if self.urgent.is_some() {
                    return Ok(Admit::Blocked(ChannelEvent::Stream(event)));
                }
                self.urgent = Some(event);
            }
            ChannelEvent::Stream(event) => {
                if self.up.is_some() {
                    return Ok(Admit::Blocked(ChannelEvent::Stream(event)));
                }
                self.up = Some(event);
            }
            event => {
                if self.down.is_some() {
                    return Ok(Admit::Blocked(event));
                }
                self.down = (self.control)(event);
            }
        }
        Ok(Admit::Taken)
    }
    fn on_command(
        &mut self,
        _: &mut crate::stdlib::layer::Env<'_, Self::Report>,
        command: StreamCommand,
    ) -> Result<crate::stdlib::layer::Admit<StreamCommand>, Self::Error> {
        use crate::stdlib::layer::Admit;
        if self.down.is_some() {
            return Ok(Admit::Blocked(command));
        }
        self.down = Some(ChannelCommand::Stream(command));
        Ok(Admit::Taken)
    }
    fn take_event(&mut self) -> Option<StreamEvent> {
        self.urgent.take().or_else(|| self.up.take())
    }
    fn take_urgent(&mut self) -> Option<StreamEvent> {
        self.urgent.take()
    }
    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<ChannelCommand> {
        self.down.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::layer::{Admit, ByteStream, Chain, Driver, Env, Layer, Top};
    use crate::time::Instant;
    use core::convert::Infallible;
    use std::sync::Mutex;

    struct Echo(Option<StreamCommand>);
    impl Layer for Echo {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            if self.0.is_some() {
                return Ok(Admit::Blocked(event));
            }
            self.0 = match event {
                StreamEvent::Data(data) => Some(StreamCommand::Write(data)),
                StreamEvent::Ended => Some(StreamCommand::End),
                StreamEvent::Reset => Some(StreamCommand::Reset),
                StreamEvent::Written(_) => None,
            };
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            never: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match never {}
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            self.0.take()
        }
    }

    #[test]
    fn ordinary_stream_composes_without_hiding_channel_controls() {
        let controls = Arc::new(Mutex::new(Vec::new()));
        let observed = controls.clone();
        let adapter = Ordinary::new(move |event| {
            let reply = matches!(
                event,
                ChannelEvent::Request {
                    want_reply: true,
                    ..
                }
            );
            observed.lock().unwrap().push(event);
            reply.then_some(ChannelCommand::Reply(true))
        });
        let mut driver = Driver::new(
            Chain::new(adapter, Echo(None)),
            Arc::new(crate::SeededEntropy::new(crate::Seed::from_u64(2))),
            Budget::new(1 << 20),
            Instant::ZERO,
        );
        assert!(matches!(
            driver.take_command(),
            Some(ChannelCommand::Accept(true))
        ));
        assert!(
            driver
                .deliver(ChannelEvent::Stream(StreamEvent::Data(Chunk::new(
                    b"payload".to_vec()
                ))))
                .unwrap()
                .moved()
        );
        driver.run().unwrap();
        let Some(ChannelCommand::Stream(StreamCommand::Write(data))) = driver.take_command() else {
            panic!("stream output missing");
        };
        assert_eq!(&*data, b"payload");
        let request = Owned::new(
            wire::SessionRequest::Subsystem("echo".into()),
            Budget::unlimited().charge(32).unwrap(),
        );
        assert!(
            driver
                .deliver(ChannelEvent::Request {
                    want_reply: true,
                    request
                })
                .unwrap()
                .moved()
        );
        driver.run().unwrap();
        assert!(matches!(
            driver.take_command(),
            Some(ChannelCommand::Reply(true))
        ));
        assert!(
            driver
                .deliver(ChannelEvent::Extended {
                    kind: 7,
                    data: Chunk::new(b"side".to_vec())
                })
                .unwrap()
                .moved()
        );
        driver.run().unwrap();
        assert!(
            matches!(&controls.lock().unwrap()[1], ChannelEvent::Extended { kind: 7, data } if &**data == b"side")
        );
        assert!(
            driver
                .deliver(ChannelEvent::Stream(StreamEvent::Ended))
                .unwrap()
                .moved()
        );
        driver.run().unwrap();
        assert!(matches!(
            driver.take_command(),
            Some(ChannelCommand::Stream(StreamCommand::End))
        ));
    }
}
