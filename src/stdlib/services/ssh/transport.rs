//! The replaceable boundary below SSH authentication and channels.
//!
//! A transport owns version exchange, key exchange, packet authentication,
//! encryption and rekeying. It never owns channel windows or authentication
//! policy. Output is appended synchronously to the connection layer's buffer:
//! the connection layer alone owns delivery and credits a child write only
//! after every encoded byte of that write has been acknowledged by the carrier.
//! Handshake bytes carry no child credit. A transport must not retain output or
//! acknowledge delivery itself.

use super::Config;
use crate::stdlib::codec::{Stream, Wire};
use crate::stdlib::layer::Budget;
use crate::stdlib::network::ConnInfo;
use crate::stdlib::protocols::ssh::transport::Transport;
pub use crate::stdlib::protocols::ssh::transport::{Negotiated, TransportError};
use crate::stdlib::protocols::ssh::{self, transport::TransportEvent};
use crate::stdlib::services::stack;
use crate::time::Instant;

/// What a transport factory receives for one accepted connection, before any
/// input is admitted.
pub struct Opening<'a> {
    /// Shared defaults; a replacement may supply its own transport policy.
    pub config: &'a Config,
    /// Identity and addresses of the accepted connection.
    pub info: &'a ConnInfo,
    /// Shared connection allocation budget.
    pub budget: &'a Budget,
    /// Carrier idle and write deadlines.
    pub limits: stack::StreamLimits,
    /// Simulation time at arrival.
    pub now: Instant,
    /// Absolute authentication deadline.
    pub login_deadline: Instant,
}

/// Peer metadata observed before transport negotiation accepts or rejects it.
#[derive(Clone, Debug)]
pub enum Observation {
    /// Peer identification, including unsupported versions.
    Version(ssh::Identification),
    /// Peer proposal, including unsupported algorithms and rekeys.
    Proposal(Box<ssh::KexInit>),
}

/// A terminal receive failure. Framing failures permit a protocol disconnect;
/// negotiation failures stop immediately, preserving any peer observation.
#[derive(Debug)]
pub enum Failure {
    /// Invalid packet framing, authentication tag or truncated input.
    Framing(TransportError),
    /// A decoded message failed transport negotiation or policy.
    Protocol {
        /// Fatal transport error.
        error: TransportError,
        /// Peer metadata retained even when negotiation fails.
        observation: Option<Observation>,
    },
}
impl From<TransportError> for Failure {
    fn from(error: TransportError) -> Self {
        Self::Protocol {
            error,
            observation: None,
        }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Framing(error) | Self::Protocol { error, .. } => error.fmt(f),
        }
    }
}
impl std::error::Error for Failure {}

/// An event after transport processing, never an unverified encrypted packet.
#[derive(Debug)]
pub enum Event {
    /// Peer metadata from this transport step.
    Observed(Observation),
    /// Both directions installed keys. Session identity remains stable on rekey.
    Established {
        /// True after a subsequent exchange, false after the initial exchange.
        rekey: bool,
    },
    /// Application packet with its sequence number before strict KEX resets.
    Packet {
        /// Incoming packet sequence number.
        sequence: u32,
        /// Message number followed by its fields.
        payload: Vec<u8>,
    },
    /// A transport message was consumed without an application event.
    Progress,
    /// Clean end of input, with no incomplete packet remaining.
    End,
}

/// Negotiation state, authoritative for application output and authentication.
#[derive(Clone, Copy, Debug)]
pub enum State<'a> {
    /// Initial exchange has not completed.
    Pending,
    /// Application packets may be sent.
    Established {
        /// First exchange hash, never replaced during rekey.
        session_id: &'a [u8],
        /// Algorithms installed in both directions.
        negotiated: &'a Negotiated,
    },
    /// Application output must wait. The original session identity is retained.
    Rekeying {
        /// First exchange hash, never replaced during rekey.
        session_id: &'a [u8],
    },
}

/// Synchronous, bounded SSH transport installed under [`super::Ssh`].
///
/// `poll` processes at most one packet, installing NEWKEYS before decoding the
/// next. Only authenticated, transport-validated application packets may cross
/// this boundary (a peer disconnect may arrive before keys). Errors are fatal.
/// Implementations obey SSH's MAX_PACKET and MAX_PAYLOAD limits. Each output
/// operation appends at most four MAX_PACKET bytes; `write_packet` appends at
/// most one MAX_PACKET and must encode the entire payload synchronously.
/// `resident_bytes` bounds all retained input and transport state before any
/// allocation. Temporary parsing space is bounded by 64 MAX_PACKET bytes.
/// Shared configuration belongs to the factory; connection storage belongs to
/// this bound. Implementations must not allocate beyond these reservations.
pub trait PacketTransport: Send + 'static {
    /// Reserved input and retained transport storage, excluding output.
    fn resident_bytes(&self) -> usize;
    /// Start once with fresh connection entropy.
    fn start(&mut self, seed: [u8; 32], out: &mut Vec<u8>) -> Result<(), TransportError>;
    /// Accept only the returned prefix; the caller retains the suffix.
    fn push(&mut self, bytes: &[u8]) -> usize;
    /// Mark EOF; poll must still process buffered packets or report truncation.
    fn end(&mut self);
    /// Whether polling can consume input, emit an event, or finish after EOF.
    /// False lets the caller avoid reserving packet scratch space while idle.
    fn poll_ready(&self) -> bool;
    /// None means more input is required. Output belongs exclusively to caller.
    fn poll(&mut self, out: &mut Vec<u8>) -> Result<Option<Event>, Failure>;
    /// Current negotiation state and stable session identity.
    fn state(&self) -> State<'_>;
    /// Whether key limits require a new exchange before further output.
    fn needs_rekey(&self) -> bool;
    /// Initiate key exchange; application output waits until established.
    fn rekey(&mut self, out: &mut Vec<u8>) -> Result<(), TransportError>;
    /// Encode an entire application packet into caller-owned output.
    fn write_packet(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), TransportError>;
    /// Encode a terminal disconnect, including during key exchange.
    fn disconnect(
        &mut self,
        reason: ssh::DisconnectReason,
        description: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), TransportError>;
}

/// The standard transport, including its bounded stream decoder.
pub struct StandardTransport {
    stream: Stream<Transport>,
    proposal: Option<ssh::KexInit>,
}
impl StandardTransport {
    /// Create the standard transport from server configuration.
    pub fn new(config: &Config) -> Self {
        Self {
            stream: Stream::new(Transport::new(
                config.host_key.clone(),
                config.identification.clone(),
            )),
            proposal: config.proposal.clone(),
        }
    }
    /// Wrap a separately configured standard codec, for transport extensions.
    pub fn from_transport(transport: Transport) -> Self {
        Self {
            stream: Stream::new(transport),
            proposal: None,
        }
    }
}
impl PacketTransport for StandardTransport {
    fn resident_bytes(&self) -> usize {
        self.stream.limit() + self.stream.held()
    }
    fn start(&mut self, seed: [u8; 32], out: &mut Vec<u8>) -> Result<(), TransportError> {
        let transport = self.stream.decoder();
        transport.seed(seed)?;
        if let Some(proposal) = self.proposal.take() {
            transport.set_proposal(proposal)?;
        }
        transport.start_identification(out)
    }
    fn push(&mut self, bytes: &[u8]) -> usize {
        self.stream.push(bytes)
    }
    fn end(&mut self) {
        self.stream.end();
    }
    fn state(&self) -> State<'_> {
        let transport = self.stream.get_ref();
        if !transport.is_established() {
            return State::Pending;
        }
        let session_id = transport
            .session_id()
            .expect("established SSH session identity");
        if transport.is_rekeying() {
            State::Rekeying { session_id }
        } else {
            State::Established {
                session_id,
                negotiated: transport.negotiated().expect("established SSH algorithms"),
            }
        }
    }
    fn needs_rekey(&self) -> bool {
        self.stream.get_ref().needs_rekey()
    }
    fn rekey(&mut self, out: &mut Vec<u8>) -> Result<(), TransportError> {
        self.stream.decoder().rekey(out)
    }
    fn write_packet(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), TransportError> {
        self.stream.decoder().write_packet(payload, out)
    }
    fn disconnect(
        &mut self,
        reason: ssh::DisconnectReason,
        description: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), TransportError> {
        self.stream.decoder().disconnect(reason, description, out)
    }
    fn poll_ready(&self) -> bool {
        self.stream.buffered() > 0 || self.stream.is_eof()
    }
    fn poll(&mut self, out: &mut Vec<u8>) -> Result<Option<Event>, Failure> {
        let Some(event) = self.stream.next() else {
            return Ok(self.stream.is_done().then_some(Event::End));
        };
        let event = event.map_err(|error| {
            Failure::Framing(match error {
                crate::stdlib::codec::Fail::Protocol(error) => error,
                _ => TransportError::State,
            })
        })?;
        let observation = match &event {
            TransportEvent::Version(version) => Some(Observation::Version(version.clone())),
            TransportEvent::Packet { payload, .. } if payload.first() == Some(&20) => {
                let ssh::Message::KexInit(proposal) =
                    ssh::Message::parse(payload).map_err(TransportError::from)?
                else {
                    return Err(TransportError::State.into());
                };
                Some(Observation::Proposal(Box::new(proposal)))
            }
            _ => None,
        };
        let sequence = match &event {
            TransportEvent::Packet { sequence, .. } => *sequence,
            _ => 0,
        };
        let transport = self.stream.decoder();
        let established = transport.is_established();
        let exchanging = transport.is_rekeying();
        let payload = transport
            .handle(event, out)
            .map_err(|error| Failure::Protocol {
                error,
                observation: observation.clone(),
            })?;
        let event = if let Some(payload) = payload {
            Event::Packet { sequence, payload }
        } else if exchanging && !transport.is_rekeying() && transport.is_established() {
            Event::Established { rekey: established }
        } else {
            observation.map_or(Event::Progress, Event::Observed)
        };
        Ok(Some(event))
    }
}
