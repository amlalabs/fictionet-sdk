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
use crate::stdlib::layer::{Budget, Charge, Owned};
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

/// Peer metadata, observed before transport negotiation accepts or rejects it.
#[derive(Clone, Debug)]
pub enum Observation {
    /// Peer identification, including unsupported versions.
    Version(ssh::Identification),
    /// Peer proposal, including unsupported algorithms and rekeys.
    Proposal(Box<ssh::KexInit>),
}

/// A terminal receive failure. Framing failures permit a protocol disconnect;
/// negotiation failures stop immediately. Peer metadata seen before either
/// was already observed.
#[derive(Debug)]
pub enum Failure {
    /// Invalid packet framing, authentication tag or truncated input.
    Framing(TransportError),
    /// A decoded message failed transport negotiation or policy.
    Protocol(TransportError),
}
impl From<TransportError> for Failure {
    fn from(error: TransportError) -> Self {
        Self::Protocol(error)
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Framing(error) | Self::Protocol(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Failure {}

/// An event after transport processing, never an unverified encrypted packet.
#[derive(Debug)]
pub enum Event {
    /// Both directions installed keys. Session identity remains stable on rekey.
    Established {
        /// True after a subsequent exchange, false after the initial exchange.
        rekey: bool,
    },
    /// Application packet with its sequence number before strict KEX resets.
    Packet {
        /// Incoming packet sequence number.
        sequence: u32,
        /// Message number followed by its fields, with the charge that paid
        /// for its allocation before it was made.
        payload: Owned<Vec<u8>>,
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
///
/// A transport pays for what it holds itself, from the budget that `push`
/// and `poll` hand it, before it allocates: its input buffer, its own state,
/// and what a packet takes while it is decoded and handled. A payload it
/// hands up carries the charge that paid for it. A refused charge changes
/// nothing (layer rule 9): `push` takes no more than the room already paid
/// for, and `poll` gives no event and keeps any decoded packet for the next
/// poll, which the runner makes once memory frees. Shared configuration
/// belongs to the factory.
pub trait PacketTransport: Send + 'static {
    /// Start once with fresh connection entropy.
    fn start(&mut self, seed: [u8; 32], out: &mut Vec<u8>) -> Result<(), TransportError>;
    /// Accept only the returned prefix; the caller retains the suffix.
    fn push(&mut self, budget: &Budget, bytes: &[u8]) -> usize;
    /// Mark EOF; poll must still process buffered packets or report truncation.
    fn end(&mut self);
    /// Whether polling can consume input, emit an event, or finish after EOF.
    fn poll_ready(&self) -> bool;
    /// None means more input or more memory is required. Output belongs
    /// exclusively to the caller. Peer metadata goes to `observe` as it is
    /// decoded, before negotiation accepts or rejects it.
    fn poll(
        &mut self,
        budget: &Budget,
        out: &mut Vec<u8>,
        observe: &mut dyn FnMut(Observation),
    ) -> Result<Option<Event>, Failure>;
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
    /// The input buffer's allocation, paid for before it grows.
    input: Option<Charge>,
    /// The protocol state, charged once at the most it can reach
    /// ([`Transport::most_held`]) before the first packet is decoded.
    state: Option<Charge>,
    /// A decoded packet whose handling the budget could not pay for yet,
    /// and the charge for what it holds.
    held_back: Option<(TransportEvent, Charge)>,
}
impl StandardTransport {
    /// Create the standard transport from server configuration.
    pub fn new(config: &Config) -> Self {
        Self::with_stream(
            Stream::new(Transport::new(
                config.host_key.clone(),
                config.identification.clone(),
            )),
            config.proposal.clone(),
        )
    }
    /// Wrap a separately configured standard codec, for transport extensions.
    pub fn from_transport(transport: Transport) -> Self {
        Self::with_stream(Stream::new(transport), None)
    }
    fn with_stream(stream: Stream<Transport>, proposal: Option<ssh::KexInit>) -> Self {
        Self {
            stream,
            proposal,
            input: None,
            state: None,
            held_back: None,
        }
    }
}
impl PacketTransport for StandardTransport {
    fn start(&mut self, seed: [u8; 32], out: &mut Vec<u8>) -> Result<(), TransportError> {
        let transport = self.stream.decoder();
        transport.seed(seed)?;
        if let Some(proposal) = self.proposal.take() {
            transport.set_proposal(proposal)?;
        }
        transport.start_identification(out)
    }
    fn push(&mut self, budget: &Budget, bytes: &[u8]) -> usize {
        if self.input.is_none() {
            self.input = budget.charge(0);
        }
        let Some(input) = &mut self.input else {
            return 0;
        };
        // Room for the buffer's largest allocation is paid for before it
        // grows; afterwards the charge comes back to what it holds. Without
        // that room, only what already fits is taken.
        let growth = if input.grow_to(self.stream.most_allocated()) {
            usize::MAX
        } else {
            input.bytes().saturating_sub(self.stream.allocated())
        };
        let taken = self.stream.push_with_budget(bytes, growth);
        input.shrink_to(self.stream.allocated());
        taken
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
        // Only an established transport rekeys, and it has decoded packets,
        // so its state is charged.
        if self.state.is_none() {
            return Err(TransportError::State);
        }
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
        self.stream.buffered() > 0 || self.stream.is_eof() || self.held_back.is_some()
    }
    fn poll(
        &mut self,
        budget: &Budget,
        out: &mut Vec<u8>,
        observe: &mut dyn FnMut(Observation),
    ) -> Result<Option<Event>, Failure> {
        if self.state.is_none() {
            let Some(state) = budget.charge(self.stream.get_ref().most_held()) else {
                return Ok(None);
            };
            self.state = Some(state);
        }
        let (event, mut charge) = match self.held_back.take() {
            Some(held) => held,
            None => {
                // Decoding copies one packet, or one version line, out of
                // the input buffer: no more than is buffered, nor than a
                // packet. That copy is paid for first.
                let copy = self.stream.buffered().min(ssh::MAX_PACKET + 16);
                let Some(charge) = budget.charge(copy) else {
                    return Ok(None);
                };
                let Some(event) = self.stream.next() else {
                    return Ok(self.stream.is_done().then_some(Event::End));
                };
                let event = event.map_err(|fail| {
                    Failure::Framing(match fail {
                        crate::stdlib::codec::Fail::Protocol(error) => error,
                        _ => TransportError::State,
                    })
                })?;
                (event, charge)
            }
        };
        // What the packet holds and what handling it takes, paid before
        // anything is parsed or changed. Refused, the packet waits.
        let need = match &event {
            // The line, and the observer's copy.
            TransportEvent::Version(_) => 2 * ssh::MAX_VERSION_LINE,
            TransportEvent::Packet { payload, .. } => {
                payload.capacity() + self.stream.get_ref().scratch(payload)
            }
        };
        if !charge.grow_to(need) {
            self.held_back = Some((event, charge));
            return Ok(None);
        }
        charge.shrink_to(need);
        match &event {
            TransportEvent::Version(version) => observe(Observation::Version(version.clone())),
            // The observer's parse is gone before negotiation parses again.
            TransportEvent::Packet { payload, .. } if payload.first() == Some(&20) => {
                let ssh::Message::KexInit(proposal) =
                    ssh::Message::parse(payload).map_err(TransportError::from)?
                else {
                    return Err(TransportError::State.into());
                };
                observe(Observation::Proposal(Box::new(proposal)));
            }
            TransportEvent::Packet { .. } => {}
        }
        let sequence = match &event {
            TransportEvent::Packet { sequence, .. } => *sequence,
            TransportEvent::Version(_) => 0,
        };
        let transport = self.stream.decoder();
        let established = transport.is_established();
        let exchanging = transport.is_rekeying();
        let event = match transport.handle(event, out)? {
            Some(payload) => {
                let paid = charge
                    .split(payload.capacity())
                    .ok_or(TransportError::State)?;
                Event::Packet {
                    sequence,
                    payload: Owned::new(payload, paid),
                }
            }
            None if exchanging && !transport.is_rekeying() && transport.is_established() => {
                Event::Established { rekey: established }
            }
            None => Event::Progress,
        };
        Ok(Some(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::protocols::ssh::transport::HostKey;
    use std::sync::Arc;

    /// What the transport holds is paid for: the input buffer's charge is
    /// what it has allocated, and the state's charge covers the protocol
    /// state.
    fn covered(transport: &StandardTransport) {
        assert_eq!(
            transport.input.as_ref().map_or(0, Charge::bytes),
            transport.stream.allocated()
        );
        if let Some(state) = &transport.state {
            assert!(state.bytes() >= transport.stream.held());
        }
    }

    /// With no room in its budget the transport takes no input and decodes
    /// nothing, changing nothing; a packet decoded whose handling does not
    /// fit waits whole. Once memory frees, each goes on.
    #[test]
    fn without_memory_the_transport_waits_and_changes_nothing() {
        let host = Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap());
        let config = Config::new(
            host.clone(),
            ssh::Identification::new("2.0", "test", None).unwrap(),
        );
        let mut transport = StandardTransport::new(&config);
        let mut out = Vec::new();
        transport.start([3; 32], &mut out).unwrap();
        let version = ssh::Identification::new("2.0", "client", None)
            .unwrap()
            .to_bytes()
            .unwrap();
        // A proposal the server can take: its own algorithms.
        let proposal = Transport::new(host, config.identification.clone())
            .proposal()
            .clone();
        let kexinit = ssh::Packet::new(ssh::Message::KexInit(proposal).to_bytes().unwrap())
            .to_bytes()
            .unwrap();
        let input = [version, kexinit.clone()].concat();
        let budget = Budget::new(1 << 20);

        let elsewhere = budget.charge(budget.limit()).unwrap();
        assert_eq!(transport.push(&budget, &input), 0);
        assert_eq!(budget.used(), elsewhere.bytes());
        drop(elsewhere);
        assert_eq!(transport.push(&budget, &input), input.len());
        covered(&transport);

        let mut observed = Vec::new();
        let elsewhere = budget.charge(budget.limit() - budget.used()).unwrap();
        let used = budget.used();
        assert!(
            transport
                .poll(&budget, &mut out, &mut |o| observed.push(o))
                .unwrap()
                .is_none()
        );
        assert!(observed.is_empty());
        assert_eq!(transport.stream.buffered(), input.len());
        assert_eq!(budget.used(), used);
        drop(elsewhere);
        assert!(matches!(
            transport.poll(&budget, &mut out, &mut |o| observed.push(o)),
            Ok(Some(Event::Progress))
        ));
        assert!(matches!(observed[..], [Observation::Version(_)]));
        covered(&transport);

        // Room to decode the proposal, but not to parse it: it waits.
        let elsewhere = budget
            .charge(budget.limit() - budget.used() - kexinit.len())
            .unwrap();
        assert!(
            transport
                .poll(&budget, &mut out, &mut |o| observed.push(o))
                .unwrap()
                .is_none()
        );
        assert_eq!(observed.len(), 1);
        assert!(transport.poll_ready());
        drop(elsewhere);
        assert!(matches!(
            transport.poll(&budget, &mut out, &mut |o| observed.push(o)),
            Ok(Some(Event::Progress))
        ));
        assert!(matches!(
            observed[..],
            [Observation::Version(_), Observation::Proposal(_)]
        ));
        assert!(!transport.poll_ready());
        covered(&transport);
        drop(transport);
        assert_eq!(budget.used(), 0);
    }
}
