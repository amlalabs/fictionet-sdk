//! The passive TCP observer: captured IP packets below, one
//! [observed stream](fictionet::stdlib::layer::ObservedStream) per TCP
//! connection above.
//!
//! [`Observer`] is a [layer](fictionet::stdlib::layer) with whole captured
//! packets below, as [`ObservedIpPacket::observed`] reads them, and the
//! [`TcpObserver`] port above. It puts each direction of each connection
//! back in order and offers the connection as one child, opened with an
//! [`ObservedConnection`] that names it. It only watches: it sends nothing
//! down, and nothing above can make it send.
//!
//! What a child gets keeps the rules of [`ObservedStream`]:
//!
//! - Each direction's bytes come in order, with nothing repeated, at
//!   sequence positions counted from the first sequence number seen in that
//!   direction. Bytes missing from the capture are never invented: where
//!   reassembly gives up on them, a [`Gap`](ObservedEvent::Gap) says how
//!   many sequence positions it skipped.
//! - A FIN is noted where it sits even when bytes before it have not
//!   arrived. When they do, they come up, then the direction's
//!   [`End`](ObservedEvent::End) with [`Termination::Fin`], once, with no
//!   need for the FIN to be sent again.
//! - A RST ends both directions with [`Termination::Reset`], after what
//!   the RST's own segment carried in order. Bytes held past a hole are
//!   not delivered.
//! - A new SYN on the same endpoints that does not answer the other side's
//!   SYN starts a new connection: the old one's open directions end with
//!   [`Termination::Replaced`], and the new one is a new child, one
//!   generation on.
//! - Payload that arrives for a direction after its end is not delivered
//!   to the child, and the generation is never reopened for it. The
//!   observer reports it ([`ObserverReport::Late`]), so packet inspection
//!   can still show it.
//! - The end of the capture, [`PacketEvent::Ended`] from below, finishes
//!   every open direction: what was held past a hole comes up after its
//!   gap, and the direction ends with [`Termination::Truncated`] if bytes
//!   were known to be missing, or [`Termination::Finalized`] if not.
//! - To stay within its [`Limits`], the observer evicts one connection at
//!   a time, giving its open directions [`Termination::Evicted`], and
//!   releases what it held for it at once.
//!
//! Capture input selects a network before looking up a pair of endpoints.
//! Each network owns its connections, while all networks share the capture's
//! limits. Aggregate connection identities retain the network and generation.
//!
//! What the observer saw of each segment that is not part of a stream,
//! such as its sequence numbers relative to the connection and whether it
//! was a retransmission, goes to its reports ([`ObserverReport`]). Nothing a
//! child needs travels only there.
//!
//! ```
//! use std::sync::Arc;
//! use fictionet::stdlib::layer::{Budget, Chunk, Driver, MuxEvent, ObservedEvent, PacketEvent, Admit};
//! use fictionet::stdlib::network::ip::{self, protocol};
//! use fictionet::stdlib::network::observer::Observer;
//! use fictionet::stdlib::network::packet::{Ingress, ObservedIpPacket};
//! use fictionet::time::Instant;
//! use fictionet::{Seed, SeededEntropy};
//!
//! // A TCP segment from port 40000 to port 80, sequence 7, carrying "hi".
//! let mut segment = vec![0x9c, 0x40, 0, 80, 0, 0, 0, 7, 0, 0, 0, 0, 0x50, 0x18, 0, 0, 0, 0, 0, 0];
//! segment.extend_from_slice(b"hi");
//! let packet = ip::packet("10.0.0.2".parse()?, "10.0.0.1".parse()?, protocol::TCP, &segment);
//!
//! let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(1)));
//! let mut tcp = Driver::new(Observer::default(), entropy, Budget::unlimited(), Instant::ZERO);
//! let packet = ObservedIpPacket::observed(Chunk::new(packet.0), Ingress::default());
//! assert!(matches!(tcp.deliver(PacketEvent::Packet(packet)), Ok(Admit::Taken)));
//! let mut child = None;
//! tcp.send_above(|event| {
//!     if let MuxEvent::Opened(handle, connection, _) = event {
//!         assert_eq!(connection.first.port(), 40000);
//!         child = Some(handle);
//!     }
//!     Admit::Taken
//! });
//! // The child's bytes come up within the credit granted for it.
//! let child = child.unwrap();
//! assert!(tcp.command(child.grant(1 << 20)).is_ok());
//! tcp.send_above(|event| {
//!     if let MuxEvent::Child(_, ObservedEvent::Data { bytes, sequence, .. }) = event {
//!         assert_eq!((&bytes[..], sequence), (&b"hi"[..], 0));
//!     }
//!     Admit::Taken
//! });
//! # Ok::<(), std::net::AddrParseError>(())
//! ```

mod flow;

use core::convert::Infallible;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use fictionet::stdlib::codec::{be16, be32};
use fictionet::stdlib::layer::{
    Admit, ChildId, Chunk, Credited, Direction, Env, EventOf, Layer, MuxCommand, MuxEvent, MuxOp,
    ObservedEvent, ObservedStream, PacketCommand, PacketEvent, Packets, Slots, Source, Termination,
    Top,
};
use fictionet::stdlib::network::ip::protocol;
use fictionet::stdlib::network::packet::{ObservedIpPacket, Scope};
use fictionet::stdlib::network::transport::{ObservedConnection, TcpObserver};

use flow::{ACK, Flow, RST, SYN, Segment, Step, Store};

/// Bounds on what an [`Observer`] keeps. No storage is reserved in advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Payload bytes held out of order across every connection. The
    /// default is 8 MiB. Zero turns out-of-order holding off.
    pub buffered: usize,
    /// Segments held out of order in one direction, counting the places
    /// of segments dropped to stay in bounds. The default is 256. Zero
    /// turns out-of-order holding off.
    pub segments: usize,
    /// Connections followed at once, ended ones included. The default is
    /// 256. Zero is raised to one. A connection past this evicts the one
    /// seen longest ago.
    pub connections: usize,
    /// Bytes of observed data waiting for the layer above to take them or
    /// grant credit for them, across every connection, with 64 more counted
    /// for each waiting piece of data or gap. The default is 8 MiB. It is
    /// checked as each packet comes, so what one packet releases at once
    /// never counts against it: while more than this waits, the connection
    /// with the most waiting is evicted.
    pub waiting: usize,
}

impl Default for Limits {
    /// 8 MiB held out of order, 256 segments a direction, 256 connections
    /// and 8 MiB waiting.
    fn default() -> Limits {
        Limits {
            buffered: 8 << 20,
            segments: 256,
            connections: 256,
            waiting: 8 << 20,
        }
    }
}

/// What an [`Observer`] saw that is not part of an observed stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverReport {
    /// A TCP segment was read.
    Segment {
        /// The connection it belongs to.
        connection: ObservedConnection,
        /// The way it went.
        direction: Direction,
        /// Its sequence number, relative to the first one seen in its
        /// direction.
        sequence: u32,
        /// Its acknowledgment number, relative to the first sequence number
        /// seen the other way, or zero when it has no ACK or that is not
        /// known.
        acknowledgment: u32,
        /// Every sequence number of its payload had been passed already.
        retransmission: bool,
    },
    /// Payload or a FIN of the segment could not be kept, to stay in bounds
    /// or because its sequence number was too far from what was expected,
    /// and nothing was skipped for it: the direction still waits for
    /// earlier bytes.
    Dropped {
        /// The connection.
        connection: ObservedConnection,
        /// The direction.
        direction: Direction,
    },
    /// Payload came after its direction ended. It was not delivered.
    Late {
        /// The connection.
        connection: ObservedConnection,
        /// The direction.
        direction: Direction,
        /// How many bytes were not delivered.
        bytes: usize,
    },
    /// A connection started while every child slot was in use, waiting for
    /// the layer above to take what earlier children left. Its traffic is
    /// not delivered.
    Unwatched {
        /// The connection.
        connection: ObservedConnection,
    },
}

/// Endpoints in a network's local table, with the lower endpoint first.
type LocalKey = (SocketAddr, SocketAddr);
/// A child's association with its network and local connection.
type Key = (Scope, SocketAddr, SocketAddr);

/// Each event a child has waiting counts this much towards
/// [`Limits::waiting`], besides its bytes.
const OVERHEAD: usize = 64;

fn index(direction: Direction) -> usize {
    match direction {
        Direction::Forward => 0,
        Direction::Reverse => 1,
    }
}

const DIRECTIONS: [Direction; 2] = [Direction::Forward, Direction::Reverse];

/// One generation of one pair of endpoints.
struct Connection {
    info: ObservedConnection,
    /// Each direction's reassembly, once a packet went that way.
    flows: [Option<Flow>; 2],
    /// Whether anything went up for each direction.
    emitted: [bool; 2],
    /// Whether each direction's end went up.
    ended: [bool; 2],
    /// The child it is delivered to, until it ended or was let go.
    child: Option<ChildId>,
    /// When a packet last came for it, in packets.
    last: u64,
}

/// What one child has waiting to go up.
struct Output {
    key: Key,
    credit: u64,
    pending: VecDeque<ObservedEvent>,
    /// What `pending` counts towards [`Limits::waiting`].
    weight: usize,
    /// Whether each direction's end has gone up.
    delivered_end: [bool; 2],
    /// Close the child once `pending` is empty.
    closing: bool,
    /// Whether it is in the ready queue.
    queued: bool,
}

/// The passive TCP observer. See the [module docs](self).
pub struct Observer {
    store: Store,
    networks: BTreeMap<Scope, BTreeMap<LocalKey, Connection>>,
    children: Slots<Output>,
    /// Children opened, not yet taken.
    opened: VecDeque<MuxEvent<ObservedStream, Top, ObservedConnection>>,
    /// Children with something to send, in turn.
    ready: VecDeque<ChildId>,
    /// What every child's waiting events count towards [`Limits::waiting`].
    waiting: usize,
    /// Packets taken so far.
    tick: u64,
    /// The capture ended.
    finished: bool,
}

impl Default for Observer {
    /// An observer with the default [`Limits`].
    fn default() -> Observer {
        Observer::new(Limits::default())
    }
}

impl Observer {
    /// An observer within `limits`, with `connections` raised to one.
    pub fn new(mut limits: Limits) -> Observer {
        limits.connections = limits.connections.max(1);
        Observer {
            store: Store { limits, held: 0 },
            networks: BTreeMap::new(),
            children: Slots::new(limits.connections.saturating_mul(2)),
            opened: VecDeque::new(),
            ready: VecDeque::new(),
            waiting: 0,
            tick: 0,
            finished: false,
        }
    }

    /// The bounds in effect.
    pub fn limits(&self) -> Limits {
        self.store.limits
    }

    /// Payload bytes held out of order across every connection.
    pub fn buffered(&self) -> usize {
        self.store.held
    }

    /// How many connections are followed, ended ones included.
    pub fn connections(&self) -> usize {
        self.networks.values().map(BTreeMap::len).sum()
    }

    /// Takes one captured packet, once what the layer above left waiting
    /// fits [`Limits::waiting`].
    fn packet(&mut self, env: &mut Env<'_, ObserverReport>, packet: &ObservedIpPacket) {
        self.make_room();
        let Some(header) = packet.header() else {
            return;
        };
        if header.protocol != protocol::TCP || header.fragment.is_some_and(|f| f.offset != 0) {
            return;
        }
        let tcp = packet.payload();
        let off = tcp.get(12).map_or(0, |b| usize::from(b >> 4) * 4);
        let (Some(sport), Some(dport), Some(seq), Some(ack), Some(&flags)) = (
            be16(tcp, 0),
            be16(tcp, 2),
            be32(tcp, 4),
            be32(tcp, 8),
            tcp.get(13),
        ) else {
            return;
        };
        if off < 20 || off > tcp.len() {
            return;
        }
        // A first fragment holds only the start of its segment's payload.
        let whole = packet.is_complete() && header.fragment.is_none_or(|f| f.is_atomic());
        let segment = Segment {
            seq,
            flags,
            payload: whole.then(|| &tcp[off..]),
            source: packet.ingress().capture.map(|capture| Source {
                packet: capture.number,
                offset: header.payload.start + off,
            }),
        };
        let src = SocketAddr::new(header.src, sport);
        let dst = SocketAddr::new(header.dst, dport);
        self.tick += 1;
        self.segment(env, packet.ingress().scope, src, dst, ack, segment);
    }

    fn segment(
        &mut self,
        env: &mut Env<'_, ObserverReport>,
        scope: Scope,
        src: SocketAddr,
        dst: SocketAddr,
        ack: u32,
        segment: Segment<'_>,
    ) {
        let key = if src <= dst {
            (scope, src, dst)
        } else {
            (scope, dst, src)
        };
        let syn = segment.flags & SYN != 0;
        let acks = segment.flags & ACK != 0;
        let payload = segment.payload.map(<[u8]>::len);
        let start = |generation| ObservedConnection {
            scope,
            first: src,
            second: dst,
            generation,
            opened: syn.then_some(if acks {
                Direction::Reverse
            } else {
                Direction::Forward
            }),
        };
        // What a SYN does: repeat the one that opened its direction, open
        // the direction that answers the other side's SYN, or start a new
        // connection on these endpoints.
        enum Opens {
            Nothing,
            Answer,
            Connection(u64),
        }
        let opens = match self
            .networks
            .get(&key.0)
            .and_then(|network| network.get(&(key.1, key.2)))
        {
            None => Opens::Connection(0),
            Some(connection) if syn => {
                let d = index(direction(&connection.info, src));
                let repeated = connection.flows[d]
                    .as_ref()
                    .is_some_and(|flow| flow.repeats_syn(segment.seq));
                let answers = acks
                    && connection.flows[1 - d]
                        .as_ref()
                        .is_some_and(|back| back.acknowledged_by(ack));
                let fresh = !connection.emitted[d] && !connection.ended[d];
                if repeated {
                    Opens::Nothing
                } else if answers && fresh {
                    Opens::Answer
                } else {
                    Opens::Connection(connection.info.generation.saturating_add(1))
                }
            }
            Some(_) => Opens::Nothing,
        };
        match opens {
            Opens::Nothing => {}
            Opens::Answer => {
                if let Some(connection) = self
                    .networks
                    .get_mut(&key.0)
                    .and_then(|network| network.get_mut(&(key.1, key.2)))
                {
                    let d = index(direction(&connection.info, src));
                    if let Some(old) = &mut connection.flows[d] {
                        old.end(&mut self.store);
                    }
                    connection.flows[d] = Some(Flow::opened(segment.seq, payload));
                }
            }
            Opens::Connection(generation) => {
                if generation != 0 {
                    self.let_go(key, Termination::Replaced);
                } else if self.connections() >= self.store.limits.connections {
                    self.evict_oldest();
                }
                self.start(env, key, start(generation));
            }
        }
        let Some(connection) = self
            .networks
            .get_mut(&key.0)
            .and_then(|network| network.get_mut(&(key.1, key.2)))
        else {
            return;
        };
        connection.last = self.tick;
        let direction = direction(&connection.info, src);
        let d = index(direction);
        let info = connection.info;
        let flow = connection.flows[d].get_or_insert_with(|| {
            if syn {
                Flow::opened(segment.seq, payload)
            } else {
                Flow::midstream(segment.seq)
            }
        });
        // A direction that ended, or that was never followed, takes no
        // more: what comes is late.
        if connection.ended[d] && !flow.ended() {
            flow.end(&mut self.store);
        }
        let mut steps = Vec::new();
        let pushed = flow.push(segment, &mut self.store, &mut steps);
        let acknowledgment = match &connection.flows[1 - d] {
            Some(back) if acks => back.relative(ack),
            _ => 0,
        };
        env.report(ObserverReport::Segment {
            connection: info,
            direction,
            sequence: pushed.rel_seq,
            acknowledgment,
            retransmission: pushed.retransmission,
        });
        if pushed.dropped {
            env.report(ObserverReport::Dropped {
                connection: info,
                direction,
            });
        }
        if pushed.late != 0 {
            env.report(ObserverReport::Late {
                connection: info,
                direction,
                bytes: pushed.late,
            });
        }
        let child = connection.child;
        let mut events = Vec::with_capacity(steps.len() + 2);
        for step in steps {
            events.push(match step {
                Step::Data {
                    sequence,
                    bytes,
                    source,
                } => ObservedEvent::Data {
                    direction,
                    bytes: Chunk::new(bytes),
                    sequence,
                    source,
                },
                Step::Gap { sequence, missing } => ObservedEvent::Gap {
                    direction,
                    sequence,
                    missing: Some(missing),
                },
                Step::Fin => {
                    connection.ended[d] = true;
                    ObservedEvent::End {
                        direction,
                        cause: Termination::Fin,
                    }
                }
            });
        }
        if !events.is_empty() {
            connection.emitted[d] = true;
        }
        if segment.flags & RST != 0 {
            for other in DIRECTIONS {
                let i = index(other);
                if connection.ended[i] {
                    continue;
                }
                connection.ended[i] = true;
                if let Some(flow) = &mut connection.flows[i] {
                    flow.end(&mut self.store);
                }
                events.push(ObservedEvent::End {
                    direction: other,
                    cause: Termination::Reset,
                });
            }
        }
        let both = connection.ended == [true, true];
        if both {
            connection.child = None;
        }
        if let Some(child) = child {
            for event in events {
                self.push(child, event);
            }
            if both {
                self.close(child);
            }
        }
    }

    /// Opens a child for a new connection.
    fn start(&mut self, env: &mut Env<'_, ObserverReport>, key: Key, info: ObservedConnection) {
        let child = match self.children.insert(Output {
            key,
            credit: 0,
            pending: VecDeque::new(),
            weight: 0,
            delivered_end: [false; 2],
            closing: false,
            queued: false,
        }) {
            Ok(child) => {
                let id = child.id();
                self.opened.push_back(MuxEvent::Opened(child, info, 0));
                Some(id)
            }
            Err(_) => {
                env.report(ObserverReport::Unwatched { connection: info });
                None
            }
        };
        self.networks.entry(key.0).or_default().insert(
            (key.1, key.2),
            Connection {
                info,
                flows: [None, None],
                emitted: [false; 2],
                ended: [child.is_none(); 2],
                child,
                last: self.tick,
            },
        );
    }

    /// Evicts the connection seen longest ago.
    fn evict_oldest(&mut self) {
        let oldest = self
            .networks
            .iter()
            .flat_map(|(scope, network)| {
                network
                    .iter()
                    .map(move |((a, b), connection)| ((*scope, *a, *b), connection))
            })
            .min_by_key(|(_, connection)| connection.last)
            .map(|(key, _)| key);
        if let Some(key) = oldest {
            self.let_go(key, Termination::Evicted);
            if let Some(network) = self.networks.get_mut(&key.0) {
                network.remove(&(key.1, key.2));
                if network.is_empty() {
                    self.networks.remove(&key.0);
                }
            }
        }
    }

    /// Stops following the connection at `key`: its open directions end
    /// with `cause`, it gives back what it held, and it stays only as the
    /// ended generation, which a new SYN replaces.
    fn let_go(&mut self, key: Key, cause: Termination) {
        let Some(connection) = self
            .networks
            .get_mut(&key.0)
            .and_then(|network| network.get_mut(&(key.1, key.2)))
        else {
            return;
        };
        let mut events = Vec::new();
        for direction in DIRECTIONS {
            let i = index(direction);
            if let Some(flow) = &mut connection.flows[i] {
                flow.end(&mut self.store);
            }
            if !connection.ended[i] {
                connection.ended[i] = true;
                events.push(ObservedEvent::End { direction, cause });
            }
        }
        if let Some(child) = connection.child.take() {
            for event in events {
                self.push(child, event);
            }
            self.close(child);
        }
    }

    /// Queues `event` for `child`.
    fn push(&mut self, child: ChildId, event: ObservedEvent) {
        let Some(output) = self.children.get_mut(child) else {
            return;
        };
        let weight = weight(&event);
        output.weight = output.weight.saturating_add(weight);
        self.waiting = self.waiting.saturating_add(weight);
        output.pending.push_back(event);
        if !output.queued {
            output.queued = true;
            self.ready.push_back(child);
        }
    }

    /// Closes `child` once what it has waiting is taken.
    fn close(&mut self, child: ChildId) {
        let Some(output) = self.children.get_mut(child) else {
            return;
        };
        output.closing = true;
        if !output.queued {
            output.queued = true;
            self.ready.push_back(child);
        }
    }

    /// Stops only the generation still attached to this child.
    fn detach(&mut self, key: Key, child: ChildId) {
        if let Some(connection) = self
            .networks
            .get_mut(&key.0)
            .and_then(|network| network.get_mut(&(key.1, key.2)))
            && connection.child == Some(child)
        {
            connection.child = None;
            connection.ended = [true; 2];
            for flow in connection.flows.iter_mut().flatten() {
                flow.end(&mut self.store);
            }
        }
    }

    /// Evicts the connections with the most waiting until what is waiting
    /// fits [`Limits::waiting`].
    fn make_room(&mut self) {
        while self.waiting > self.store.limits.waiting {
            let heaviest = self
                .children
                .ids()
                .filter_map(|id| {
                    let output = self.children.get(id)?;
                    Some((output.weight, id, output.key))
                })
                .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            let Some((weight, child, key)) = heaviest.filter(|(weight, _, _)| *weight != 0) else {
                break;
            };
            self.detach(key, child);
            self.waiting = self.waiting.saturating_sub(weight);
            let Some(output) = self.children.get_mut(child) else {
                break;
            };
            output.pending.clear();
            output.weight = 0;
            for direction in DIRECTIONS {
                if !output.delivered_end[index(direction)] {
                    output.pending.push_back(ObservedEvent::End {
                        direction,
                        cause: Termination::Evicted,
                    });
                }
            }
            self.close(child);
        }
    }

    /// Finishes every connection at the end of the capture, in endpoint
    /// order.
    fn finish(&mut self) {
        let keys: Vec<Key> = self
            .networks
            .iter()
            .flat_map(|(scope, network)| network.keys().map(move |(a, b)| (*scope, *a, *b)))
            .collect();
        for key in keys {
            let Some(connection) = self
                .networks
                .get_mut(&key.0)
                .and_then(|network| network.get_mut(&(key.1, key.2)))
            else {
                continue;
            };
            let Some(child) = connection.child.take() else {
                continue;
            };
            let mut events = Vec::new();
            for direction in DIRECTIONS {
                let i = index(direction);
                if connection.ended[i] {
                    continue;
                }
                connection.ended[i] = true;
                let mut holed = false;
                if let Some(flow) = &mut connection.flows[i] {
                    holed = flow.holed();
                    let mut steps = Vec::new();
                    flow.finish(&mut self.store, &mut steps);
                    for step in steps {
                        match step {
                            Step::Data {
                                sequence,
                                bytes,
                                source,
                            } => events.push(ObservedEvent::Data {
                                direction,
                                bytes: Chunk::new(bytes),
                                sequence,
                                source,
                            }),
                            Step::Gap { sequence, missing } => events.push(ObservedEvent::Gap {
                                direction,
                                sequence,
                                missing: Some(missing),
                            }),
                            Step::Fin => {}
                        }
                    }
                }
                events.push(ObservedEvent::End {
                    direction,
                    cause: if holed {
                        Termination::Truncated
                    } else {
                        Termination::Finalized
                    },
                });
            }
            for event in events {
                self.push(child, event);
            }
            self.close(child);
        }
    }
}

/// Which way a packet from `src` goes on `connection`.
fn direction(connection: &ObservedConnection, src: SocketAddr) -> Direction {
    if src == connection.first {
        Direction::Forward
    } else {
        Direction::Reverse
    }
}

/// What `event` counts towards [`Limits::waiting`] while it waits.
fn weight(event: &ObservedEvent) -> usize {
    match event {
        ObservedEvent::Data { bytes, .. } => bytes.len().saturating_add(OVERHEAD),
        ObservedEvent::Gap { .. } => OVERHEAD,
        // At most two a child, and never refused for credit.
        ObservedEvent::End { .. } => 0,
    }
}

impl Layer for Observer {
    type Lower = Packets<ObservedIpPacket, Infallible>;
    type Upper = TcpObserver;
    type Report = ObserverReport;
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn report_bytes(_: &ObserverReport) -> Option<usize> {
        Some(0)
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, ObserverReport>,
        event: PacketEvent<ObservedIpPacket>,
    ) -> Result<Admit<PacketEvent<ObservedIpPacket>>, Infallible> {
        if self.finished {
            return Ok(Admit::Closed(event));
        }
        match &event {
            PacketEvent::Packet(packet) => self.packet(env, packet),
            PacketEvent::Ended => {
                self.finished = true;
                self.finish();
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, ObserverReport>,
        command: MuxCommand<ObservedStream, Top>,
    ) -> Result<Admit<MuxCommand<ObservedStream, Top>>, Infallible> {
        match command.into_op() {
            MuxOp::Child(_, command) => match command {},
            MuxOp::Control(command) => match command {},
            MuxOp::Credit(child, units) => {
                if let Some(output) = self.children.get_mut(child) {
                    output.credit = output.credit.saturating_add(units);
                    if !output.queued && (!output.pending.is_empty() || output.closing) {
                        output.queued = true;
                        self.ready.push_back(child);
                    }
                }
            }
            MuxOp::Close(child) => {
                if let Some(output) = self.children.remove(child) {
                    self.waiting = self.waiting.saturating_sub(output.weight);
                    self.detach(output.key, child);
                }
            }
        }
        Ok(Admit::Taken)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<PacketCommand<Infallible>> {
        None
    }

    fn take_event(&mut self) -> Option<EventOf<TcpObserver>> {
        if let Some(opened) = self.opened.pop_front() {
            return Some(opened);
        }
        for _ in 0..self.ready.len() {
            let child = self.ready.pop_front()?;
            let Some(output) = self.children.get_mut(child) else {
                continue;
            };
            output.queued = false;
            let Some(event) = output.pending.front() else {
                if output.closing {
                    self.children.remove(child);
                    return Some(MuxEvent::Closed(child));
                }
                continue;
            };
            let cost = event.credit();
            if cost > output.credit {
                // It waits for credit, and comes back with it.
                continue;
            }
            output.credit -= cost;
            let event = output.pending.pop_front()?;
            let weight = weight(&event);
            output.weight = output.weight.saturating_sub(weight);
            self.waiting = self.waiting.saturating_sub(weight);
            if let ObservedEvent::End { direction, .. } = event {
                output.delivered_end[index(direction)] = true;
            }
            if !output.pending.is_empty() || output.closing {
                output.queued = true;
                self.ready.push_back(child);
            }
            return Some(MuxEvent::Child(child, event));
        }
        None
    }
}

#[cfg(test)]
mod tests;
