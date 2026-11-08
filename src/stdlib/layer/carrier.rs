//! The four carrier contracts and the handles of multiplexed children.

use core::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Buf, Bytes};

use fictionet::stdlib::layer::{Charge, CommandOf, EventOf, Port};

// ---------------------------------------------------------------------------
// Bytes

/// Owned bytes on their way through a stack, with what they cost.
///
/// A receiver that takes only part of a chunk [`advance`](Self::advance)s
/// past what it took and hands the chunk back, so the rest keeps its place.
/// The [`Charge`] that paid for the whole allocation goes wherever the chunk
/// goes and is given back when the chunk is dropped.
pub struct Chunk {
    bytes: Bytes,
    charge: Option<Charge>,
}

impl Chunk {
    /// Bytes nothing has been charged for, such as input whose owner
    /// accounts for it.
    pub fn new(bytes: impl Into<Bytes>) -> Chunk {
        Chunk {
            bytes: bytes.into(),
            charge: None,
        }
    }

    /// Bytes paid for by `charge`, which should cover their whole
    /// allocation. Take the charge before allocating.
    pub fn with_charge(bytes: impl Into<Bytes>, charge: Charge) -> Chunk {
        Chunk {
            bytes: bytes.into(),
            charge: Some(charge),
        }
    }

    /// The bytes not yet taken.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether every byte has been taken.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Marks the first `n` bytes as taken. Panics if fewer remain.
    pub fn advance(&mut self, n: usize) {
        self.bytes.advance(n);
    }

    /// The bytes charged for this chunk.
    pub fn charged(&self) -> usize {
        self.charge.as_ref().map_or(0, Charge::bytes)
    }
}

impl core::ops::Deref for Chunk {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Chunk")
            .field("len", &self.len())
            .field("charged", &self.charged())
            .finish()
    }
}

/// What a value uses of a child's credit (see [`Mux`]).
pub trait Credited {
    /// The credit units this value uses.
    fn credit(&self) -> u64;
}

// ---------------------------------------------------------------------------
// The ordered byte stream

/// An ordered byte stream: TCP, TLS plaintext, an SSH channel's data, a
/// CONNECT tunnel.
///
/// Bytes arrive in order and chunk boundaries mean nothing. Each direction
/// ends on its own. A receiver may take part of a chunk
/// ([`Admit::Partial`](super::Admit::Partial)). Writing is three steps: the
/// layer below takes the bytes, hands them on, and later says the transport
/// took them ([`StreamEvent::Written`]).
#[derive(Clone, Copy, Debug)]
pub struct ByteStream;

impl Port for ByteStream {
    type Event = StreamEvent;
    type Command = StreamCommand;
}

/// What comes up a byte stream.
#[derive(Debug)]
pub enum StreamEvent {
    /// The next bytes from the peer.
    Data(Chunk),
    /// The transport took this many more of the bytes written to it. This
    /// is not proof the peer read them.
    Written(u64),
    /// The peer will send nothing more. The other direction stays open.
    Ended,
    /// The connection was reset: both directions are gone.
    Reset,
}

/// What goes down a byte stream.
#[derive(Debug)]
pub enum StreamCommand {
    /// Bytes to send, after the ones before.
    Write(Chunk),
    /// Nothing more will be sent. The other direction stays open.
    End,
    /// Reset the connection.
    Reset,
}

impl Credited for StreamEvent {
    fn credit(&self) -> u64 {
        match self {
            StreamEvent::Data(chunk) => chunk.len() as u64,
            _ => 0,
        }
    }
}

impl Credited for StreamCommand {
    fn credit(&self) -> u64 {
        match self {
            StreamCommand::Write(chunk) => chunk.len() as u64,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Datagrams

/// Datagrams with endpoint metadata `M`, such as UDP with its addresses.
///
/// Each datagram is whole, and an empty one is still a datagram. Nothing
/// takes part of one: [`Datagram`] has no way to split. This carrier
/// promises nothing about delivery: a datagram may be lost, repeated or
/// reordered, and one datagram ending is not the conversation ending.
pub struct Datagrams<M>(PhantomData<fn() -> M>);

impl<M> Port for Datagrams<M> {
    type Event = DatagramEvent<M>;
    type Command = DatagramCommand<M>;
}

/// One whole datagram and where it is from or going.
#[derive(Debug)]
pub struct Datagram<M> {
    payload: Chunk,
    meta: M,
}

impl<M> Datagram<M> {
    /// A datagram of `payload`, from or to `meta`.
    pub fn new(payload: Chunk, meta: M) -> Datagram<M> {
        Datagram { payload, meta }
    }

    /// Its bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Its endpoint metadata.
    pub fn meta(&self) -> &M {
        &self.meta
    }

    /// Its bytes and metadata.
    pub fn into_parts(self) -> (Chunk, M) {
        (self.payload, self.meta)
    }
}

/// What comes up a datagram port.
#[derive(Debug)]
pub enum DatagramEvent<M> {
    /// One datagram.
    Datagram(Datagram<M>),
    /// The socket closed: no more datagrams.
    Ended,
}

/// What goes down a datagram port.
#[derive(Debug)]
pub enum DatagramCommand<M> {
    /// Send one datagram.
    Send(Datagram<M>),
    /// Close the socket.
    End,
}

impl<M> Credited for DatagramEvent<M> {
    fn credit(&self) -> u64 {
        u64::from(matches!(self, DatagramEvent::Datagram(_)))
    }
}

impl<M> Credited for DatagramCommand<M> {
    fn credit(&self) -> u64 {
        u64::from(matches!(self, DatagramCommand::Send(_)))
    }
}

// ---------------------------------------------------------------------------
// Typed messages

/// Whole typed protocol units: `I` coming up, `O` going down. A request
/// with its correlation, a decoded frame, a connection's control messages.
/// A message boundary is never an end of input; the end is its own event.
pub struct Messages<I, O = I>(PhantomData<fn() -> (I, O)>);

impl<I, O> Port for Messages<I, O> {
    type Event = MessageEvent<I>;
    type Command = MessageCommand<O>;
}

/// What comes up a message port.
#[derive(Debug, PartialEq, Eq)]
pub enum MessageEvent<I> {
    /// One message.
    Message(I),
    /// No more messages will come.
    Ended,
}

/// What goes down a message port.
#[derive(Debug, PartialEq, Eq)]
pub enum MessageCommand<O> {
    /// Send one message.
    Send(O),
    /// No more messages will be sent.
    End,
}

impl<I> Credited for MessageEvent<I> {
    fn credit(&self) -> u64 {
        u64::from(matches!(self, MessageEvent::Message(_)))
    }
}

impl<O> Credited for MessageCommand<O> {
    fn credit(&self) -> u64 {
        u64::from(matches!(self, MessageCommand::Send(_)))
    }
}

// ---------------------------------------------------------------------------
// Multiplexed children

/// A connection with children: connection control of port `K`, plus any
/// number of children, each speaking port `C`. HTTP/2 streams, SSH
/// channels, QUIC streams.
///
/// A child is opened by the peer or by asking ([`MuxCommand::open`]), and
/// the upper side receives its [`Child`] handle in [`MuxEvent::Opened`].
/// Commands for a child can only be made from its handle, and closing
/// consumes the handle.
///
/// Children's traffic moves under credit, in both directions, counted by
/// [`Credited`]. The mux sends a child's events up only within the credit
/// the upper side granted ([`Child::grant`]), and the upper side sends a
/// child's commands down only within the credit the mux granted
/// ([`MuxEvent::Credit`]). So neither side ever has to refuse one child's
/// traffic, and a child that stops reading holds only its own credit while
/// its siblings and the connection's control traffic go on. Refusing a
/// whole item ([`Admit::Blocked`](super::Admit::Blocked)) is left for the
/// connection as a whole.
pub struct Mux<C, K>(PhantomData<fn() -> (C, K)>);

impl<C: Port, K: Port> Port for Mux<C, K> {
    type Event = MuxEvent<C, K>;
    type Command = MuxCommand<C, K>;
}

/// What comes up from a multiplexed connection.
pub enum MuxEvent<C: Port, K: Port> {
    /// A new child, opened by the peer or because the upper side asked.
    /// The handle is the only way to address it.
    Opened(Child),
    /// An event of one child, within the credit granted for it.
    Child(ChildId, EventOf<C>),
    /// The child may send this many more credit units.
    Credit(ChildId, u64),
    /// The child is gone. Its id, and any handle for it, will never be
    /// valid again.
    Closed(ChildId),
    /// A connection control event.
    Control(EventOf<K>),
}

/// What goes down to a multiplexed connection. Commands for a child are
/// made only from its [`Child`] handle; [`op`](Self::op) reads one.
pub struct MuxCommand<C: Port, K: Port>(MuxOp<C, K>);

/// What a [`MuxCommand`] asks for.
pub enum MuxOp<C: Port, K: Port> {
    /// Open a child; the answer is [`MuxEvent::Opened`].
    Open,
    /// A command for one child, within the credit the mux granted.
    Child(ChildId, CommandOf<C>),
    /// The child's events may use this many more credit units.
    Credit(ChildId, u64),
    /// Close the child at once, as a reset does.
    Close(ChildId),
    /// A connection control command.
    Control(CommandOf<K>),
}

impl<C: Port, K: Port> MuxCommand<C, K> {
    /// Asks the connection to open a child.
    pub fn open() -> MuxCommand<C, K> {
        MuxCommand(MuxOp::Open)
    }

    /// A connection control command.
    pub fn control(command: CommandOf<K>) -> MuxCommand<C, K> {
        MuxCommand(MuxOp::Control(command))
    }

    /// What it asks for.
    pub fn op(&self) -> &MuxOp<C, K> {
        &self.0
    }

    /// What it asks for, owned.
    pub fn into_op(self) -> MuxOp<C, K> {
        self.0
    }
}

impl<C: Port, K: Port> core::fmt::Debug for MuxCommand<C, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match &self.0 {
            MuxOp::Open => "Open",
            MuxOp::Child(..) => "Child",
            MuxOp::Credit(..) => "Credit",
            MuxOp::Close(_) => "Close",
            MuxOp::Control(_) => "Control",
        })
    }
}

/// Which child, of which connection, in which generation of its slot.
///
/// Two children are the same only if all three match, so an id outlives
/// its child harmlessly: the connection that reuses the slot gives the
/// successor a new generation, and another connection's children have
/// another scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChildId {
    scope: u64,
    slot: u32,
    generation: u64,
}

/// The upper side's handle on one child. It is not `Clone`: each child has
/// one owner, and [`close`](Self::close) consumes it.
#[derive(Debug, PartialEq, Eq)]
pub struct Child {
    id: ChildId,
}

impl Child {
    /// Which child this is.
    pub fn id(&self) -> ChildId {
        self.id
    }

    /// A command for this child.
    pub fn send<C: Port, K: Port>(&self, command: CommandOf<C>) -> MuxCommand<C, K> {
        MuxCommand(MuxOp::Child(self.id, command))
    }

    /// Lets the mux send this child's events using `units` more credit.
    pub fn grant<C: Port, K: Port>(&self, units: u64) -> MuxCommand<C, K> {
        MuxCommand(MuxOp::Credit(self.id, units))
    }

    /// Closes the child at once, giving up the handle.
    pub fn close<C: Port, K: Port>(self) -> MuxCommand<C, K> {
        MuxCommand(MuxOp::Close(self.id))
    }
}

/// Numbers each [`Slots`], so ids of different connections never match.
static SCOPES: AtomicU64 = AtomicU64::new(1);

/// A mux's children, each with the state `T` it keeps for it.
///
/// [`insert`](Self::insert) makes the [`Child`] handle that goes up in
/// [`MuxEvent::Opened`]; it is the only way to make one. Every lookup checks
/// the id's scope and generation, so a stale id finds nothing. The number of
/// children is bounded. Iteration is in slot order, the same in every run.
pub struct Slots<T> {
    scope: u64,
    entries: Vec<(u64, Option<T>)>,
    free: Vec<u32>,
    live: usize,
    limit: usize,
}

impl<T> Slots<T> {
    /// Room for at most `limit` children at once.
    pub fn new(limit: usize) -> Slots<T> {
        Slots {
            scope: SCOPES.fetch_add(1, Ordering::Relaxed),
            entries: Vec::new(),
            free: Vec::new(),
            live: 0,
            limit: limit.min(u32::MAX as usize),
        }
    }

    /// Adds a child, or hands `value` back when the limit is reached.
    pub fn insert(&mut self, value: T) -> Result<Child, T> {
        if self.live >= self.limit {
            return Err(value);
        }
        let slot = match self.free.pop() {
            Some(slot) => slot,
            None => {
                self.entries.push((0, None));
                (self.entries.len() - 1) as u32
            }
        };
        let entry = &mut self.entries[slot as usize];
        entry.1 = Some(value);
        self.live += 1;
        Ok(Child {
            id: ChildId {
                scope: self.scope,
                slot,
                generation: entry.0,
            },
        })
    }

    fn entry(&self, id: ChildId) -> Option<&(u64, Option<T>)> {
        if id.scope != self.scope {
            return None;
        }
        self.entries
            .get(id.slot as usize)
            .filter(|(generation, _)| *generation == id.generation)
    }

    /// Whether `id` is a live child of this connection.
    pub fn contains(&self, id: ChildId) -> bool {
        self.entry(id).is_some_and(|(_, v)| v.is_some())
    }

    /// The state of child `id`, if it is live.
    pub fn get(&self, id: ChildId) -> Option<&T> {
        self.entry(id).and_then(|(_, v)| v.as_ref())
    }

    /// The state of child `id`, if it is live.
    pub fn get_mut(&mut self, id: ChildId) -> Option<&mut T> {
        if !self.contains(id) {
            return None;
        }
        self.entries[id.slot as usize].1.as_mut()
    }

    /// Removes child `id`. Its slot's next child gets a new generation.
    pub fn remove(&mut self, id: ChildId) -> Option<T> {
        if !self.contains(id) {
            return None;
        }
        let entry = &mut self.entries[id.slot as usize];
        entry.0 += 1;
        let value = entry.1.take();
        self.free.push(id.slot);
        self.live -= 1;
        value
    }

    /// The live children's ids, in slot order.
    pub fn ids(&self) -> impl Iterator<Item = ChildId> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, (_, v))| v.is_some())
            .map(|(slot, (generation, _))| ChildId {
                scope: self.scope,
                slot: slot as u32,
                generation: *generation,
            })
    }

    /// How many children are live.
    pub fn len(&self) -> usize {
        self.live
    }

    /// Whether no children are live.
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// The most children at once.
    pub fn limit(&self) -> usize {
        self.limit
    }
}
