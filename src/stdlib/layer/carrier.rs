//! The four carrier contracts and the handles of multiplexed children.

use core::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::children::ChildWake;
use fictionet::stdlib::layer::{Budget, Charge, CommandOf, EventOf, Port};

// ---------------------------------------------------------------------------
// Bytes

/// Owned bytes on their way through a stack, with what they cost.
///
/// A receiver that takes only part of a chunk [`advance`](Self::advance)s
/// past what it took and hands the chunk back, so the rest keeps its place.
/// The backing holds two independent things that are given back when its
/// last piece is dropped: a reservation that pays for the allocation's
/// memory (its capacity), and an optional [`CreditLease`] that holds a
/// child's receive credit until the bytes are consumed. Every change to
/// either goes through the private transitions below. Shared cursor and
/// lease metadata are bounded engine storage: routers and layers must also
/// enforce item limits, including for empty chunks.
pub struct Chunk {
    backing: Arc<ChunkBacking>,
    start: usize,
    end: usize,
}

struct ChunkBacking {
    bytes: Vec<u8>,
    /// Memory: what pays for `bytes`' allocation, if anything does yet.
    reservation: Option<Reservation>,
    /// Flow control: receive credit the bytes hold until released.
    lease: Option<Arc<CreditLease>>,
}

/// What pays for a backing's memory: a charge of its own, or a share of
/// one that pays for many, such as a child's receive window.
enum Reservation {
    Own(Charge),
    Shared(Arc<Charge>),
}

impl Reservation {
    fn bytes(&self) -> usize {
        match self {
            Reservation::Own(charge) => charge.bytes(),
            Reservation::Shared(charge) => charge.bytes(),
        }
    }
}

impl Chunk {
    /// Bytes nothing has been charged for, such as input whose owner
    /// accounts for it.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Chunk {
        Self::backed(bytes.into(), None, None)
    }

    fn backed(
        bytes: Vec<u8>,
        reservation: Option<Reservation>,
        lease: Option<Arc<CreditLease>>,
    ) -> Chunk {
        let end = bytes.len();
        Chunk {
            backing: Arc::new(ChunkBacking {
                bytes,
                reservation,
                lease,
            }),
            start: 0,
            end,
        }
    }

    /// Bytes paid for by `charge`, which should cover their whole
    /// allocation. Take the charge before allocating.
    pub fn with_charge(bytes: Vec<u8>, charge: Charge) -> Chunk {
        assert!(
            charge.bytes() >= bytes.capacity(),
            "chunk backing exceeds its reservation"
        );
        Self::backed(bytes, Some(Reservation::Own(charge)), None)
    }

    /// The backing, when this chunk alone holds it and the bytes are all
    /// of it, so its reservation and lease can change in place.
    fn sole_whole(&mut self) -> Option<&mut ChunkBacking> {
        let whole = self.start == 0 && self.end == self.backing.bytes.len();
        whole.then(|| Arc::get_mut(&mut self.backing)).flatten()
    }

    /// Moves the remaining bytes into an allocation of their own size under
    /// `reservation` and `lease`. Other pieces keep the old backing.
    fn copy_under(&mut self, reservation: Reservation, lease: Option<Arc<CreditLease>>) {
        *self = Self::backed(self.to_vec(), Some(reservation), lease);
    }

    /// Puts the bytes under `charge`, which pays for them already, so what
    /// paid for them before may release, and drops any lease: the window
    /// that `charge` pays for takes a new one. In place when this chunk
    /// alone holds its backing and the bytes are all of it; otherwise they
    /// are copied into an allocation of their own size, so the shared charge
    /// covers no more than the bytes.
    pub(crate) fn reback(&mut self, charge: Arc<Charge>) {
        if let Some(backing) = self.sole_whole() {
            backing.bytes.shrink_to_fit();
            backing.reservation = Some(Reservation::Shared(charge));
            backing.lease = None;
            return;
        }
        self.copy_under(Reservation::Shared(charge), None);
    }

    /// Makes the bytes hold `lease` until every piece of them is released.
    /// The caller has just made this chunk the sole owner of its backing.
    pub(crate) fn lease(&mut self, lease: CreditLease) {
        Arc::get_mut(&mut self.backing)
            .expect("leased bytes are held by one chunk")
            .lease = Some(Arc::new(lease));
    }

    /// Puts the bytes under a charge from `budget`, so what paid for them
    /// before releases: for bytes handed from one owner to another. In
    /// place when this chunk alone holds its backing and the bytes are all
    /// of it; otherwise the bytes are copied into an allocation of their
    /// own. Receive credit stays with the bytes. Refusal leaves the chunk
    /// unchanged.
    pub fn recharge(&mut self, budget: &Budget) -> bool {
        if let Some(backing) = self.sole_whole() {
            let Some(charge) = budget.charge(backing.bytes.capacity()) else {
                return false;
            };
            backing.reservation = Some(Reservation::Own(charge));
            return true;
        }
        let Some(charge) = budget.charge(self.len()) else {
            return false;
        };
        let lease = self.backing.lease.clone();
        self.copy_under(Reservation::Own(charge), lease);
        true
    }

    /// The first `n` bytes, sharing this chunk's backing, without taking
    /// them from it. Panics if fewer remain.
    pub(crate) fn prefix(&self, n: usize) -> Chunk {
        assert!(n <= self.len(), "chunk prefix exceeds its remaining bytes");
        Chunk {
            backing: self.backing.clone(),
            start: self.start,
            end: self.start + n,
        }
    }

    /// The bytes not yet taken.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether every byte has been taken.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Marks the first `n` bytes as taken. Panics if fewer remain.
    pub fn advance(&mut self, n: usize) {
        assert!(n <= self.len(), "chunk cursor exceeds its remaining bytes");
        self.start += n;
    }

    /// Splits off a prefix without allocating. Both pieces retain the same
    /// backing reservation until their last owner releases it.
    pub fn split_to(&mut self, n: usize) -> Chunk {
        assert!(n <= self.len(), "chunk prefix exceeds its remaining bytes");
        let prefix = Chunk {
            backing: self.backing.clone(),
            start: self.start,
            end: self.start + n,
        };
        self.start += n;
        prefix
    }

    /// Reserves unaccounted backing before retaining it. Charged storage keeps
    /// its existing reservation, including any unread suffix. When this chunk
    /// alone holds its backing and the bytes are all of it, the charge is
    /// attached in place, after trimming spare capacity; otherwise the bytes
    /// are copied into an allocation of their own size. Receive credit stays
    /// with the bytes either way. Refusal leaves the bytes unreserved.
    pub fn reserve(&mut self, budget: &Budget) -> bool {
        if self.backing.reservation.is_some() {
            return true;
        }
        if let Some(backing) = self.sole_whole() {
            backing.bytes.shrink_to_fit();
            let Some(charge) = budget.charge(backing.bytes.capacity()) else {
                return false;
            };
            backing.reservation = Some(Reservation::Own(charge));
            return true;
        }
        let Some(charge) = budget.charge(self.len()) else {
            return false;
        };
        let lease = self.backing.lease.clone();
        self.copy_under(Reservation::Own(charge), lease);
        true
    }

    /// Edits the remaining bytes without losing their reservation or receive
    /// credit. Unique backing is reused. Shared backing is copied only after
    /// reserving the copy; refusal leaves the chunk unchanged. Receive credit
    /// remains held until every original and edited piece is released.
    pub fn make_mut(&mut self, budget: &Budget) -> Option<&mut [u8]> {
        if Arc::strong_count(&self.backing) != 1 {
            let charge = budget.charge(self.len())?;
            let lease = self.backing.lease.clone();
            self.copy_under(Reservation::Own(charge), lease);
        }
        let backing = Arc::get_mut(&mut self.backing).expect("copied or already sole");
        if backing.reservation.is_none() {
            let charge = budget.charge(backing.bytes.capacity())?;
            backing.reservation = Some(Reservation::Own(charge));
        }
        Some(&mut backing.bytes[self.start..self.end])
    }

    /// The bytes not yet taken, as a vector. Reuses the allocation when
    /// this chunk alone owns uncharged backing that holds exactly these
    /// bytes, and copies them otherwise. Any charge goes back when the
    /// chunk's backing is dropped: the vector carries none.
    pub fn into_vec(self) -> Vec<u8> {
        let whole = self.start == 0 && self.end == self.backing.bytes.len();
        if whole && self.backing.reservation.is_none() && self.backing.lease.is_none() {
            match Arc::try_unwrap(self.backing) {
                Ok(backing) => return backing.bytes,
                Err(backing) => return backing.bytes[self.start..self.end].to_vec(),
            }
        }
        self.to_vec()
    }

    /// The shared backing allocation's charge. Split pieces name the same
    /// charge; their charged values must not be added together.
    pub fn charged(&self) -> usize {
        self.backing.reservation.as_ref().map_or(0, Reservation::bytes)
    }
}

impl core::ops::Deref for Chunk {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.backing.bytes[self.start..self.end]
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

/// A lease on a child's receive credit, given back when dropped. It is
/// flow control only, separate from whatever pays for memory: a carrier
/// with retained data attaches it to its backing storage, so the credit
/// returns when the last piece of the payload is released.
pub struct CreditLease {
    child: Arc<ChildWake>,
    units: u64,
}

impl CreditLease {
    pub(crate) fn new(child: Arc<ChildWake>, units: u64) -> Self {
        Self { child, units }
    }
}

impl Drop for CreditLease {
    fn drop(&mut self) {
        self.child.release(self.units);
    }
}

/// What a value uses of a child's credit (see [`Mux`]).
pub trait Credited {
    /// The credit units this value uses.
    fn credit(&self) -> u64;

    /// Takes a legal prefix within `units`, returning the untouched item
    /// when this carrier is atomic or no prefix fits.
    fn admit_credit(self, units: u64) -> Result<(Self, Option<Self>), Self>
    where
        Self: Sized,
    {
        if self.credit() <= units {
            Ok((self, None))
        } else {
            Err(self)
        }
    }

    /// Backing bytes to reserve before advertising a receive window. This
    /// is independent of item slots and peer command credit. Carriers whose
    /// credit counts messages must supply a bounded payload policy separately.
    fn receive_bytes(_window: u64) -> Option<usize> {
        Some(0)
    }

    /// Admits a payload against the already reserved receive backing, or
    /// reserves its own separately accounted payload for an atomic carrier.
    fn reserve_receive(&mut self, budget: &Budget, _backing: &Arc<Charge>) -> bool {
        self.reserve(budget)
    }

    /// Reserves any retained payload before admission. Carrier implementations
    /// with owned storage must override this or carry a reservation already.
    fn reserve(&mut self, _budget: &Budget) -> bool {
        true
    }

    /// Attaches receive credit to the retained payload. Atomic messages use
    /// admission credit; byte and body carriers override this to retain it.
    fn retain_credit(&mut self, mut credit: CreditLease) -> bool {
        credit.units = 0;
        false
    }

    /// Whether credit can split this value at legal byte boundaries.
    fn splittable(&self) -> bool {
        false
    }

    /// Whether this event terminates the child and invalidates queued data.
    fn terminal_reset(&self) -> bool {
        false
    }
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

    fn urgent(event: &StreamEvent) -> bool {
        matches!(event, StreamEvent::Written(_) | StreamEvent::Reset)
    }
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
    fn terminal_reset(&self) -> bool {
        matches!(self, Self::Reset)
    }
    fn receive_bytes(window: u64) -> Option<usize> {
        usize::try_from(window).ok()
    }

    fn reserve_receive(&mut self, _: &Budget, backing: &Arc<Charge>) -> bool {
        if let Self::Data(chunk) = self {
            // The receive window pays for the bytes now; what paid before
            // may release.
            chunk.reback(backing.clone());
        }
        true
    }

    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            Self::Data(chunk) => chunk.reserve(budget),
            _ => true,
        }
    }

    fn retain_credit(&mut self, credit: CreditLease) -> bool {
        if let Self::Data(chunk) = self {
            chunk.lease(credit);
            true
        } else {
            false
        }
    }

    fn credit(&self) -> u64 {
        match self {
            StreamEvent::Data(chunk) => chunk.len() as u64,
            _ => 0,
        }
    }
}

impl Credited for StreamCommand {
    fn splittable(&self) -> bool {
        matches!(self, Self::Write(_))
    }
    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            Self::Write(chunk) => chunk.reserve(budget),
            _ => true,
        }
    }
    fn admit_credit(self, units: u64) -> Result<(Self, Option<Self>), Self> {
        if self.credit() <= units {
            return Ok((self, None));
        }
        match self {
            StreamCommand::Write(mut chunk) if units > 0 => {
                let prefix = chunk.split_to(units as usize);
                Ok((
                    StreamCommand::Write(prefix),
                    Some(StreamCommand::Write(chunk)),
                ))
            }
            command => Err(command),
        }
    }

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

    pub(super) fn payload_mut(&mut self) -> &mut Chunk {
        &mut self.payload
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
/// A child is opened by the peer or through typed connection control, and
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
pub struct Mux<C, K, O = ()>(PhantomData<fn(C, K, O)>);

impl<C: Port, K: Port, O> Port for Mux<C, K, O> {
    type Event = MuxEvent<C, K, O>;
    type Command = MuxCommand<C, K>;
}

/// What comes up from a multiplexed connection.
pub enum MuxEvent<C: Port, K: Port, O = ()> {
    /// A new child, opened by the peer or because the upper side asked.
    /// The handle is the only way to address it. The final value is the
    /// largest atomic command cost this child can ever admit, independent
    /// of its currently granted credit.
    Opened(Child, O, u64),
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

// Numbers each Slots, so ids of different connections never match.
static SCOPES: AtomicU64 = AtomicU64::new(1);

/// A mux's children, each with the state `T` it keeps for it.
///
/// Handles carry an opaque runtime identity that separates muxes, including
/// worlds with the same seed. Within one mux every handle has the same scope,
/// so ordering depends only on slot and generation. The scope is not a replay
/// identifier.
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
    _storage: Option<Charge>,
}

impl<T> Slots<T> {
    /// Room for at most `limit` children at once. This constructor uses
    /// bounded engine storage; connection-owned muxes use [`Self::with_budget`].
    pub fn new(limit: usize) -> Slots<T> {
        Slots {
            scope: SCOPES
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .expect("child scopes exhausted"),
            entries: Vec::new(),
            free: Vec::new(),
            live: 0,
            limit: limit.min(u32::MAX as usize),
            _storage: None,
        }
    }

    /// Reserves all slot and free-list storage against a connection budget
    /// before allocating. Values stored in a slot own their payload charges.
    pub fn with_budget(limit: usize, budget: &Budget) -> Option<Slots<T>> {
        let limit = limit.min(u32::MAX as usize);
        let bytes = limit.checked_mul(size_of::<(u64, Option<T>)>() + size_of::<u32>())?;
        let charge = budget.charge(bytes)?;
        let mut slots = Slots::new(limit);
        slots.entries = Vec::with_capacity(limit);
        slots.free = Vec::with_capacity(limit);
        slots._storage = Some(charge);
        Some(slots)
    }

    /// Adds a child, or hands `value` back when the limit is reached.
    pub fn insert(&mut self, value: T) -> Result<Child, T> {
        if self.live >= self.limit {
            return Err(value);
        }
        let slot = match self.free.pop() {
            Some(slot) => slot,
            None => {
                if self.entries.len() >= self.limit {
                    return Err(value);
                }
                if self.entries.len() == self.entries.capacity() {
                    self.entries.reserve_exact(1);
                }
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
        let value = entry.1.take();
        if let Some(next) = entry.0.checked_add(1) {
            entry.0 = next;
            if self.free.len() == self.free.capacity() {
                self.free.reserve_exact(1);
            }
            self.free.push(id.slot);
        }
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

#[cfg(test)]
mod slot_tests {
    use super::*;

    #[test]
    fn editing_unique_bytes_keeps_the_allocation_and_reservation() {
        let budget = Budget::new(8);
        let mut chunk = Chunk::with_charge(vec![1, 2, 3, 4], budget.charge(4).unwrap());
        chunk.advance(1);
        let allocation = chunk.as_ptr();
        chunk.make_mut(&Budget::new(0)).unwrap()[0] = 9;
        assert_eq!(chunk.as_ptr(), allocation);
        assert_eq!(&*chunk, &[9, 3, 4]);
        assert_eq!(budget.used(), 4);
        drop(chunk);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn editing_shared_bytes_reserves_before_copying_and_preserves_siblings() {
        let budget = Budget::new(6);
        let mut tail = Chunk::with_charge(vec![1, 2, 3, 4], budget.charge(4).unwrap());
        let mut head = tail.split_to(2);
        assert!(head.make_mut(&Budget::new(1)).is_none());
        assert_eq!(&*head, &[1, 2]);
        assert_eq!(budget.used(), 4);
        head.make_mut(&budget).unwrap()[0] = 9;
        assert_eq!(&*tail, &[3, 4]);
        assert_eq!(&*head, &[9, 2]);
        assert_eq!(budget.used(), 6);
        drop(tail);
        assert_eq!(budget.used(), 2);
        drop(head);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reserving_unique_whole_backing_reuses_its_allocation() {
        let mut chunk = Chunk::new(vec![1, 2, 3, 4]);
        let allocation = chunk.as_ptr();
        assert!(!chunk.reserve(&Budget::new(3)));
        assert_eq!(chunk.charged(), 0);
        let budget = Budget::new(4);
        assert!(chunk.reserve(&budget));
        assert_eq!(chunk.as_ptr(), allocation);
        assert_eq!(&*chunk, &[1, 2, 3, 4]);
        assert_eq!(budget.used(), 4);
        drop(chunk);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reserving_spare_capacity_charges_only_what_is_kept() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[1, 2]);
        let mut chunk = Chunk::new(bytes);
        let budget = Budget::new(2);
        assert!(chunk.reserve(&budget));
        assert_eq!(&*chunk, &[1, 2]);
        assert_eq!(chunk.charged(), budget.used());
        drop(chunk);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reserving_shared_backing_copies_and_leaves_siblings_alone() {
        let mut tail = Chunk::new(vec![1, 2, 3, 4]);
        let mut head = tail.split_to(2);
        let budget = Budget::new(2);
        assert!(head.reserve(&budget));
        assert_ne!(head.as_ptr(), tail.as_ptr().wrapping_sub(2));
        assert_eq!(&*head, &[1, 2]);
        assert_eq!(&*tail, &[3, 4]);
        assert_eq!(tail.charged(), 0);
        assert_eq!(budget.used(), 2);
        drop(head);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn recharging_whole_unique_bytes_moves_the_charge_without_copying() {
        let from = Budget::new(4);
        let to = Budget::new(4);
        let mut chunk = Chunk::with_charge(vec![1, 2, 3, 4], from.charge(4).unwrap());
        let allocation = chunk.as_ptr();
        assert!(!chunk.recharge(&Budget::new(3)));
        assert_eq!(from.used(), 4, "a refused recharge leaves the old charge");
        assert!(chunk.recharge(&to));
        assert_eq!(chunk.as_ptr(), allocation);
        assert_eq!(&*chunk, &[1, 2, 3, 4]);
        assert_eq!((from.used(), to.used()), (0, 4));
        drop(chunk);
        assert_eq!(to.used(), 0);
    }

    #[test]
    fn recharging_shared_bytes_copies_them_and_keeps_the_sibling_charged() {
        let from = Budget::new(4);
        let to = Budget::new(4);
        let mut tail = Chunk::with_charge(vec![1, 2, 3, 4], from.charge(4).unwrap());
        let mut head = tail.split_to(1);
        assert!(head.recharge(&to));
        assert_eq!(&*head, &[1]);
        assert_eq!(&*tail, &[2, 3, 4]);
        assert_eq!((from.used(), to.used()), (4, 1));
        drop(tail);
        assert_eq!(from.used(), 0);
        drop(head);
        assert_eq!(to.used(), 0);
    }

    #[test]
    fn a_prefix_shares_the_backing_and_takes_nothing() {
        let budget = Budget::new(4);
        let chunk = Chunk::with_charge(vec![1, 2, 3, 4], budget.charge(4).unwrap());
        let prefix = chunk.prefix(2);
        assert_eq!(prefix.as_ptr(), chunk.as_ptr());
        assert_eq!(&*prefix, &[1, 2]);
        assert_eq!(chunk.len(), 4);
        drop(chunk);
        assert_eq!(budget.used(), 4, "the prefix still holds the backing");
        drop(prefix);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn editing_unreserved_bytes_accounts_for_the_backing_capacity() {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&[1, 2]);
        let mut chunk = Chunk::new(bytes);
        assert!(chunk.make_mut(&Budget::new(2)).is_none());
        assert_eq!(&*chunk, &[1, 2]);
        let budget = Budget::new(32);
        chunk.make_mut(&budget).unwrap()[1] = 3;
        assert_eq!(budget.used(), 32);
        drop(chunk);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn an_exhausted_generation_retires_its_slot() {
        let mut slots = Slots::new(1);
        let first = slots.insert(()).unwrap();
        slots.entries[0].0 = u64::MAX;
        let last = ChildId {
            generation: u64::MAX,
            ..first.id()
        };
        assert_eq!(slots.remove(last), Some(()));
        assert!(!slots.contains(last));
        assert!(slots.insert(()).is_err());
    }

    #[test]
    fn slot_storage_is_reserved_before_it_grows() {
        assert!(Slots::<u8>::with_budget(1, &Budget::new(0)).is_none());
        let budget = Budget::new(1000);
        let mut slots = Slots::with_budget(2, &budget).unwrap();
        let charged = budget.used();
        let a = slots.insert(1u8).unwrap();
        let _b = slots.insert(2).unwrap();
        assert!(slots.insert(3).is_err());
        slots.remove(a.id());
        let _c = slots.insert(3).unwrap();
        assert_eq!(budget.used(), charged);
        drop(slots);
        assert_eq!(budget.used(), 0);
    }
}
