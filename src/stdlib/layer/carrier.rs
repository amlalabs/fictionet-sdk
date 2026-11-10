//! The four carrier contracts and the handles of multiplexed children.

use core::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use super::children::ChildWake;
use fictionet::stdlib::layer::{Budget, Charge, Chunk, CommandOf, EventOf, Held, Port};

// ---------------------------------------------------------------------------
// Credit

/// A lease on a child's receive credit, given back when dropped. It is
/// flow control only, separate from whatever pays for memory: a carrier
/// with retained data makes its [`Chunk`] hold it ([`Chunk::hold`]), so
/// the credit returns when the last piece of the payload is released.
pub struct CreditLease {
    child: Arc<ChildWake>,
    units: u64,
}

impl CreditLease {
    pub(crate) fn new(child: Arc<ChildWake>, units: u64) -> Self {
        Self { child, units }
    }

    /// Gives up the lease without releasing its credit, for a carrier that
    /// does not hold it: the mux returns that credit itself when the child
    /// takes the event, so releasing it here would count it twice and wake
    /// the child for nothing.
    pub(crate) fn disarm(mut self) {
        self.units = 0;
    }
}

impl Drop for CreditLease {
    fn drop(&mut self) {
        if self.units != 0 {
            self.child.release(self.units);
        }
    }
}

impl Held for CreditLease {}

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

    /// Admits a payload into the receive window `window` already pays for,
    /// or reserves its own separately accounted payload for an atomic
    /// carrier.
    fn reserve_receive(&mut self, budget: &Budget, _window: &Arc<Charge>) -> bool {
        self.reserve(budget)
    }

    /// Reserves any retained payload before admission. Carrier implementations
    /// with owned storage must override this or carry a reservation already.
    fn reserve(&mut self, _budget: &Budget) -> bool {
        true
    }

    /// Makes the retained payload hold `lease`, so its receive credit
    /// returns when the payload is released, or hands the lease back when
    /// this value does not hold credit. Atomic messages return their credit
    /// when admitted; byte carriers override this to hold it.
    fn retain_lease(&mut self, lease: CreditLease) -> Option<CreditLease> {
        Some(lease)
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

    fn reserve_receive(&mut self, _: &Budget, window: &Arc<Charge>) -> bool {
        if let Self::Data(chunk) = self {
            chunk.move_into_window(window.clone());
        }
        true
    }

    fn reserve(&mut self, budget: &Budget) -> bool {
        match self {
            Self::Data(chunk) => chunk.repay(budget),
            _ => true,
        }
    }

    fn retain_lease(&mut self, lease: CreditLease) -> Option<CreditLease> {
        match self {
            Self::Data(chunk) => chunk.hold(lease).err(),
            _ => Some(lease),
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
            Self::Write(chunk) => chunk.repay(budget),
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
    /// The child's first credit, as [`Credit`](Self::Credit) gives it,
    /// with the receive window its events go in: memory the receiver paid
    /// for on the child's budget, as large as all the credit it grants, so
    /// it holds every byte the mux may send the child at once. The window
    /// is lent, not given: while the receiver keeps it, a mux may make the
    /// child's bytes in it ([`Chunk::in_window`]) instead of paying for
    /// them itself, and the receiver takes them in with no charge moving.
    /// It goes back to the child's budget when the receiver lets go of the
    /// child and its bytes, whatever the mux holds. A mux with no use for
    /// it takes the credit alone.
    Window(ChildId, u64, Weak<Charge>),
    /// Close the child at once, as a reset does, for the cause the
    /// receiver gives. The mux tells its peer that cause in the protocol's
    /// own terms and guesses none.
    Close(ChildId, Closing),
    /// A connection control command.
    Control(CommandOf<K>),
}

/// Why a child is closed, as the receiver decided it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closing {
    /// The receiver is done with it.
    Done,
    /// Never taken: past the receiver's limit on children, or the
    /// application said no.
    Prohibited,
    /// Never taken: no memory for it now. The peer may try again.
    ResourceShortage,
    /// Taken, then given up on: its layer failed or it broke its limits.
    Failed,
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
            MuxOp::Window(..) => "Window",
            MuxOp::Close(..) => "Close",
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

    /// Lets the mux send this child's events using its first `units` of
    /// credit, and lends it `window`, the receive window they go in
    /// ([`MuxOp::Window`]).
    pub fn lend_window<C: Port, K: Port>(
        &self,
        units: u64,
        window: &Arc<Charge>,
    ) -> MuxCommand<C, K> {
        MuxCommand(MuxOp::Window(self.id, units, Arc::downgrade(window)))
    }

    /// Closes the child at once, for the cause `why`, giving up the
    /// handle.
    pub fn close<C: Port, K: Port>(self, why: Closing) -> MuxCommand<C, K> {
        MuxCommand(MuxOp::Close(self.id, why))
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
    /// What pays for the slots, when a budget does: all of them at once
    /// ([`Slots::with_budget`]), or those made so far
    /// ([`Slots::with_places`]), which grow charged first.
    storage: Option<Charge>,
    /// The slots grow only as their charge does.
    charged_growth: bool,
    /// The generation a new slot starts at: past every generation a slot
    /// given back by [`shrink_to`](Slots::shrink_to) had, so no id of one
    /// finds its successor.
    fresh: u64,
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
            storage: None,
            charged_growth: false,
            fresh: 0,
        }
    }

    /// The bytes one slot takes: its entry and its place in the free list.
    const PLACE: usize = size_of::<(u64, Option<T>)>() + size_of::<u32>();

    /// Reserves all slot and free-list storage against a connection budget
    /// before allocating. Values stored in a slot own their payload charges.
    pub fn with_budget(limit: usize, budget: &Budget) -> Option<Slots<T>> {
        let limit = limit.min(u32::MAX as usize);
        let bytes = limit.checked_mul(Self::PLACE)?;
        let charge = budget.charge(bytes)?;
        let mut slots = Slots::new(limit);
        slots.entries = Vec::with_capacity(limit);
        slots.free = Vec::with_capacity(limit);
        slots.storage = Some(charge);
        Some(slots)
    }

    /// Room for at most `limit` children, `keep` slots of it charged to
    /// `budget` and made now. More slots are made as children need them,
    /// doubling, each growth charged before it is made; a growth the
    /// budget refuses refuses the child. Slots stay made for the next
    /// children, and those past `keep` go back once every child has gone
    /// ([`shrink_to`](Self::shrink_to)), so a connection that serves one
    /// child at a time allocates nothing for them.
    pub fn with_places(budget: &Budget, keep: usize, limit: usize) -> Option<Slots<T>> {
        let limit = limit.min(u32::MAX as usize);
        let keep = keep.min(limit);
        let charge = budget.charge(keep.checked_mul(Self::PLACE)?)?;
        let mut slots = Slots::new(limit);
        slots.entries = Vec::with_capacity(keep);
        slots.free = Vec::with_capacity(keep);
        slots.storage = Some(charge);
        slots.charged_growth = true;
        Some(slots)
    }

    /// Makes room for one more slot: by one place without a budget, or,
    /// with one, by doubling within the limit, charged first. `false`,
    /// changing nothing, when the budget refuses.
    fn grow(&mut self) -> bool {
        let made = self.entries.capacity();
        let Some(storage) = self.storage.as_mut().filter(|_| self.charged_growth) else {
            self.entries.reserve_exact(1);
            return true;
        };
        let more = made.max(1).min(self.limit - made);
        let Some(bytes) = (made + more).checked_mul(Self::PLACE) else {
            return false;
        };
        if !storage.grow_to(bytes) {
            return false;
        }
        self.entries.reserve_exact(made + more - self.entries.len());
        self.free.reserve_exact(made + more - self.free.len());
        true
    }

    /// Gives back the slots past `keep` and their charge, once no child is
    /// live. A slot made afterwards starts at a generation past every one
    /// given back, so their ids never find it.
    pub fn shrink_to(&mut self, keep: usize) {
        if self.live > 0 || self.entries.capacity() <= keep {
            return;
        }
        let past = self.entries.iter().map(|(generation, _)| *generation).max();
        self.fresh = self.fresh.max(past.unwrap_or(0));
        self.entries.clear();
        self.free.clear();
        self.entries.shrink_to(keep);
        self.free.shrink_to(keep);
        if let Some(storage) = &mut self.storage {
            storage.shrink_to(self.entries.capacity() * Self::PLACE);
        }
    }

    /// Adds a child, or hands `value` back when the limit is reached, or
    /// when a slot must be made and the budget refuses it.
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
                if self.entries.len() == self.entries.capacity() && !self.grow() {
                    return Err(value);
                }
                self.entries.push((self.fresh, None));
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

    /// `bytes` in an allocation of exactly their size that `budget` pays for.
    fn paid(budget: &Budget, bytes: &[u8]) -> Chunk {
        Chunk::copy_of(budget, bytes).unwrap()
    }

    #[test]
    fn admitting_bytes_paid_elsewhere_moves_their_charge_to_the_receiver() {
        let sender = Budget::new(4);
        let receiver = Budget::new(4);
        let mut event = StreamEvent::Data(paid(&sender, &[1, 2, 3, 4]));
        assert!(!event.reserve(&Budget::new(3)));
        assert_eq!(
            sender.used(),
            4,
            "a refused admission leaves the old charge"
        );
        assert!(event.reserve(&receiver));
        assert_eq!((sender.used(), receiver.used()), (0, 4));
        let StreamEvent::Data(chunk) = event else {
            unreachable!()
        };
        assert_eq!(&*chunk, &[1, 2, 3, 4]);
        drop(chunk);
        assert_eq!(receiver.used(), 0);
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

    /// Slots made with places grow as children need them, each growth
    /// charged first and refused, changing nothing, when the budget has no
    /// room; once every child has gone, what they grew goes back. An id of
    /// a child whose slot went back never finds a later child.
    #[test]
    fn slots_with_places_grow_charged_and_shrink_without_reviving_ids() {
        let budget = Budget::new(1 << 16);
        let mut slots = Slots::with_places(&budget, 2, 64).unwrap();
        let kept = budget.used();
        let first: Vec<ChildId> = (0..10).map(|i| slots.insert(i).unwrap().id()).collect();
        assert!(budget.used() > kept, "growth past the places is charged");
        for id in &first {
            assert!(slots.remove(*id).is_some());
        }
        slots.shrink_to(2);
        assert_eq!(budget.used(), kept, "the growth went back");
        let again: Vec<ChildId> = (0..10).map(|i| slots.insert(i).unwrap().id()).collect();
        for old in &first {
            assert!(!slots.contains(*old), "an old id found a new child");
        }
        assert!(again.iter().all(|id| slots.contains(*id)));

        // A budget with room for the kept places only refuses the third
        // child, and the slots stay as they were.
        let tight = Budget::new(Slots::<u8>::PLACE * 2);
        let mut slots = Slots::with_places(&tight, 2, 64).unwrap();
        let _a = slots.insert(1u8).unwrap();
        let _b = slots.insert(2).unwrap();
        assert_eq!(slots.insert(3).map(|child| child.id()), Err(3));
        assert_eq!((slots.len(), tight.used()), (2, tight.limit()));
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
