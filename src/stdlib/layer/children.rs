use super::carrier::CreditLease;
use super::charged::charge_places;
use super::env::Wakes;
use std::cell::OnceCell;
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::task::{Wake, Waker};

use fictionet::stdlib::layer::{
    Admit, Budget, Charge, ChargedDeque, Child, ChildId, Closing, CommandOf, Credited, Env,
    EventOf, Layer, Mux, MuxCommand, MuxEvent, OwnedWork, Port, Refusals, Starved, Top, Waiter,
    WorkOwner,
};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use slab::Slab;

/// How many commands wait for the mux, and how many of those places only
/// connection control and credit may use.
const QUEUE: usize = 64;
const RESERVE: usize = 8;
const MAX_CHILDREN: usize = 4096;
/// The child places a router reserves with its queues and keeps once no
/// child is open.
const FLOOR: usize = 4;
type ChildFactory<B, O> = dyn FnMut(ChildId, O, &Budget) -> Option<B> + Send;
type ChildBudget<O> = dyn FnMut(ChildId, &O, &Budget) -> Budget + Send;

/// One `B` on each child of a multiplexed connection, with the
/// connection's control port `K` passed up.
///
/// Put it on a mux with a [`Chain`](super::Chain): gRPC with its
/// application on each HTTP/2 stream is
/// `Chain<Http2, Children<Chain<Grpc, App>, Control>>`. A layer that needs
/// a child's port cannot be put on a bare byte stream, because `Children`
/// needs a [`Mux`] below it:
///
/// ```compile_fail,E0271
/// # use fictionet::stdlib::layer::*;
/// # use core::marker::PhantomData;
/// # struct Probe<L, U>(PhantomData<(L, U)>);
/// # impl<L: Port, U: Port> Layer for Probe<L, U> {
/// #     type Lower = L; type Upper = U; type Report = (); type Timer = ();
/// #     type Work = (); type Done = (); type Error = ();
/// #     fn on_event(&mut self, _: &mut Env<'_, ()>, e: EventOf<L>) -> Result<Admit<EventOf<L>>, ()> { Ok(Admit::Blocked(e)) }
/// #     fn on_command(&mut self, _: &mut Env<'_, ()>, c: CommandOf<U>) -> Result<Admit<CommandOf<U>>, ()> { Ok(Admit::Blocked(c)) }
/// #     fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<CommandOf<L>> { None }
/// #     fn take_event(&mut self) -> Option<EventOf<U>> { None }
/// # }
/// # struct Call; struct Reply;
/// type Calls = Messages<Call, Reply>;
/// // An application on each child, put on a byte stream instead of a mux.
/// type Wrong = Chain<Probe<Top, ByteStream>, Children<Probe<Calls, Top>, Top>>;
/// fn build(stack: Wrong) {}
/// ```
///
/// On a mux whose children carry that port, it compiles:
///
/// ```
/// # use fictionet::stdlib::layer::*;
/// # use core::marker::PhantomData;
/// # struct Probe<L, U>(PhantomData<(L, U)>);
/// # impl<L: Port, U: Port> Layer for Probe<L, U> {
/// #     type Lower = L; type Upper = U; type Report = (); type Timer = ();
/// #     type Work = (); type Done = (); type Error = ();
/// #     fn on_event(&mut self, _: &mut Env<'_, ()>, e: EventOf<L>) -> Result<Admit<EventOf<L>>, ()> { Ok(Admit::Blocked(e)) }
/// #     fn on_command(&mut self, _: &mut Env<'_, ()>, c: CommandOf<U>) -> Result<Admit<CommandOf<U>>, ()> { Ok(Admit::Blocked(c)) }
/// #     fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<CommandOf<L>> { None }
/// #     fn take_event(&mut self) -> Option<EventOf<U>> { None }
/// # }
/// # struct Call; struct Reply;
/// type Calls = Messages<Call, Reply>;
/// type Right = Chain<Probe<Top, Mux<Calls, Top>>, Children<Probe<Calls, Top>, Top>>;
/// fn build(stack: Right) {}
/// ```
///
/// Each child's layer is made when the child opens and dropped, with its
/// timers and work, when the child closes. Its timers and work are keyed by
/// its [`ChildId`], so a result for a closed child reaches nothing, even if
/// a new child has its slot. A child that fails is closed and reported
/// ([`ChildReport::Failed`]); its siblings go on.
///
/// Every child gets `window` credit units for its events. A child that stops
/// reading holds at most `window` units plus bounded item and completion
/// slots. A child's commands wait in a place of their own until the mux
/// grants credit for them, so a child the peer does
/// not read holds up nothing but itself.
///
/// A child's layer changes only when `Children` calls it, so the router
/// keeps three queues of children instead of looking at every child. A
/// child waits in the ready queue once it got an event, credit, a timer, a
/// work result or a wake from its work, or once its released payload
/// returned credit, and goes back to the end while its visits move or find
/// the mux's queue full. An advance visits the children ready when it
/// starts, in queue order, at most 64 of them. A child that was called
/// waits in the work queue until its layer has no work to hand over. Its
/// deadline, read after each call, waits in a heap ordered by time and then
/// by when it was armed, so of children due together the one whose timer
/// fired last comes last. At most 4096 children can be configured. Byte
/// receive credit returns when its backing is released; atomic message
/// credit returns on admission, independently of memory.
///
/// The router's queues and its first few child places are charged to the
/// budget from its first step. Further places and each child's inbox are
/// charged as they grow, the places up to the limit and each inbox up to
/// its bound, and the further places go once no child is left. An opening
/// whose place or window the budget cannot hold now is refused for want of
/// memory ([`ChildReport::Refused`] with [`Closing::ResourceShortage`]),
/// and its siblings go on. Once open, a child is never closed for memory
/// (rule 9): each child asks through a [view](Budget::view) of its budget,
/// and when that refuses, a command waits in the child's outbox, and an
/// event goes back to the mux, until the budget frees and the child is
/// visited again. The one exception is a charge larger than the child's
/// whole limit, which no release can meet: that child alone is closed and
/// reported as failed ([`Closing::Failed`]), as the runner ends a stack
/// that needs more than its limit.
///
/// The mux never waits for a child's reading. Credit bounds a child's
/// bytes, but not how many events it holds: many small pieces, completions
/// and ends cost nothing. Each child holds at most 64 events and one urgent
/// event. When an event finds its child's place full, the child is visited
/// at once to take what waits. A child that still takes nothing is
/// overloaded: it alone is refused and closed, its work cancelled, and the
/// event is dropped with it. So any child, however it reads, holds up
/// neither its siblings nor the connection's own traffic below and above.
/// Memory is the one wait: an event its budget cannot pay for now goes
/// back to the mux, and what the mux has behind it waits too, until that
/// budget frees.
pub struct Children<B, K, O = ()>
where
    B: Layer<Upper = Top>,
    EventOf<B::Lower>: Credited,
    CommandOf<B::Lower>: Credited,
    K: Port,
{
    make: Box<ChildFactory<B, O>>,
    budget_for: Option<Box<ChildBudget<O>>>,
    close_finished: bool,
    /// Children to visit, linked through their own `links`.
    ready: List,
    /// Children whose layers may have work to hand over.
    work: List,
    /// How many deadlines have been armed, to order those due together.
    armed: u64,
    limit: usize,
    window: u64,
    /// How many open children wait for memory.
    waiting: usize,
    /// The children and the router's queues, with what pays for them.
    places: Places<B, K>,
}

/// The router's storage, paid for as one: its two queues, and for each
/// child place a place in every table, which are the children, their ids
/// in order, the deadline heap, the wake queue, a closing place in the
/// command queue, and what a closed child leaves for the next ([`Spare`]).
/// The places grow only here, every table together or none: the growth is
/// charged first, as a charged queue grows, by doubling when the budget
/// has room and by as many places as it has room for when not. They go
/// back together too.
struct Places<B: Layer, K: Port> {
    /// The open children, each at a key that stays its own while it is open.
    kids: Slab<Kid<B>>,
    /// Their ids and keys, in id order.
    order: Vec<(ChildId, usize)>,
    /// The keys of children with a deadline, a binary heap with the first
    /// due at the top. Each child knows where it is.
    timers: Vec<usize>,
    /// The children something outside a call reached ([`ChildWake`]).
    woken: Arc<Woken>,
    /// Commands for the mux: [`QUEUE`] places, and one more for each child
    /// place, for the child's closing.
    down: VecDeque<MuxCommand<B::Lower, K>>,
    /// Control events for above.
    up: VecDeque<EventOf<K>>,
    /// What closed children left, at most one for each place no child
    /// fills, taken by the next children opened.
    spares: Vec<Spare>,
    /// The child places paid for, which every table holds.
    count: usize,
    /// What pays for the queues and the places: `None` until the first
    /// step paid for the queues and the first [`FLOOR`] places. Last, so
    /// it outlives everything it pays for.
    charge: Option<Charge>,
}

impl<B: Layer, K: Port> Places<B, K> {
    /// Nothing paid for and nothing allocated.
    fn new() -> Self {
        Places {
            kids: Slab::new(),
            order: Vec::new(),
            timers: Vec::new(),
            woken: Arc::new(Woken {
                any: AtomicBool::new(false),
                keys: Mutex::new(Vec::new()),
            }),
            down: VecDeque::new(),
            up: VecDeque::new(),
            spares: Vec::new(),
            count: 0,
            charge: None,
        }
    }

    /// The two queues' [`QUEUE`] places.
    fn queue_bytes() -> usize {
        QUEUE * (size_of::<MuxCommand<B::Lower, K>>() + size_of::<EventOf<K>>())
    }

    /// One child place: the child itself, a vacant place's next key
    /// included, its wake state with its two counts, its place in the wake
    /// queue, its id in order, its place in the deadline heap, its closing
    /// place in the command queue, and its place among the spares with
    /// what a child's other parts hold behind their counts: its budget's
    /// record, its work's lifetime and its receive window's charge.
    fn place_bytes() -> usize {
        let counted = |bytes: usize| 2 * size_of::<usize>() + bytes;
        size_of::<Kid<B>>()
            + size_of::<usize>()
            + counted(size_of::<ChildWake>())
            + size_of::<usize>()
            + size_of::<(ChildId, usize)>()
            + size_of::<usize>()
            + size_of::<MuxCommand<B::Lower, K>>()
            + size_of::<Spare>()
            + Budget::VIEW_BYTES
            + counted(size_of::<AtomicBool>())
            + counted(size_of::<Charge>())
    }

    /// Keeps what a closed child left for the next child opened, while a
    /// place no child fills has room for it. Within the places paid for,
    /// so nothing grows.
    fn keep(&mut self, spare: Spare) {
        if self.spares.len() < self.count - self.kids.len() {
            self.spares.push(spare);
        }
    }

    /// Pays for the queues and the first [`FLOOR`] places the first time
    /// anything arrives, then allocates them. Returns whether they are
    /// paid for. A refusal changes nothing: what arrived waits for memory
    /// (rule 9), and the refusal is the runner's to see, through `budget`.
    fn reserve(&mut self, budget: &Budget) -> bool {
        if self.charge.is_some() {
            return true;
        }
        let Some(charge) = budget.charge(Self::place_bytes() * FLOOR + Self::queue_bytes()) else {
            return false;
        };
        self.charge = Some(charge);
        self.up = VecDeque::with_capacity(QUEUE);
        self.grow_to(FLOOR);
        true
    }

    /// Makes a place for one more child, at most `limit`. Returns whether
    /// there is one.
    fn make_room(&mut self, limit: usize) -> bool {
        if self.kids.len() < self.count {
            return true;
        }
        let Some(charge) = &mut self.charge else {
            return false;
        };
        let wanted = self.kids.len() + 1;
        let Some(more) = charge_places(charge, self.count, wanted, limit, Self::place_bytes())
        else {
            return false;
        };
        self.grow_to(self.count + more);
        true
    }

    /// Every table holds `count` places, which are paid for.
    fn grow_to(&mut self, count: usize) {
        self.kids.reserve_exact(count - self.kids.len());
        self.order.reserve_exact(count - self.order.len());
        self.timers.reserve_exact(count - self.timers.len());
        // Only open children wait in the wake queue, fewer than `count`.
        let mut keys = self.woken.keys.lock();
        let queued = keys.len();
        keys.reserve_exact(count - queued);
        drop(keys);
        self.down.reserve_exact(QUEUE + count - self.down.len());
        self.spares.reserve_exact(count - self.spares.len());
        self.count = count;
    }

    /// With no children, the places past the first [`FLOOR`] go, so an
    /// idle connection holds the same whatever it held before: its queues
    /// and those places, so one with a few children at a time never gives
    /// places back to take them again. Closing commands still queued keep
    /// their places until the mux takes them.
    fn release(&mut self) {
        let count = FLOOR.max(self.down.len().saturating_sub(QUEUE));
        if !self.kids.is_empty() || count >= self.count {
            return;
        }
        let Some(charge) = &mut self.charge else {
            return;
        };
        self.kids = Slab::with_capacity(count);
        self.order = Vec::with_capacity(count);
        self.timers = Vec::with_capacity(count);
        // Closed children left the wake queue, so it is empty.
        *self.woken.keys.lock() = Vec::with_capacity(count);
        self.down.shrink_to(QUEUE + count);
        let mut spares = Vec::with_capacity(count);
        spares.extend(self.spares.drain(..).take(count));
        self.spares = spares;
        self.count = count;
        charge.shrink_to(Self::queue_bytes() + count * Self::place_bytes());
    }
}

/// A child's place in one of the router's lists.
#[derive(Clone, Copy, Default)]
struct Link {
    prev: Option<usize>,
    next: Option<usize>,
    linked: bool,
}

/// A first-in, first-out list of children, linked through the children:
/// `ready` through their first link, `work` through their second.
struct List {
    which: usize,
    head: Option<usize>,
    tail: Option<usize>,
    len: usize,
}

impl List {
    const READY: usize = 0;
    const WORK: usize = 1;

    fn new(which: usize) -> List {
        List {
            which,
            head: None,
            tail: None,
            len: 0,
        }
    }

    /// Puts child `key` at the end, unless it is in the list.
    fn push<B: Layer>(&mut self, kids: &mut Slab<Kid<B>>, key: usize) {
        if kids[key].links[self.which].linked {
            return;
        }
        kids[key].links[self.which] = Link {
            prev: self.tail,
            next: None,
            linked: true,
        };
        match self.tail {
            Some(tail) => kids[tail].links[self.which].next = Some(key),
            None => self.head = Some(key),
        }
        self.tail = Some(key);
        self.len += 1;
    }

    /// Takes child `key` out, if it is in the list.
    fn unlink<B: Layer>(&mut self, kids: &mut Slab<Kid<B>>, key: usize) {
        let link = kids[key].links[self.which];
        if !link.linked {
            return;
        }
        match link.prev {
            Some(prev) => kids[prev].links[self.which].next = link.next,
            None => self.head = link.next,
        }
        match link.next {
            Some(next) => kids[next].links[self.which].prev = link.prev,
            None => self.tail = link.prev,
        }
        kids[key].links[self.which] = Link::default();
        self.len -= 1;
    }

    fn pop<B: Layer>(&mut self, kids: &mut Slab<Kid<B>>) -> Option<usize> {
        let key = self.head?;
        self.unlink(kids, key);
        Some(key)
    }
}

struct Kid<B: Layer> {
    id: ChildId,
    handle: Child,
    owner: WorkOwner,
    urgent: Option<EventOf<B::Lower>>,
    layer: B,
    budget: Budget,
    /// Events the mux sent within credit that the layer has not taken.
    inbox: ChargedDeque<(EventOf<B::Lower>, bool)>,
    wake: Arc<ChildWake>,
    /// Its waker ([`within`]): what its calls get, and what waits on its
    /// budget after a charge of its was refused.
    waiter: ChildWaker,
    /// Its places in the ready and work lists.
    links: [Link; 2],
    /// Its deadline after its last call, the arming number that orders it
    /// among deadlines at the same moment, and where it is in the heap.
    due: Option<(Instant, B::Timer)>,
    armed: u64,
    heap: Option<usize>,
    /// What pays for the memory of the bytes in its receive window, shared
    /// by every chunk that waits in it.
    window: Arc<Charge>,
    /// The window went to the mux with the first credit.
    lent: bool,
    max_command: u64,
    /// Credit the mux may still use for this child's events.
    granted: u64,
    /// Credit of events the layer took, not yet granted again.
    owed: u64,
    /// Credit the mux granted for this child's commands.
    credit: u64,
    /// A command of the layer's that waits for credit.
    outbox: Option<CommandOf<B::Lower>>,
    /// It waits for memory ([`Kid::wait_for_memory`]).
    memory: bool,
}

/// What a closed child leaves for the next child opened, so that opening
/// a child allocates nothing once children have come and gone: the state
/// its wakes go through, its budget's record of refusals, its work's
/// lifetime, and the place of its receive window. The next child uses
/// each part again only if nothing else holds it then: a part something
/// still holds (a waker the closed child's work kept, a lease of its
/// credit, a charge made through its view) stays that holder's, and the
/// new child gets a new one, so nothing of a closed child's reaches the
/// next. None of it holds memory of the budget's, so an idle router holds
/// what it held before its first child.
struct Spare {
    wake: Arc<ChildWake>,
    /// The closed child's view of its budget.
    budget: Budget,
    /// Cancelled when its child closed.
    owner: WorkOwner,
    /// Kept only if nothing else held it when its child closed, its charge
    /// given back then: a window holds its child's bytes until the last
    /// chunk made in it goes, as ever, and never while it waits here.
    window: Option<Arc<Charge>>,
}

impl<B: Layer> Kid<B> {
    /// The child closed: its work's lifetime ends, and what can serve the
    /// next child is kept, a kept window holding a charge of nothing on
    /// `idle`, the router's own budget, in place of the child's.
    fn retire(self, idle: &Budget) -> (Child, Spare) {
        let Kid {
            id: _,
            handle,
            owner,
            urgent,
            layer,
            budget,
            inbox,
            wake,
            waiter,
            links: _,
            due,
            armed: _,
            heap: _,
            mut window,
            lent: _,
            max_command: _,
            granted: _,
            owed: _,
            credit: _,
            outbox,
            memory: _,
        } = self;
        owner.cancel();
        // The rest of the child goes first, its layer and its chunks among
        // them, so a window nothing else holds after is the router's alone.
        drop((urgent, layer, inbox, waiter, due, outbox));
        let kept = match Arc::get_mut(&mut window) {
            Some(charge) => {
                *charge = Charge::nothing(idle);
                true
            }
            None => false,
        };
        let spare = Spare {
            wake,
            budget,
            owner,
            window: kept.then_some(window),
        };
        (handle, spare)
    }

    /// After calls into the child that began with its budget's refusals at
    /// `since`: if a charge was refused meanwhile, the child is visited
    /// again once its budget has room for it (rule 9). The child asks
    /// through a view of its own, which the runner above does not read,
    /// so the router waits on it for the child, with the waiter made from
    /// `around`, what the child runs in. A charge that needed more than the
    /// whole limit is met by no release: the child is starved, nothing
    /// waits, and the caller closes it as failed, as the runner ends a
    /// stack that needs more than its limit.
    ///
    /// The child waits for memory from a refusal until calls that
    /// `retried` (a visit, which advances its layer, where a layer tries a
    /// refused charge again) meet none, and while a part of its layer
    /// waits on a view of its own. `waiting` counts the children that
    /// wait, which the router reports to its runner
    /// ([`Layer::waits_for_memory`]), so their wait is not idle.
    #[must_use]
    fn wait_for_memory(
        &mut self,
        since: Refusals,
        around: Wakes<'_>,
        retried: bool,
        waiting: &mut usize,
    ) -> Option<Starved> {
        let starved = self.budget.starved_since(since);
        let refused = starved.is_none() && self.budget.refused_since(since);
        if refused {
            let waiter = self.waiter.waiter(|| around.waker());
            self.budget.wake_when_freed(waiter, since);
        }
        let was = self.memory;
        self.memory = refused || self.layer.waits_for_memory() || (was && !retried);
        *waiting = (*waiting + usize::from(self.memory)) - usize::from(was);
        starved
    }
}

/// What reaches a child from outside `Children`'s calls into it: receive
/// credit returned by payload released elsewhere, wakes from its work,
/// which may share state with its layer (a tunnel's connection does), and
/// wakes of the [`Env::waker`] its calls get. Each gets the child visited
/// at the next advance.
pub(crate) struct ChildWake {
    /// The child's place in `Children`, its own while it is open.
    key: usize,
    released: AtomicU64,
    /// `Children` is calling the child and collects what it releases.
    calling: AtomicBool,
    /// The child waits in `queue`, or is being readied from it. A closed
    /// child's stays set.
    woken: AtomicBool,
    /// The child closed, so a wake queues nothing. Changed and read with
    /// the queue locked.
    closed: AtomicBool,
    /// Where the child waits once woken.
    queue: Arc<Woken>,
    /// The task that polls the child's work, woken with it.
    task: Mutex<Option<Waker>>,
}

/// The open children woken from outside `Children`'s calls, each once until
/// it is collected. Collecting them costs what was woken, not every open
/// child. A child leaves the queue when it closes, so the queue never holds
/// more keys than there are open children, and a key in it is never a
/// later child's at the same place.
struct Woken {
    /// Something is queued: an advance with nothing woken skips the lock.
    any: AtomicBool,
    /// Their keys.
    keys: Mutex<Vec<usize>>,
}

impl ChildWake {
    fn new(key: usize, queue: Arc<Woken>) -> ChildWake {
        ChildWake {
            key,
            released: AtomicU64::new(0),
            calling: AtomicBool::new(false),
            woken: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            queue,
            task: Mutex::new(None),
        }
    }

    /// `this`, a closed child's, made the wake state of a new child at
    /// `key`, as [`new`](Self::new) makes one, when nothing else holds it:
    /// no waker the closed child's work kept, no lease of its credit, no
    /// waiter of its budget. `None` while something holds it, which keeps
    /// it, so nothing of the closed child's ever reaches the new one.
    fn renewed(mut this: Arc<Self>, key: usize) -> Option<Arc<Self>> {
        let wake = Arc::get_mut(&mut this)?;
        wake.key = key;
        *wake.released.get_mut() = 0;
        *wake.calling.get_mut() = false;
        *wake.woken.get_mut() = false;
        *wake.closed.get_mut() = false;
        *wake.task.get_mut() = None;
        Some(this)
    }

    // A release is never lost. Every call ends by clearing `calling` and is
    // followed by a visit, which clears it before taking `released` with a
    // read-modify-write. A release whose add comes after that take reads
    // from it, so it sees `calling` cleared, or set again by a later visit
    // whose own take collects it; an add before the take is collected by it.

    /// Payload holding `units` of receive credit was released.
    pub(crate) fn release(&self, units: u64) {
        self.released.fetch_add(units, Ordering::AcqRel);
        if !self.calling.load(Ordering::Acquire) {
            self.notify();
        }
    }

    /// Queues the child, unless it waits in the queue already or closed.
    /// Collecting clears `woken` before the visit, so a wake after that
    /// queues it again.
    fn notify(&self) {
        if self.woken.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut keys = self.queue.keys.lock();
        if !self.closed.load(Ordering::Relaxed) {
            keys.push(self.key);
            self.queue.any.store(true, Ordering::Release);
        }
    }

    /// The child closed: it leaves the queue, and later wakes queue nothing.
    /// A wake that set `woken` before this either queued the child before
    /// the lock was taken here, and is taken out, or finds it closed.
    fn close(&self) {
        let mut keys = self.queue.keys.lock();
        self.closed.store(true, Ordering::Relaxed);
        if self.woken.load(Ordering::Relaxed) {
            keys.retain(|&key| key != self.key);
        }
    }

    /// `Children` starts calling the child: credit released meanwhile is
    /// collected after the calls instead of waking it.
    fn enter(&self) {
        self.calling.store(true, Ordering::Relaxed);
    }

    fn leave(&self) {
        self.calling.store(false, Ordering::Release);
    }

    /// Brackets one call into the child. A visit follows it.
    fn call<T>(&self, call: impl FnOnce() -> T) -> T {
        self.enter();
        let result = call();
        self.leave();
        result
    }

    /// Ends a visit's calls and takes the credit released since the last
    /// visit.
    fn take_released(&self) -> u64 {
        self.leave();
        self.released.swap(0, Ordering::AcqRel)
    }

    /// A waker for the child's work that also wakes `task`, the poller.
    pub(crate) fn waker(self: &Arc<Self>, task: &Waker) -> Waker {
        {
            let mut current = self.task.lock();
            if !current.as_ref().is_some_and(|w| w.will_wake(task)) {
                *current = Some(task.clone());
            }
        }
        Waker::from(self.clone())
    }
}

impl Wake for ChildWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
        let task = self.task.lock().clone();
        if let Some(task) = task {
            task.wake();
        }
    }
}

/// A child's [`Env::waker`], and what its budget wakes when memory frees
/// after a charge of the child's was refused, one waiter for both: it
/// queues the child, then wakes what the child runs in. It is made the
/// first time a call asks for the waker or the child waits for memory, so
/// a child that does neither costs nothing for it, and then kept, so every
/// call gets the same waker and the budget sees a child that waits again
/// as the same waiter. It changes nothing in the child's wake, so it stays
/// good while the child is open.
pub(super) struct ChildWaker {
    child: Arc<ChildWake>,
    made: OnceCell<Waiter>,
}

impl ChildWaker {
    fn new(child: Arc<ChildWake>) -> ChildWaker {
        ChildWaker {
            child,
            made: OnceCell::new(),
        }
    }

    /// The waiter, made now to wake `around`'s waker if there is none yet.
    pub(super) fn waiter(&self, around: impl FnOnce() -> Waker) -> &Waiter {
        self.made.get_or_init(|| {
            let child = self.child.clone();
            let around = around();
            Waiter::from_fn(move || {
                child.notify();
                around.wake_by_ref();
            })
        })
    }
}

/// A child's work: its result goes back to the child, and a wake from it,
/// or its end without a result, gets the child visited.
pub struct ChildWork<W> {
    id: ChildId,
    pub(crate) work: OwnedWork<W>,
    pub(crate) wake: Arc<ChildWake>,
    pub(crate) finished: bool,
}

impl<W> ChildWork<W> {
    /// The child the work is for.
    pub fn id(&self) -> ChildId {
        self.id
    }

    /// Whether the child has closed.
    pub fn cancelled(&self) -> bool {
        self.work.cancelled()
    }
}

impl<W> Drop for ChildWork<W> {
    fn drop(&mut self) {
        if !self.finished {
            self.wake.notify();
        }
    }
}

/// What [`Children`] reports.
#[derive(Debug, PartialEq, Eq)]
pub enum ChildReport<E, X> {
    /// A child's layer reported this.
    Event(ChildId, E),
    /// A child's layer failed. The child was closed; its siblings go on.
    Failed(ChildId, X),
    /// A child was not taken, or broke its limits once taken, and was
    /// closed at once for the cause given, the one its close carried.
    Refused(ChildId, Closing),
}

/// The mux sent a child more than the credit granted for it: a broken mux,
/// so the whole connection stops. Memory never stops it: what the budget
/// cannot hold now waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overrun {
    /// The mux exceeded granted carrier credit.
    Credit(ChildId),
}

impl core::fmt::Display for Overrun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Credit(_) => "the mux sent a child more than its credit",
        })
    }
}

impl core::error::Error for Overrun {}

impl<B, K, O> Children<B, K, O>
where
    B: Layer<Upper = Top>,
    EventOf<B::Lower>: Credited,
    CommandOf<B::Lower>: Credited,
    K: Port,
{
    /// At most `limit` children at once, each with `window` credit units for
    /// its events and a layer from `make`. Returning `None` refuses this child.
    pub fn new(
        limit: usize,
        window: u64,
        make: impl FnMut(ChildId, O, &Budget) -> Option<B> + Send + 'static,
    ) -> Self {
        assert!(
            limit <= MAX_CHILDREN,
            "child limit exceeds the bounded router capacity"
        );
        Children {
            make: Box::new(make),
            budget_for: None,
            close_finished: false,
            ready: List::new(List::READY),
            work: List::new(List::WORK),
            armed: 0,
            limit,
            window,
            waiting: 0,
            places: Places::new(),
        }
    }

    /// Releases a child handle when its application is terminal and every
    /// command has drained. Enable this when the mux owns transport retirement
    /// independently of application lifetime. By default, the mux controls
    /// closure; finishing an application does not imply a reset of its carrier.
    pub fn close_finished(mut self) -> Self {
        self.close_finished = true;
        self
    }

    /// Chooses a child's budget before allocating its receive window or
    /// invoking its application factory. Siblings may share a budget (for
    /// example, one sandbox's connections) without sharing a lifetime.
    pub fn budgets(
        mut self,
        select: impl FnMut(ChildId, &O, &Budget) -> Budget + Send + 'static,
    ) -> Self {
        self.budget_for = Some(Box::new(select));
        self
    }

    /// The key of child `id`, while it is open.
    fn key(&self, id: ChildId) -> Option<usize> {
        let at = self
            .places
            .order
            .binary_search_by_key(&id, |(key, _)| *key)
            .ok()?;
        Some(self.places.order[at].1)
    }

    fn remove(&mut self, id: ChildId) -> Option<Kid<B>> {
        let at = self
            .places
            .order
            .binary_search_by_key(&id, |(key, _)| *key)
            .ok()?;
        let key = self.places.order.remove(at).1;
        self.ready.unlink(&mut self.places.kids, key);
        self.work.unlink(&mut self.places.kids, key);
        if let Some(place) = self.places.kids[key].heap {
            self.unschedule(place);
        }
        let kid = self.places.kids.remove(key);
        kid.wake.close();
        self.waiting -= usize::from(kid.memory);
        Some(kid)
    }

    /// Keeps what `kid`, which [`remove`](Self::remove) took out, leaves
    /// for the next child, and hands back its handle for its close.
    fn retire(&mut self, kid: Kid<B>) -> Child {
        let idle = self
            .places
            .charge
            .as_ref()
            .expect("a child was opened, so the places are paid for")
            .budget()
            .clone();
        let (handle, spare) = kid.retire(&idle);
        self.places.keep(spare);
        handle
    }

    /// Takes child `id` out and retires it, handing back its handle.
    fn close(&mut self, id: ChildId) -> Option<Child> {
        let kid = self.remove(id)?;
        Some(self.retire(kid))
    }

    /// Child `key` was called: its layer may have work, its deadline is
    /// read again, and with `ready` it needs a visit. A timer that `fired`
    /// is armed again even at the same moment, behind the others.
    fn called(&mut self, key: usize, ready: bool, fired: bool) {
        if ready {
            self.ready.push(&mut self.places.kids, key);
        }
        self.work.push(&mut self.places.kids, key);
        let due = self.places.kids[key].layer.deadline();
        self.schedule(key, due, fired);
    }

    /// Sets child `key`'s deadline in the heap.
    fn schedule(&mut self, key: usize, due: Option<(Instant, B::Timer)>, fired: bool) {
        let kid = &mut self.places.kids[key];
        if !fired && kid.due == due {
            return;
        }
        let place = kid.heap;
        kid.due = due;
        if kid.due.is_none() {
            if let Some(place) = place {
                self.unschedule(place);
            }
            return;
        }
        self.armed += 1;
        kid.armed = self.armed;
        let place = place.unwrap_or_else(|| {
            self.places.timers.push(key);
            self.places.timers.len() - 1
        });
        let place = self.sift_up(place);
        self.sift_down(place);
    }

    /// Takes the deadline at `place` out of the heap.
    fn unschedule(&mut self, place: usize) {
        let key = self.places.timers.swap_remove(place);
        self.places.kids[key].heap = None;
        if place < self.places.timers.len() {
            let place = self.sift_up(place);
            self.sift_down(place);
        }
    }

    /// When the child at heap `place` is due, and its arming number.
    fn due_at(&self, place: usize) -> (Instant, u64) {
        let kid = &self.places.kids[self.places.timers[place]];
        let (at, _) = kid.due.as_ref().expect("a scheduled child has a deadline");
        (*at, kid.armed)
    }

    fn sift_up(&mut self, mut place: usize) -> usize {
        while place > 0 {
            let parent = (place - 1) / 2;
            if self.due_at(parent) <= self.due_at(place) {
                break;
            }
            self.places.timers.swap(parent, place);
            self.places.kids[self.places.timers[place]].heap = Some(place);
            place = parent;
        }
        self.places.kids[self.places.timers[place]].heap = Some(place);
        place
    }

    fn sift_down(&mut self, mut place: usize) {
        loop {
            let mut first = place;
            for child in [2 * place + 1, 2 * place + 2] {
                if child < self.places.timers.len() && self.due_at(child) < self.due_at(first) {
                    first = child;
                }
            }
            if first == place {
                break;
            }
            self.places.timers.swap(first, place);
            self.places.kids[self.places.timers[place]].heap = Some(place);
            place = first;
        }
        self.places.kids[self.places.timers[place]].heap = Some(place);
    }

    /// Readies the children something reached from outside a call, in id
    /// order, whatever order their wakes came in.
    fn collect_wakes(&mut self) {
        let any = &self.places.woken.any;
        if !any.load(Ordering::Relaxed) || !any.swap(false, Ordering::Acquire) {
            return;
        }
        let mut keys = self.places.woken.keys.lock();
        let kids = &mut self.places.kids;
        keys.sort_unstable_by_key(|&key| kids[key].id);
        for key in keys.drain(..) {
            // Reads the wake that queued it, and whatever came before it.
            kids[key].wake.woken.swap(false, Ordering::Acquire);
            self.ready.push(kids, key);
            self.work.push(kids, key);
        }
    }

    /// The layer of child `id`, while it is open.
    pub fn child(&self, id: ChildId) -> Option<&B> {
        self.key(id).map(|key| &self.places.kids[key].layer)
    }

    /// The open children, in order.
    pub fn ids(&self) -> impl Iterator<Item = ChildId> + '_ {
        self.places.order.iter().map(|(id, _)| *id)
    }

    /// Whether nothing is open or queued either way: until an event comes,
    /// no step can move anything, and there is no timer or work.
    pub(crate) fn is_idle(&self) -> bool {
        self.places.kids.is_empty() && self.places.down.is_empty() && self.places.up.is_empty()
    }

    /// Closes a failed child and reports it.
    fn fail(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        id: ChildId,
        error: B::Error,
    ) {
        if let Some(handle) = self.close(id) {
            // Closing is bounded by the mux's own limit on children: the
            // mux keeps the slot until it takes this command.
            self.places.down.push_back(handle.close(Closing::Failed));
            env.report(ChildReport::Failed(id, error));
        }
    }

    /// Closes a child that broke its limits, for the cause `why`, and
    /// reports it with that cause. Dropping it cancels its work.
    fn refuse(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        id: ChildId,
        why: Closing,
    ) {
        if let Some(handle) = self.close(id) {
            self.places.down.push_back(handle.close(why));
            env.report(ChildReport::Refused(id, why));
        }
    }

    /// Whether child `id`'s place is full: its urgent place, or its inbox.
    fn full(&self, id: ChildId, urgent: bool) -> bool {
        self.key(id).is_some_and(|key| {
            let kid = &self.places.kids[key];
            if urgent {
                kid.urgent.is_some()
            } else {
                kid.inbox.len() >= QUEUE
            }
        })
    }

    /// One visit to child `key`: its internal work, one event in, one
    /// command out, and credit granted again. Returns whether anything
    /// moved. The child stays ready if something moved or if the mux's
    /// queue had no room for what it has to send.
    fn visit(&mut self, env: &mut Env<'_, ChildReport<B::Report, B::Error>>, key: usize) -> bool {
        self.ready.unlink(&mut self.places.kids, key);
        let since = self.places.kids[key].budget.refusals();
        let Some((moved, waiting)) = self.visit_kid(env, key) else {
            return true;
        };
        let kid = &mut self.places.kids[key];
        let id = kid.id;
        if kid
            .wait_for_memory(since, env.wakes(), true, &mut self.waiting)
            .is_some()
        {
            self.refuse(env, id, Closing::Failed);
            return true;
        }
        self.called(key, moved || waiting, false);
        moved
    }

    /// The visit itself: whether anything moved and whether the child waits
    /// for room in the mux's queue, or `None` if the child was closed.
    fn visit_kid(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        key: usize,
    ) -> Option<(bool, bool)> {
        let kid = &mut self.places.kids[key];
        let id = kid.id;
        let report = move |e| ChildReport::Event(id, e);
        // Until `take_released` below. A closed child takes nothing more.
        kid.wake.enter();
        let mut moved = match env.scoped_child(&kid.budget, &kid.waiter, report, |env| {
            kid.layer.advance(env)
        }) {
            Ok(moved) => moved,
            Err(e) => {
                self.fail(env, id, e);
                return None;
            }
        };
        if let Some(event) = kid.urgent.take() {
            match env.scoped_child(&kid.budget, &kid.waiter, report, |env| {
                kid.layer.on_event(env, event)
            }) {
                Ok(Admit::Taken | Admit::Closed(_)) => moved = true,
                Ok(Admit::Blocked(event) | Admit::Partial(event)) => kid.urgent = Some(event),
                Err(e) => {
                    self.fail(env, id, e);
                    return None;
                }
            }
        }
        if let Some((event, retained)) = kid.inbox.pop_front() {
            let cost = event.credit();
            match env.scoped_child(&kid.budget, &kid.waiter, report, |env| {
                kid.layer.on_event(env, event)
            }) {
                Ok(Admit::Taken | Admit::Closed(_)) => {
                    if !retained {
                        kid.owed += cost;
                    }
                    moved = true;
                }
                Ok(Admit::Partial(rest)) => {
                    if !retained {
                        kid.owed += cost - rest.credit().min(cost);
                    }
                    assert!(kid.inbox.push_front((rest, retained)).is_ok());
                    moved = true;
                }
                Ok(Admit::Blocked(event)) => {
                    assert!(kid.inbox.push_front((event, retained)).is_ok());
                }
                Err(e) => {
                    self.fail(env, id, e);
                    return None;
                }
            }
        }
        if kid.outbox.is_none() {
            kid.outbox = env.scoped_child(&kid.budget, &kid.waiter, report, |env| {
                kid.layer.take_command(env)
            });
            moved |= kid.outbox.is_some();
        }
        let output_idle = kid.outbox.is_none();
        let mut waiting = false;
        if let Some(mut command) = kid.outbox.take() {
            if !command.splittable() && command.credit() > kid.max_command {
                self.refuse(env, id, Closing::Failed);
                return None;
            }
            if !command.reserve(&kid.budget) {
                // Its budget cannot pay for the command now: the command
                // waits in the outbox, and the child for memory
                // (`wait_for_memory`, after the visit).
                kid.outbox = Some(command);
            } else if self.places.down.len() < QUEUE - RESERVE {
                match command.admit_credit(kid.credit) {
                    Ok((prefix, rest)) => {
                        kid.credit -= prefix.credit();
                        self.places.down.push_back(kid.handle.send(prefix));
                        kid.outbox = rest;
                        moved = true;
                    }
                    // Credit from the mux gets the child visited again.
                    Err(command) => kid.outbox = Some(command),
                }
            } else {
                kid.outbox = Some(command);
                waiting = true;
            }
        }
        kid.owed += kid.wake.take_released();
        if kid.owed > 0 {
            if self.places.down.len() < QUEUE {
                // The first credit lends the mux the window that pays for
                // every byte it lets come up, so the mux can make them in
                // it.
                let grant = if kid.lent {
                    kid.handle.grant(kid.owed)
                } else {
                    kid.lent = true;
                    kid.handle.lend_window(kid.owed, &kid.window)
                };
                self.places.down.push_back(grant);
                kid.granted += kid.owed;
                kid.owed = 0;
                moved = true;
            } else {
                waiting = true;
            }
        }
        if self.close_finished && output_idle && kid.layer.is_terminal() {
            if self.places.down.len() < QUEUE {
                let handle = self.close(id).expect("visited child");
                self.places.down.push_back(handle.close(Closing::Done));
                return None;
            }
            waiting = true;
        }
        Some((moved, waiting))
    }
}

impl<B, K, O> Layer for Children<B, K, O>
where
    B: Layer<Upper = Top>,
    EventOf<B::Lower>: Credited,
    CommandOf<B::Lower>: Credited,
    K: Port,
{
    type Lower = Mux<B::Lower, K, O>;
    type Upper = K;
    type Report = ChildReport<B::Report, B::Error>;
    type Timer = (ChildId, B::Timer);
    type Work = ChildWork<B::Work>;
    type Done = (ChildId, B::Done);
    type Error = Overrun;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: MuxEvent<B::Lower, K, O>,
    ) -> Result<Admit<MuxEvent<B::Lower, K, O>>, Overrun> {
        if !self.places.reserve(env.budget()) {
            return Ok(Admit::Blocked(event));
        }
        match event {
            MuxEvent::Opened(child, opening, max_command) => {
                let id = child.id();
                if self.places.down.len() >= QUEUE {
                    return Ok(Admit::Blocked(MuxEvent::Opened(
                        child,
                        opening,
                        max_command,
                    )));
                }
                // A child past the limit, or one the application says no
                // to, is prohibited; one whose place or window the budget
                // cannot hold now is refused for want of memory. Either is
                // closed at once, its siblings and the connection
                // untouched.
                // The child asks through a view of its own, so what its
                // budget refuses is its own record, not a sibling's. What
                // a closed child left serves it where nothing else holds
                // it ([`Spare`]).
                let selected = match &mut self.budget_for {
                    Some(select) => select(id, &opening, env.budget()),
                    None => env.budget().clone(),
                };
                let (budget, kept_wake, owner, kept_window) = match self.places.spares.pop() {
                    Some(Spare {
                        wake,
                        budget,
                        owner,
                        window,
                    }) => (selected.view_in(budget), Some(wake), owner, window),
                    None => (selected.view(), None, WorkOwner::new(), None),
                };
                let reserved = if self.places.kids.len() >= self.limit {
                    Err(Closing::Prohibited)
                } else if !self.places.make_room(self.limit) {
                    Err(Closing::ResourceShortage)
                } else {
                    EventOf::<B::Lower>::receive_bytes(self.window)
                        .and_then(|bytes| budget.charge(bytes))
                        .ok_or(Closing::ResourceShortage)
                };
                let made = reserved.and_then(|window| {
                    let layer = (self.make)(id, opening, &budget).ok_or(Closing::Prohibited)?;
                    Ok((window, layer))
                });
                let (window, layer) = match made {
                    Ok(made) => made,
                    Err(why) => {
                        // Nothing of it went to a child, so it is kept as
                        // it was, for the next.
                        if let Some(wake) = kept_wake {
                            self.places.keep(Spare {
                                wake,
                                budget,
                                owner,
                                window: kept_window,
                            });
                        }
                        self.places.down.push_back(child.close(why));
                        env.report(ChildReport::Refused(id, why));
                        return Ok(Admit::Taken);
                    }
                };
                // A kept window is the router's alone: no one could reach
                // it since its child closed.
                let window = match kept_window {
                    Some(mut kept) => match Arc::get_mut(&mut kept) {
                        Some(place) => {
                            *place = window;
                            kept
                        }
                        None => Arc::new(window),
                    },
                    None => Arc::new(window),
                };
                let mut owner = owner;
                owner.renew();
                let due = layer.deadline();
                assert!(env.fits_below(&layer), "composition is too deep");
                let place = self.places.kids.vacant_entry();
                let key = place.key();
                let wake = kept_wake
                    .and_then(|wake| ChildWake::renewed(wake, key))
                    .unwrap_or_else(|| Arc::new(ChildWake::new(key, self.places.woken.clone())));
                let waiter = ChildWaker::new(wake.clone());
                place.insert(Kid {
                    id,
                    handle: child,
                    links: [Link::default(); 2],
                    due: None,
                    armed: 0,
                    heap: None,
                    layer,
                    inbox: ChargedDeque::new(&budget, QUEUE),
                    budget,
                    owner,
                    urgent: None,
                    wake,
                    waiter,
                    window,
                    max_command,
                    lent: false,
                    granted: 0,
                    owed: self.window,
                    credit: 0,
                    outbox: None,
                    memory: false,
                });
                let at = self
                    .places
                    .order
                    .binary_search_by_key(&id, |(key, _)| *key)
                    .unwrap_err();
                self.places.order.insert(at, (id, key));
                self.ready.push(&mut self.places.kids, key);
                self.work.push(&mut self.places.kids, key);
                self.schedule(key, due, false);
            }
            MuxEvent::Child(id, mut event) => {
                // Reset ends this lifetime immediately. Notify the child, then
                // discard its refused input, output, credit and work together.
                if event.terminal_reset() {
                    if let Some(mut kid) = self.remove(id) {
                        kid.owner.cancel();
                        if let Err(error) = env.scoped_child(
                            &kid.budget,
                            &kid.waiter,
                            |event| ChildReport::Event(id, event),
                            |env| kid.layer.on_event(env, event),
                        ) {
                            env.report(ChildReport::Failed(id, error));
                        }
                        let handle = self.retire(kid);
                        self.places.down.push_back(handle.close(Closing::Done));
                    }
                    return Ok(Admit::Taken);
                }
                // A child already gone has nothing to deliver to.
                let Some(key) = self.key(id) else {
                    return Ok(Admit::Taken);
                };
                let cost = event.credit();
                if cost > self.places.kids[key].granted {
                    return Err(Overrun::Credit(id));
                }
                // A full place gets the child one visit to make room. A
                // child that makes none is overloaded and goes alone: the
                // event is never handed back to block the mux.
                let urgent = B::Lower::urgent(&event);
                if self.full(id, urgent) {
                    self.visit(env, key);
                    if self.full(id, urgent) {
                        self.refuse(env, id, Closing::Failed);
                    }
                }
                if let Some(key) = self.key(id) {
                    let kid = &mut self.places.kids[key];
                    if urgent {
                        kid.urgent = Some(event);
                    } else {
                        // Its place in the inbox and its payload are paid
                        // for first, both refusals changing nothing. The
                        // inbox has room for it, so only memory refuses:
                        // the event goes back to the mux and waits, the
                        // child with it, until its budget frees (rule 9).
                        // An event the child could never pay for closes
                        // the child, and goes with it.
                        let since = kid.budget.refusals();
                        if !kid.inbox.reserve(1) || !event.reserve_receive(&kid.budget, &kid.window)
                        {
                            if kid
                                .wait_for_memory(since, env.wakes(), false, &mut self.waiting)
                                .is_none()
                            {
                                return Ok(Admit::Blocked(MuxEvent::Child(id, event)));
                            }
                            self.refuse(env, id, Closing::Failed);
                            return Ok(Admit::Taken);
                        }
                        kid.granted -= cost;
                        // Credit the payload does not hold goes back when
                        // the child takes the event (`visit`).
                        let retained = cost > 0
                            && match event.retain_lease(CreditLease::new(kid.wake.clone(), cost)) {
                                Some(lease) => {
                                    lease.disarm();
                                    false
                                }
                                None => true,
                            };
                        assert!(
                            kid.inbox.push_back((event, retained)).is_ok(),
                            "the place was reserved"
                        );
                    }
                    self.ready.push(&mut self.places.kids, key);
                }
            }
            MuxEvent::Credit(id, units) => {
                if let Some(key) = self.key(id) {
                    let kid = &mut self.places.kids[key];
                    kid.credit = kid.credit.saturating_add(units);
                    self.ready.push(&mut self.places.kids, key);
                }
            }
            MuxEvent::Closed(id) => {
                // The mux closed it: its handle has nothing left to say.
                self.close(id);
            }
            MuxEvent::Control(event) => {
                if self.places.up.len() >= QUEUE {
                    return Ok(Admit::Blocked(MuxEvent::Control(event)));
                }
                self.places.up.push_back(event);
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<K>,
    ) -> Result<Admit<CommandOf<K>>, Overrun> {
        if !self.places.reserve(env.budget()) || self.places.down.len() >= QUEUE {
            return Ok(Admit::Blocked(command));
        }
        self.places.down.push_back(MuxCommand::control(command));
        Ok(Admit::Taken)
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        (id, timer): Self::Timer,
    ) -> Result<bool, Overrun> {
        let Some(key) = self.key(id) else {
            return Ok(false);
        };
        let kid = &mut self.places.kids[key];
        let since = kid.budget.refusals();
        let layer = &mut kid.layer;
        let result = kid.wake.call(|| {
            env.scoped_child(
                &kid.budget,
                &kid.waiter,
                move |e| ChildReport::Event(id, e),
                |env| layer.on_timer(env, timer),
            )
        });
        // A child that declines its timer still goes behind its siblings
        // due at the same time, so theirs fire first.
        match result {
            Ok(fired) => {
                if self.places.kids[key]
                    .wait_for_memory(since, env.wakes(), false, &mut self.waiting)
                    .is_some()
                {
                    self.refuse(env, id, Closing::Failed);
                } else {
                    self.called(key, true, true);
                }
                Ok(fired)
            }
            Err(e) => {
                self.fail(env, id, e);
                Ok(true)
            }
        }
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        (id, done): Self::Done,
    ) -> Result<(), Overrun> {
        let Some(key) = self.key(id) else {
            return Ok(());
        };
        let kid = &mut self.places.kids[key];
        let since = kid.budget.refusals();
        let layer = &mut kid.layer;
        let result = kid.wake.call(|| {
            env.scoped_child(
                &kid.budget,
                &kid.waiter,
                move |e| ChildReport::Event(id, e),
                |env| layer.on_done(env, done),
            )
        });
        match result {
            Ok(()) => {
                if self.places.kids[key]
                    .wait_for_memory(since, env.wakes(), false, &mut self.waiting)
                    .is_some()
                {
                    self.refuse(env, id, Closing::Failed);
                } else {
                    self.called(key, true, false);
                }
            }
            Err(e) => self.fail(env, id, e),
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Overrun> {
        // The queues are the router's fixed state: an idle connection holds
        // them from its first step. Until they are paid for, no child is
        // open, so nothing can move.
        if !self.places.reserve(env.budget()) {
            return Ok(false);
        }
        self.collect_wakes();
        // The children ready now, in list order, at most QUEUE of them. One
        // that stays ready goes to the end and waits for the next advance.
        let mut moved = false;
        for visits in 0..self.ready.len {
            if visits == QUEUE {
                self.places.release();
                return Ok(true);
            }
            let Some(key) = self.ready.head else {
                break;
            };
            moved |= self.visit(env, key);
        }
        self.places.release();
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<MuxCommand<B::Lower, K>> {
        self.places.down.pop_front()
    }

    fn take_event(&mut self) -> Option<EventOf<K>> {
        self.places.up.pop_front()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        while let Some(key) = self.work.pop(&mut self.places.kids) {
            let kid = &mut self.places.kids[key];
            let layer = &mut kid.layer;
            let Some(work) = kid.wake.call(|| layer.take_work()) else {
                continue;
            };
            let work = ChildWork {
                id: kid.id,
                work: kid.owner.own(work),
                wake: kid.wake.clone(),
                finished: false,
            };
            // Handing work over can change the layer, as a session's idle
            // timer stops while its work runs. The child goes to the end of
            // the work list, behind its siblings.
            self.called(key, true, false);
            return Some(work);
        }
        None
    }

    fn report_bytes(report: &Self::Report) -> Option<usize> {
        match report {
            ChildReport::Event(_, event) => B::report_bytes(event),
            ChildReport::Refused(..) => Some(0),
            ChildReport::Failed(_, _) => None,
        }
    }

    fn depth(&self) -> usize {
        1 + self
            .places
            .kids
            .iter()
            .map(|(_, kid)| kid.layer.depth())
            .max()
            .unwrap_or(0)
    }

    /// Whether an open child waits for memory on its own view
    /// ([`Kid::wait_for_memory`]), which the runner does not read.
    fn waits_for_memory(&self) -> bool {
        self.waiting > 0
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        let kid = &self.places.kids[*self.places.timers.first()?];
        let (at, timer) = kid.due.clone()?;
        Some((at, (kid.id, timer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Seed;
    use crate::entropy::SeededEntropy;
    use crate::stdlib::layer::{
        ByteStream, Chunk, Direction, Driver, ObservedEvent, ObservedStream, Slots, StreamCommand,
        StreamEvent,
    };
    use bytes::Bytes;
    use std::convert::Infallible;

    #[derive(Default)]
    struct Reader {
        held: Option<Chunk>,
        writes: VecDeque<StreamCommand>,
        waiting: bool,
        ended: bool,
        completions: u64,
        work: bool,
        productive: bool,
        timer: bool,
        fired: usize,
        terminal: bool,
    }

    impl Layer for Reader {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn is_terminal(&self) -> bool {
            self.terminal
        }
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            match event {
                StreamEvent::Data(_) if self.waiting || self.held.is_some() => {
                    return Ok(Admit::Blocked(event));
                }
                StreamEvent::Data(chunk) => self.held = Some(chunk),
                StreamEvent::Written(n) => {
                    self.waiting = false;
                    self.completions += n;
                }
                StreamEvent::Ended => self.ended = true,
                StreamEvent::Reset => self.held = None,
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            c: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match c {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            self.writes.pop_front().or_else(|| {
                self.productive
                    .then(|| StreamCommand::Write(Chunk::unpaid(vec![1])))
            })
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn take_work(&mut self) -> Option<()> {
            self.work.then_some(())
        }
        fn deadline(&self) -> Option<(Instant, ())> {
            self.timer.then_some((Instant::ZERO, ()))
        }
        fn on_timer(&mut self, _: &mut Env<'_, ()>, _: ()) -> Result<bool, Infallible> {
            self.fired += 1;
            Ok(true)
        }
    }

    fn driver(
        mut make: impl FnMut(ChildId, &'static str, &Budget) -> Reader + Send + 'static,
    ) -> Driver<Children<Reader, Top, &'static str>> {
        Driver::new(
            Children::new(3, 8, move |id, opening, budget| {
                Some(make(id, opening, budget))
            }),
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::new(100_000),
            Instant::ZERO,
        )
    }

    /// A child that counts the observed bytes it takes.
    #[derive(Default)]
    struct Observe(usize);

    impl Layer for Observe {
        type Lower = ObservedStream;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            event: ObservedEvent,
        ) -> Result<Admit<ObservedEvent>, Infallible> {
            if let ObservedEvent::Data { bytes, .. } = event {
                self.0 += bytes.len();
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<Infallible> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    fn observed_byte() -> ObservedEvent {
        ObservedEvent::Data {
            direction: Direction::Forward,
            bytes: Chunk::unpaid(vec![1]),
            sequence: 0,
            source: None,
        }
    }

    #[test]
    fn credit_returned_at_delivery_wakes_nothing_when_admitted() {
        let mut driver = Driver::new(
            Children::<Observe, Top, ()>::new(1, 8, |_, (), _| Some(Observe::default())),
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let child = Slots::new(1).insert(()).unwrap();
        let id = child.id();
        let _ = driver.deliver(MuxEvent::Opened(child, (), 0)).unwrap();
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        // Observed data does not hold its credit: the mux returns it when
        // the child takes the event, so admitting it wakes nothing.
        let _ = driver
            .deliver(MuxEvent::Child(id, observed_byte()))
            .unwrap();
        assert!(!driver.layer().places.woken.any.load(Ordering::Acquire));
        assert!(driver.layer().places.woken.keys.lock().is_empty());
        driver.run().unwrap();
        assert_eq!(driver.layer().child(id).unwrap().0, 1);
        assert!(matches!(
            driver.take_command().unwrap().into_op(),
            super::super::MuxOp::Credit(found, 1) if found == id
        ));
    }

    /// An event whose payload the child's budget cannot pay for now goes
    /// back to the mux unchanged, and the child stays open: nothing is
    /// closed or reported. The release that makes room wakes the task, and
    /// the event, offered again, is taken once.
    #[test]
    fn an_uncharged_payload_that_does_not_fit_waits_with_its_child_open() {
        let budget = Budget::new(4096);
        let child_budget = budget.clone();
        let children = Children::<Observe, Top, ()>::new(2, 8, |_, (), _| Some(Observe::default()))
            .budgets(move |_, _, _| child_budget.clone());
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let task = Arc::new(Task::default());
        driver.set_waker(&Waker::from(task.clone()));
        let mut slots = Slots::new(2);
        let mut ids = Vec::new();
        for _ in 0..2 {
            let child = slots.insert(()).unwrap();
            ids.push(child.id());
            let _ = driver.deliver(MuxEvent::Opened(child, (), 0)).unwrap();
        }
        driver.run().unwrap();
        let payload = observed_byte;
        for id in &ids {
            let _ = driver.deliver(MuxEvent::Child(*id, payload())).unwrap();
            driver.run().unwrap();
        }
        while driver.take_command().is_some() {}
        let taken = driver.layer().child(ids[0]).unwrap().0;
        let rest = budget.charge(budget.limit() - budget.used()).unwrap();
        let Ok(Admit::Blocked(back)) = driver.deliver(MuxEvent::Child(ids[0], payload())) else {
            panic!("a payload its budget refuses goes back to the mux")
        };
        assert!(
            matches!(&back, MuxEvent::Child(id, ObservedEvent::Data { bytes, .. })
                if *id == ids[0] && bytes.len() == 1),
            "unchanged"
        );
        driver.run().unwrap();
        assert!(
            driver.layer().child(ids[0]).is_some(),
            "the child stays open"
        );
        assert!(
            std::iter::from_fn(|| driver.take_command())
                .all(|command| !matches!(command.into_op(), super::super::MuxOp::Close(..))),
            "nothing is closed"
        );
        assert!(
            driver
                .observations()
                .drain()
                .all(|report| !matches!(report, ChildReport::Refused(..))),
            "nothing is refused"
        );
        assert_eq!(task.0.load(Ordering::Acquire), 0, "no memory freed yet");
        drop(rest);
        assert!(
            task.0.load(Ordering::Acquire) > 0,
            "the release wakes the task"
        );
        assert!(matches!(driver.deliver(back), Ok(Admit::Taken)));
        driver.run().unwrap();
        assert_eq!(driver.layer().child(ids[0]).unwrap().0, taken + 1);
        let _ = driver.deliver(MuxEvent::Child(ids[1], payload())).unwrap();
        driver.run().unwrap();
        assert_eq!(driver.layer().child(ids[1]).unwrap().0, 2);
    }

    /// Children closed or refused, each with its cause.
    type Causes = Vec<(ChildId, Closing)>;

    /// The closes a stack of children sent down, and the refusals it
    /// reported.
    fn closes_and_refusals(driver: &mut Driver<Children<Observe, Top, ()>>) -> (Causes, Causes) {
        let closed = std::iter::from_fn(|| driver.take_command())
            .filter_map(|command| match command.into_op() {
                super::super::MuxOp::Close(id, why) => Some((id, why)),
                _ => None,
            })
            .collect();
        let refused = driver
            .observations()
            .drain()
            .filter_map(|report| match report {
                ChildReport::Refused(id, why) => Some((id, why)),
                _ => None,
            })
            .collect();
        (closed, refused)
    }

    /// An event larger than its child's whole limit can never be paid for:
    /// no release meets it, so waiting would hold up the mux for good. That
    /// child alone is closed as failed and the event goes with it; its
    /// sibling and the connection go on.
    #[test]
    fn an_event_past_its_childs_limit_closes_that_child_alone() {
        let budget = Budget::new(4096);
        let child_budget = budget.clone();
        // Credit for the event, so only memory stands in its way.
        let window = 4 * budget.limit() as u64;
        let children =
            Children::<Observe, Top, ()>::new(2, window, |_, (), _| Some(Observe::default()))
                .budgets(move |_, _, _| child_budget.clone());
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(94))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let mut slots = Slots::new(2);
        let ids: Vec<_> = (0..2)
            .map(|_| {
                let child = slots.insert(()).unwrap();
                let id = child.id();
                let _ = driver.deliver(MuxEvent::Opened(child, (), 0)).unwrap();
                id
            })
            .collect();
        driver.run().unwrap();
        let _ = closes_and_refusals(&mut driver);
        let mark = driver.refusals();
        let past = ObservedEvent::Data {
            direction: Direction::Forward,
            bytes: Chunk::unpaid(vec![1; 2 * budget.limit()]),
            sequence: 0,
            source: None,
        };
        assert!(
            matches!(
                driver.deliver(MuxEvent::Child(ids[0], past)),
                Ok(Admit::Taken)
            ),
            "the mux is not held up"
        );
        driver.run().unwrap();
        assert!(
            driver.layer().child(ids[0]).is_none(),
            "the child is closed"
        );
        let (closed, refused) = closes_and_refusals(&mut driver);
        assert_eq!(closed, [(ids[0], Closing::Failed)]);
        assert_eq!(refused, [(ids[0], Closing::Failed)]);
        assert_eq!(
            driver.budget().starved_since(mark),
            None,
            "the connection is not starved"
        );
        let _ = driver
            .deliver(MuxEvent::Child(ids[1], observed_byte()))
            .unwrap();
        driver.run().unwrap();
        assert_eq!(driver.layer().child(ids[1]).unwrap().0, 1);
    }

    /// A command larger than its child's whole limit can never be paid for,
    /// so it does not wait in the outbox for good: that child alone is
    /// closed as failed, nothing of the command goes down, and its sibling
    /// and the connection go on.
    #[test]
    fn a_command_past_its_childs_limit_closes_that_child_alone() {
        let budget = Budget::new(4096);
        let child_budget = budget.clone();
        let limit = budget.limit();
        let mut driver = Driver::new(
            Children::<Reader, Top, ()>::new(2, 8, move |_, (), _| {
                Some(Reader {
                    writes: [StreamCommand::Write(Chunk::unpaid(vec![7; 2 * limit]))].into(),
                    ..Reader::default()
                })
            })
            .budgets(move |_, _, _| child_budget.clone()),
            Arc::new(SeededEntropy::new(Seed::from_u64(95))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let mark = driver.refusals();
        let mut slots = Slots::new(2);
        let first = slots.insert(()).unwrap();
        let id = first.id();
        let _ = driver.deliver(MuxEvent::Opened(first, (), 64)).unwrap();
        let _ = driver.deliver(MuxEvent::Credit(id, 64)).unwrap();
        driver.run().unwrap();
        assert!(driver.layer().child(id).is_none(), "the child is closed");
        let mut closed = Vec::new();
        while let Some(command) = driver.take_command() {
            match command.into_op() {
                super::super::MuxOp::Child(_, StreamCommand::Write(_)) => {
                    panic!("nothing unpaid goes down")
                }
                super::super::MuxOp::Close(gone, why) => closed.push((gone, why)),
                _ => {}
            }
        }
        assert_eq!(closed, [(id, Closing::Failed)]);
        let refused: Vec<_> = driver
            .observations()
            .drain()
            .filter_map(|report| match report {
                ChildReport::Refused(id, why) => Some((id, why)),
                _ => None,
            })
            .collect();
        assert_eq!(refused, [(id, Closing::Failed)]);
        assert_eq!(
            driver.budget().starved_since(mark),
            None,
            "the connection is not starved"
        );
        let second = slots.insert(()).unwrap();
        let sibling = second.id();
        assert!(matches!(
            driver.deliver(MuxEvent::Opened(second, (), 64)),
            Ok(Admit::Taken)
        ));
        assert!(driver.layer().child(sibling).is_some(), "a sibling opens");
    }

    #[test]
    fn terminal_children_drain_every_command_before_closing() {
        let mut driver = driver(|_, _, _| Reader {
            terminal: true,
            writes: [
                StreamCommand::Write(Chunk::unpaid(b"first".to_vec())),
                StreamCommand::Write(Chunk::unpaid(b"last".to_vec())),
                StreamCommand::End,
            ]
            .into(),
            ..Reader::default()
        });
        driver.layer_mut().close_finished = true;
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        assert!(
            driver
                .deliver(MuxEvent::Opened(child, "stream", 9))
                .unwrap()
                .moved()
        );
        assert!(driver.deliver(MuxEvent::Credit(id, 9)).unwrap().moved());
        driver.run().unwrap();
        let mut bytes = Vec::new();
        let mut ended = false;
        let mut closed = false;
        driver.send_below(|command| {
            match command.into_op() {
                super::super::MuxOp::Child(_, StreamCommand::Write(chunk)) => {
                    assert!(!ended && !closed);
                    bytes.extend_from_slice(&chunk);
                }
                super::super::MuxOp::Child(_, StreamCommand::End) => ended = true,
                super::super::MuxOp::Close(_, why) => {
                    assert_eq!(why, Closing::Done, "a finished child is done");
                    assert!(ended);
                    closed = true;
                }
                _ => {}
            }
            Admit::Taken
        });
        assert_eq!(bytes, b"firstlast");
        assert!(closed);
    }

    #[test]
    fn child_budgets_are_selected_before_allocation_and_do_not_refuse_siblings() {
        let denied = Budget::new(0);
        let allowed = Budget::new(4096);
        let (empty, room) = (denied.clone(), allowed.clone());
        let children = Children::<Reader, Top, bool>::new(2, 8, |_, allowed, budget| {
            assert!(
                allowed,
                "a refused child must not construct its application"
            );
            assert!(
                budget.used() > 0,
                "receive storage is reserved before construction"
            );
            Some(Reader::default())
        })
        .budgets(move |_, allowed, _| {
            if *allowed {
                room.clone()
            } else {
                empty.clone()
            }
        });
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let mut slots = Slots::new(2);
        let refused = slots.insert(()).unwrap();
        let accepted = slots.insert(()).unwrap();
        let (refused_id, accepted_id) = (refused.id(), accepted.id());
        assert!(
            driver
                .deliver(MuxEvent::Opened(refused, false, 8))
                .unwrap()
                .moved()
        );
        assert!(
            driver
                .deliver(MuxEvent::Opened(accepted, true, 8))
                .unwrap()
                .moved()
        );
        driver.run().unwrap();
        assert!(driver.layer().child(refused_id).is_none());
        assert!(driver.layer().child(accepted_id).is_some());
        assert_eq!(denied.used(), 0);
        assert!(allowed.used() > 0);
        assert!(
            driver
                .deliver(MuxEvent::Closed(accepted_id))
                .unwrap()
                .moved()
        );
        assert_eq!(allowed.used(), 0);
    }

    #[test]
    fn stream_output_drains_through_a_smaller_credit_window() {
        let mut driver = driver(|_, name, _| {
            assert_eq!(name, "stream");
            Reader {
                writes: VecDeque::from([StreamCommand::Write(Chunk::unpaid(Bytes::from_static(
                    b"abcdefgh",
                )))]),
                ..Reader::default()
            }
        });
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        assert!(
            driver
                .deliver(MuxEvent::Opened(child, "stream", 1))
                .unwrap()
                .moved()
        );
        let mut delivered = Vec::new();
        for _ in 0..8 {
            assert!(driver.deliver(MuxEvent::Credit(id, 1)).unwrap().moved());
            driver.run().unwrap();
            while let Some(command) = driver.take_command() {
                if let super::super::MuxOp::Child(actual, StreamCommand::Write(bytes)) =
                    command.into_op()
                {
                    assert_eq!(actual, id);
                    assert_eq!(bytes.len(), 1);
                    delivered.extend_from_slice(&bytes);
                }
            }
        }
        assert_eq!(delivered, b"abcdefgh");
    }

    #[test]
    fn completion_passes_refused_data_but_eof_does_not() {
        let mut driver = driver(|_, _, _| Reader {
            waiting: true,
            ..Reader::default()
        });
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        let _ = driver
            .deliver(MuxEvent::Opened(child, "stream", 8))
            .unwrap();
        driver.run().unwrap();
        let _ = driver
            .deliver(MuxEvent::Child(
                id,
                StreamEvent::Data(Chunk::unpaid(Bytes::from_static(b"abc"))),
            ))
            .unwrap();
        let _ = driver
            .deliver(MuxEvent::Child(id, StreamEvent::Ended))
            .unwrap();
        driver.run().unwrap();
        assert!(!driver.layer().child(id).unwrap().ended);
        let _ = driver
            .deliver(MuxEvent::Child(id, StreamEvent::Written(3)))
            .unwrap();
        driver.run().unwrap();
        let kid = driver.layer().child(id).unwrap();
        assert_eq!(kid.completions, 3);
        assert_eq!(kid.held.as_deref(), Some(&b"abc"[..]));
        assert!(kid.ended);
    }

    #[test]
    fn retained_input_holds_receive_credit_until_its_backing_is_released() {
        let mut driver = driver(|_, _, _| Reader::default());
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        let _ = driver
            .deliver(MuxEvent::Opened(child, "stream", 8))
            .unwrap();
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        let _ = driver
            .deliver(MuxEvent::Child(
                id,
                StreamEvent::Data(Chunk::unpaid(Bytes::from_static(b"abc"))),
            ))
            .unwrap();
        driver.run().unwrap();
        assert!(driver.take_command().is_none());
        let chunk = driver.layer_mut().places.kids[0].layer.held.take().unwrap();
        driver.run().unwrap();
        assert!(driver.take_command().is_none());
        drop(chunk);
        driver.run().unwrap();
        assert!(matches!(
            driver.take_command().unwrap().into_op(),
            super::super::MuxOp::Credit(_, 3)
        ));
    }

    #[test]
    fn editing_retained_input_returns_credit_only_after_the_last_piece() {
        for shared in [false, true] {
            let mut driver = driver(|_, _, _| Reader::default());
            let mut slots = Slots::new(1);
            let child = slots.insert(()).unwrap();
            let id = child.id();
            let _ = driver
                .deliver(MuxEvent::Opened(child, "stream", 8))
                .unwrap();
            driver.run().unwrap();
            while driver.take_command().is_some() {}
            let _ = driver
                .deliver(MuxEvent::Child(
                    id,
                    StreamEvent::Data(Chunk::unpaid(vec![1, 2, 3])),
                ))
                .unwrap();
            driver.run().unwrap();
            let chunk = driver.layer_mut().places.kids[0].layer.held.take().unwrap();
            let mut original = Some(chunk);
            let mut edit = if shared {
                original.as_mut().unwrap().split_to(1)
            } else {
                original.take().unwrap()
            };
            let budget = Budget::new(16);
            edit.make_mut(&budget).unwrap()[0] = 9;
            if shared {
                drop(original.take());
            }
            driver.run().unwrap();
            assert!(driver.take_command().is_none());
            drop(edit);
            driver.run().unwrap();
            assert!(matches!(driver.take_command().unwrap().into_op(),
                super::super::MuxOp::Credit(found, 3) if found == id));
            driver.run().unwrap();
            assert!(driver.take_command().is_none());
            assert_eq!(budget.used(), 0);
        }
    }

    /// Opens a child on `driver` that holds one piece of data, taken out of
    /// its layer and returned, with the commands its opening made taken.
    fn holding(
        driver: &mut Driver<Children<Reader, Top, &'static str>>,
        slots: &mut Slots<()>,
    ) -> (ChildId, Chunk) {
        let child = slots.insert(()).unwrap();
        let id = child.id();
        let _ = driver
            .deliver(MuxEvent::Opened(child, "stream", 8))
            .unwrap();
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        let _ = driver
            .deliver(MuxEvent::Child(
                id,
                StreamEvent::Data(Chunk::unpaid(vec![1])),
            ))
            .unwrap();
        driver.run().unwrap();
        assert!(driver.take_command().is_none());
        let layer = driver.layer_mut();
        let key = layer.key(id).unwrap();
        (id, layer.places.kids[key].layer.held.take().unwrap())
    }

    /// A child whose state changes outside its calls: it keeps the waker
    /// its calls get, and writes once `go` is set.
    struct Waits {
        go: Arc<AtomicBool>,
        kept: Arc<Mutex<Option<Waker>>>,
        wrote: bool,
    }

    impl Layer for Waits {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
            self.kept.lock().get_or_insert_with(|| env.waker());
            Ok(false)
        }
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            _: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            c: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match c {}
        }
        fn take_command(&mut self, _: &mut Env<'_, ()>) -> Option<StreamCommand> {
            (self.go.load(Ordering::Acquire) && !self.wrote).then(|| {
                self.wrote = true;
                StreamCommand::Write(Chunk::unpaid(vec![1]))
            })
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    /// Counts the wakes of the task that runs the stack.
    #[derive(Default)]
    struct Task(AtomicU64);

    impl Wake for Task {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn a_child_woken_from_outside_its_calls_wakes_the_runner_and_is_visited() {
        let go = Arc::new(AtomicBool::new(false));
        let kept = Arc::new(Mutex::new(None));
        let (child_go, child_kept) = (go.clone(), kept.clone());
        let mut driver = Driver::new(
            Children::<Waits, Top, ()>::new(1, 8, move |_, (), _| {
                Some(Waits {
                    go: child_go.clone(),
                    kept: child_kept.clone(),
                    wrote: false,
                })
            }),
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let task = Arc::new(Task::default());
        driver.set_waker(&Waker::from(task.clone()));
        let child = Slots::new(1).insert(()).unwrap();
        let id = child.id();
        let _ = driver.deliver(MuxEvent::Opened(child, (), 8)).unwrap();
        assert!(driver.deliver(MuxEvent::Credit(id, 8)).unwrap().moved());
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        driver.run().unwrap();
        assert!(driver.take_command().is_none());
        assert!(!driver.woken());
        // Another thread changes the child's state and wakes it.
        go.store(true, Ordering::Release);
        let waker = kept.lock().clone().expect("the child kept its waker");
        std::thread::spawn(move || waker.wake()).join().unwrap();
        assert_eq!(task.0.load(Ordering::Acquire), 1);
        assert!(driver.woken());
        driver.run().unwrap();
        assert!(!driver.woken());
        assert!(matches!(
            driver.take_command().unwrap().into_op(),
            super::super::MuxOp::Child(found, StreamCommand::Write(_)) if found == id
        ));
    }

    /// A child that asks its budget for `want` bytes on each advance until
    /// it gets them (rule 9), and keeps the waker of each call.
    struct Hungry {
        want: usize,
        held: Option<Charge>,
        tries: usize,
        wakers: Vec<Waker>,
    }

    impl Layer for Hungry {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
            self.wakers.push(env.waker());
            if self.held.is_some() {
                return Ok(false);
            }
            self.tries += 1;
            self.held = env.budget().charge(self.want);
            Ok(self.held.is_some())
        }
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            _: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            c: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match c {}
        }
        fn take_command(&mut self, _: &mut Env<'_, ()>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    /// A child charges a budget of its own, not the stack's, which the
    /// runner above waits on. When that budget refuses it, the router waits
    /// on it for the child, with the one waker the child has: the release
    /// that leaves room wakes the runner and gets the child visited, with
    /// no other event.
    #[test]
    fn a_child_refused_by_its_own_budget_is_visited_when_that_budget_frees() {
        let sandbox = Budget::new(4096);
        let child_budget = sandbox.clone();
        let want = 1024;
        let mut driver = Driver::new(
            Children::<Hungry, Top, ()>::new(1, 8, move |_, (), _| {
                Some(Hungry {
                    want,
                    held: None,
                    tries: 0,
                    wakers: Vec::new(),
                })
            })
            .budgets(move |_, _, _| child_budget.clone()),
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        let task = Arc::new(Task::default());
        driver.set_waker(&Waker::from(task.clone()));
        let woken = || task.0.load(Ordering::Acquire);
        let child = Slots::new(1).insert(()).unwrap();
        let id = child.id();
        let _ = driver.deliver(MuxEvent::Opened(child, (), 8)).unwrap();
        // The sandbox has less room than the child wants.
        let hog = sandbox
            .charge(sandbox.limit() - sandbox.used() - want + 1)
            .unwrap();
        // Rounds as a runner makes them, until nothing moves.
        for _ in 0..4 {
            let since = driver.refusals();
            driver.run().unwrap();
            while driver.take_command().is_some() {}
            driver.wake_when_freed(since);
        }
        let tries = driver.layer().child(id).unwrap().tries;
        assert!(tries > 0 && driver.layer().child(id).unwrap().held.is_none());
        driver.run().unwrap();
        assert_eq!(
            driver.layer().child(id).unwrap().tries,
            tries,
            "a refused child waits"
        );
        assert_eq!(woken(), 0, "no memory freed yet");

        // Memory frees on the child's budget, not the stack's.
        drop(hog);
        assert_eq!(woken(), 1, "the release wakes the runner once");
        assert!(driver.woken());
        driver.run().unwrap();
        let child = driver.layer().child(id).unwrap();
        assert!(child.tries > tries, "the child is visited again");
        assert!(child.held.is_some(), "and gets its memory");
        let first = &child.wakers[0];
        assert!(
            child.wakers.iter().all(|w| w.will_wake(first)),
            "every call gets the child's one waker"
        );
    }

    /// The router waits for memory exactly while one of its children does
    /// on that child's own view: from the refusal, through calls that do
    /// not try again, until a visit finds room, or until the child that
    /// waits is gone. Its siblings' state makes no difference.
    #[test]
    fn the_router_waits_for_memory_while_a_child_does() {
        let sandbox = Budget::new(4096);
        let child_budget = sandbox.clone();
        let want = 1024;
        let wants = Arc::new(std::sync::Mutex::new(vec![want, 0, want]));
        let mut driver = Driver::new(
            Children::<Hungry, Top, ()>::new(3, 8, move |_, (), _| {
                Some(Hungry {
                    want: wants.lock().unwrap().remove(0),
                    held: None,
                    tries: 0,
                    wakers: Vec::new(),
                })
            })
            .budgets(move |_, _, _| child_budget.clone()),
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        let mut slots = Slots::new(3);
        let mut open = |driver: &mut Driver<Children<Hungry, Top, ()>>| {
            let child = slots.insert(()).unwrap();
            let id = child.id();
            let _ = driver.deliver(MuxEvent::Opened(child, (), 8)).unwrap();
            id
        };
        let (a, b) = (open(&mut driver), open(&mut driver));
        assert!(!driver.layer().waits_for_memory(), "nothing refused yet");
        let hog = sandbox
            .charge(sandbox.limit() - sandbox.used() - want + 1)
            .unwrap();
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        assert!(driver.layer().child(a).unwrap().held.is_none());
        assert!(
            driver.layer().child(b).unwrap().held.is_some(),
            "b wants nothing"
        );
        assert!(driver.layer().waits_for_memory(), "a waits");
        // Credit for the waiting child is a call that tries nothing again
        // until its visit, which still finds no room.
        let _ = driver.deliver(MuxEvent::Credit(a, 1)).unwrap();
        assert!(driver.layer().waits_for_memory());
        driver.run().unwrap();
        assert!(driver.layer().waits_for_memory(), "still no room");
        // b closing changes nothing; a closing ends the wait.
        let _ = driver.deliver(MuxEvent::Closed(b)).unwrap();
        assert!(driver.layer().waits_for_memory());
        let _ = driver.deliver(MuxEvent::Closed(a)).unwrap();
        assert!(
            !driver.layer().waits_for_memory(),
            "the waiting child is gone"
        );
        // A third child waits, and a visit with room ends its wait. What
        // the closed children held went back, so the room is taken again.
        let c = open(&mut driver);
        let more = sandbox
            .charge(sandbox.limit() - sandbox.used() - want + 1)
            .unwrap();
        driver.run().unwrap();
        assert!(driver.layer().waits_for_memory(), "c waits");
        drop((hog, more));
        driver.run().unwrap();
        assert!(driver.layer().child(c).unwrap().held.is_some());
        assert!(!driver.layer().waits_for_memory(), "c has its memory");
    }

    /// A command whose payload the child's budget cannot pay for now stays
    /// in the child's outbox, and the child stays open: nothing is closed
    /// or reported. The release that makes room wakes the task with no
    /// other event, and the command goes down once, unchanged.
    #[test]
    fn a_command_its_budget_refuses_waits_in_the_outbox_and_goes_once_memory_frees() {
        let sandbox = Budget::new(4096);
        let child_budget = sandbox.clone();
        let payload = b"waits for memory";
        let mut driver = Driver::new(
            Children::<Reader, Top, ()>::new(1, 8, move |_, (), _| {
                Some(Reader {
                    writes: [StreamCommand::Write(Chunk::unpaid(payload.to_vec()))].into(),
                    ..Reader::default()
                })
            })
            .budgets(move |_, _, _| child_budget.clone()),
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        let task = Arc::new(Task::default());
        driver.set_waker(&Waker::from(task.clone()));
        let woken = || task.0.load(Ordering::Acquire);
        let child = Slots::new(1).insert(()).unwrap();
        let id = child.id();
        let _ = driver.deliver(MuxEvent::Opened(child, (), 64)).unwrap();
        assert!(driver.deliver(MuxEvent::Credit(id, 64)).unwrap().moved());
        let hog = sandbox.charge(sandbox.limit() - sandbox.used()).unwrap();
        /// Runs the stack and takes what it sends down: the bytes written.
        fn down(driver: &mut Driver<Children<Reader, Top, ()>>, written: &mut Vec<u8>) {
            for _ in 0..4 {
                driver.run().unwrap();
                while let Some(command) = driver.take_command() {
                    match command.into_op() {
                        super::super::MuxOp::Child(_, StreamCommand::Write(chunk)) => {
                            written.extend_from_slice(&chunk)
                        }
                        super::super::MuxOp::Close(..) => panic!("the child was closed"),
                        _ => {}
                    }
                }
            }
        }
        let mut written = Vec::new();
        down(&mut driver, &mut written);
        let layer = driver.layer();
        let key = layer.key(id).expect("the child stays open");
        assert!(layer.places.kids[key].outbox.is_some(), "the command waits");
        assert!(written.is_empty(), "nothing unpaid goes down");
        assert!(
            driver
                .observations()
                .drain()
                .all(|report| !matches!(report, ChildReport::Refused(..))),
            "nothing is refused"
        );
        assert_eq!(woken(), 0, "no memory freed yet");
        drop(hog);
        assert!(woken() > 0, "the release wakes the task");
        assert!(driver.woken());
        down(&mut driver, &mut written);
        assert_eq!(written, payload, "the command goes down once, unchanged");
        let layer = driver.layer();
        assert!(layer.places.kids[layer.key(id).unwrap()].outbox.is_none());
    }

    #[test]
    fn children_woken_together_are_visited_in_id_order() {
        let mut driver = driver(|_, _, _| Reader::default());
        let mut slots = Slots::new(3);
        let held: Vec<_> = (0..3).map(|_| holding(&mut driver, &mut slots)).collect();
        let ids: Vec<_> = held.iter().map(|(id, _)| *id).collect();
        // Released last child first, so their wakes come in reverse order.
        for (_, chunk) in held.into_iter().rev() {
            drop(chunk);
        }
        driver.run().unwrap();
        let mut credited = Vec::new();
        while let Some(command) = driver.take_command() {
            if let super::super::MuxOp::Credit(id, 1) = command.into_op() {
                credited.push(id);
            }
        }
        assert_eq!(credited, ids);
    }

    #[test]
    fn a_closed_child_leaves_the_wake_queue_and_its_wakes_reach_no_later_child() {
        let mut driver = driver(|_, _, _| Reader::default());
        let mut slots = Slots::new(3);
        // Woken, then closed before it was collected.
        let (queued, chunk) = holding(&mut driver, &mut slots);
        drop(chunk);
        assert!(!driver.layer().places.woken.keys.lock().is_empty());
        let _ = driver.deliver(MuxEvent::Closed(queued)).unwrap();
        assert!(driver.layer().places.woken.keys.lock().is_empty());
        // Closed, then woken: a later child has its place by then.
        let (closed, chunk) = holding(&mut driver, &mut slots);
        let place = driver.layer().key(closed);
        let _ = driver.deliver(MuxEvent::Closed(closed)).unwrap();
        let (later, later_chunk) = holding(&mut driver, &mut slots);
        assert_eq!(driver.layer().key(later), place);
        drop(chunk);
        assert!(driver.layer().places.woken.keys.lock().is_empty());
        driver.run().unwrap();
        assert!(driver.take_command().is_none());
        // The later child's own wake still reaches it.
        drop(later_chunk);
        driver.run().unwrap();
        assert!(matches!(driver.take_command().unwrap().into_op(),
            super::super::MuxOp::Credit(found, 1) if found == later));
    }

    #[test]
    fn a_factory_refusal_returns_the_child_and_its_storage() {
        let budget = Budget::new(4096);
        let held = budget.clone();
        let children =
            Children::<Reader, Top, bool>::new(2, 8, |_, allowed, _| allowed.then(Reader::default))
                .budgets(move |_, _, _| held.clone());
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let mut slots = Slots::new(2);
        let refused = slots.insert(()).unwrap();
        let id = refused.id();
        let _ = driver.deliver(MuxEvent::Opened(refused, false, 8)).unwrap();
        assert!(driver.layer().child(id).is_none());
        assert_eq!(budget.used(), 0);
        assert!(matches!(driver.take_command().unwrap().into_op(),
            super::super::MuxOp::Close(found, Closing::Prohibited) if found == id));
        let accepted = slots.insert(()).unwrap();
        let id = accepted.id();
        let _ = driver.deliver(MuxEvent::Opened(accepted, true, 8)).unwrap();
        assert!(driver.layer().child(id).is_some());
    }

    /// Opens [`FLOOR`] children, so the places are full, lets `squeeze`
    /// hold what it wants of the stack's budget and the children's, and
    /// opens one more, which the application allows or not. Returns the
    /// cause its close carried and the cause its report gave.
    fn refused_opening(
        limit: usize,
        allowed: bool,
        squeeze: impl FnOnce(&Budget, &Budget) -> Option<Charge>,
    ) -> (Closing, Closing) {
        let kids = Budget::new(100_000);
        let held = kids.clone();
        let children = Children::<Reader, Top, bool>::new(limit, 8, |_, allowed, _| {
            allowed.then(Reader::default)
        })
        .budgets(move |_, _, _| held.clone());
        let stack = Budget::new(100_000);
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(97))),
            stack.clone(),
            Instant::ZERO,
        );
        let mut slots = Slots::new(FLOOR + 1);
        for _ in 0..FLOOR {
            let child = slots.insert(()).unwrap();
            let _ = driver.deliver(MuxEvent::Opened(child, true, 8)).unwrap();
        }
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        assert_eq!(driver.layer().ids().count(), FLOOR);
        let _held = squeeze(&stack, &kids);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        assert!(matches!(
            driver.deliver(MuxEvent::Opened(child, allowed, 8)),
            Ok(Admit::Taken)
        ));
        assert!(
            driver.layer().child(id).is_none(),
            "the opening was refused"
        );
        let closed = std::iter::from_fn(|| driver.take_command())
            .find_map(|command| match command.into_op() {
                super::super::MuxOp::Close(found, why) if found == id => Some(why),
                _ => None,
            })
            .expect("the refused child is closed");
        let reported = driver
            .observations()
            .drain()
            .find_map(|report| match report {
                ChildReport::Refused(found, why) if found == id => Some(why),
                _ => None,
            })
            .expect("the refused child is reported");
        (closed, reported)
    }

    /// Each opening Children refuses reports the cause its close carries:
    /// one past the limit on children, or one the application says no to,
    /// is prohibited; one whose window or place the budget cannot hold now
    /// is refused for want of memory.
    #[test]
    fn a_refused_opening_reports_the_cause_its_close_carries() {
        let fill = |budget: &Budget| budget.charge(budget.limit() - budget.used());
        let cases = [
            (
                "count",
                refused_opening(FLOOR, true, |_, _| None),
                Closing::Prohibited,
            ),
            (
                "factory",
                refused_opening(8, false, |_, _| None),
                Closing::Prohibited,
            ),
            (
                "window",
                refused_opening(8, true, |_, kids| fill(kids)),
                Closing::ResourceShortage,
            ),
            (
                "places",
                refused_opening(8, true, |stack, _| fill(stack)),
                Closing::ResourceShortage,
            ),
        ];
        for (case, (closed, reported), cause) in cases {
            assert_eq!(
                closed, reported,
                "{case}: the report gives the close's cause"
            );
            assert_eq!(closed, cause, "{case}");
        }
    }

    #[test]
    fn empty_data_is_bounded_and_child_work_rotates_and_cancels() {
        let mut driver = driver(|_, _, _| Reader {
            waiting: true,
            work: true,
            ..Reader::default()
        });
        let mut slots = Slots::new(2);
        let first = slots.insert(()).unwrap();
        let a = first.id();
        let second = slots.insert(()).unwrap();
        let b = second.id();
        let _ = driver.deliver(MuxEvent::Opened(first, "a", 8)).unwrap();
        let _ = driver.deliver(MuxEvent::Opened(second, "b", 8)).unwrap();
        for _ in 0..QUEUE {
            assert!(
                driver
                    .deliver(MuxEvent::Child(
                        a,
                        StreamEvent::Data(Chunk::unpaid(Bytes::new()))
                    ))
                    .unwrap()
                    .moved()
            );
        }
        // Empty data costs no credit, but holds one of the bounded places.
        assert_eq!(driver.layer().places.kids[0].inbox.len(), QUEUE);
        let work = driver.layer_mut().take_work().unwrap();
        let first = work.id();
        let second = driver.layer_mut().take_work().unwrap().id();
        assert_ne!(first, second);
        assert_eq!([first, second], [a, b]);
        assert!(!work.cancelled());
        let _ = driver
            .deliver(MuxEvent::Child(a, StreamEvent::Reset))
            .unwrap();
        assert!(work.cancelled());
        assert_eq!(driver.layer_mut().take_work().unwrap().id(), b);
    }
    #[test]
    fn refusing_a_full_inbox_keeps_siblings_and_cancels_its_work() {
        let mut driver = driver(|_, _, _| Reader {
            waiting: true,
            work: true,
            ..Reader::default()
        });
        let mut slots = Slots::new(2);
        let first = slots.insert(()).unwrap();
        let a = first.id();
        let second = slots.insert(()).unwrap();
        let b = second.id();
        assert!(
            driver
                .deliver(MuxEvent::Opened(first, "a", 8))
                .unwrap()
                .moved()
        );
        assert!(
            driver
                .deliver(MuxEvent::Opened(second, "b", 8))
                .unwrap()
                .moved()
        );
        let work = driver.layer_mut().take_work().unwrap();
        let owner = work.id();
        assert_eq!(owner, a);
        for _ in 0..=QUEUE {
            assert!(
                driver
                    .deliver(MuxEvent::Child(
                        a,
                        StreamEvent::Data(Chunk::unpaid(Vec::new()))
                    ))
                    .unwrap()
                    .moved()
            );
        }
        assert!(work.cancelled());
        assert_eq!(driver.layer_mut().places.kids.len(), 1);
        assert_eq!(driver.layer_mut().take_work().unwrap().id(), b);
        assert!(
            driver
                .deliver(MuxEvent::Child(b, StreamEvent::Written(9)))
                .unwrap()
                .moved()
        );
        driver.run().unwrap();
        assert_eq!(driver.layer().child(b).unwrap().completions, 9);
    }

    /// A child that takes every event, or, with `refuse`, never takes one.
    struct Probe {
        refuse: bool,
        taken: usize,
    }

    impl Layer for Probe {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            if self.refuse {
                return Ok(Admit::Blocked(event));
            }
            self.taken += 1;
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            c: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match c {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    #[test]
    fn a_child_that_refuses_everything_holds_up_neither_siblings_nor_control() {
        use crate::stdlib::layer::{MessageEvent, Messages, MuxOp};
        let children: Children<Probe, Messages<u8>, bool> =
            Children::new(3, 8, |_, refuse, _| Some(Probe { refuse, taken: 0 }));
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(97))),
            Budget::new(1 << 20),
            Instant::ZERO,
        );
        let mut slots = Slots::new(3);
        let mut ids = Vec::new();
        for refuse in [true, true, false] {
            let child = slots.insert(()).unwrap();
            ids.push(child.id());
            assert!(
                driver
                    .deliver(MuxEvent::Opened(child, refuse, 8))
                    .unwrap()
                    .moved()
            );
        }
        let [stuck, stuck_urgent, ready] = ids[..] else {
            unreachable!()
        };
        // The driver never runs in between: only the visits Children makes
        // when a place is full move anything.
        let rounds = 4 * QUEUE;
        for round in 0..rounds {
            for event in [
                MuxEvent::Child(stuck, StreamEvent::Data(Chunk::unpaid(Bytes::new()))),
                MuxEvent::Child(stuck_urgent, StreamEvent::Written(1)),
                MuxEvent::Child(ready, StreamEvent::Data(Chunk::unpaid(Bytes::new()))),
                MuxEvent::Child(ready, StreamEvent::Written(1)),
                MuxEvent::Control(MessageEvent::Message(round as u8)),
            ] {
                assert!(matches!(driver.deliver(event), Ok(Admit::Taken)));
            }
            assert!(matches!(
                driver.layer_mut().take_event(),
                Some(MessageEvent::Message(n)) if n == round as u8
            ));
        }
        driver.run().unwrap();
        assert!(driver.layer().child(stuck).is_none());
        assert!(driver.layer().child(stuck_urgent).is_none());
        assert_eq!(driver.layer().child(ready).unwrap().taken, 2 * rounds);
        let mut closed = Vec::new();
        while let Some(command) = driver.take_command() {
            if let MuxOp::Close(id, why) = command.into_op() {
                assert_eq!(why, Closing::Failed, "an overloaded child failed");
                closed.push(id);
            }
        }
        closed.sort();
        assert_eq!(closed, [stuck, stuck_urgent]);
        let refused: Vec<_> = driver
            .observations()
            .drain()
            .filter_map(|report| match report {
                ChildReport::Refused(id, why) => {
                    assert_eq!(why, Closing::Failed);
                    Some(id)
                }
                _ => None,
            })
            .collect();
        assert!(refused.contains(&stuck) && refused.contains(&stuck_urgent));
        assert!(!refused.contains(&ready));
    }

    #[test]
    fn continuously_ready_children_rotate_across_bounded_sweeps() {
        let children: Children<Reader, Top> = Children::new(70, 8, |_, (), _| {
            Some(Reader {
                productive: true,
                ..Reader::default()
            })
        });
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(94))),
            Budget::new(16 << 20),
            Instant::ZERO,
        );
        let mut slots = Slots::new(70);
        for _ in 0..70 {
            let child = slots.insert(()).unwrap();
            let id = child.id();
            let _ = driver.deliver(MuxEvent::Opened(child, (), 1)).unwrap();
            let _ = driver.deliver(MuxEvent::Credit(id, 1000)).unwrap();
        }
        let mut sent = std::collections::BTreeSet::new();
        for _ in 0..70 {
            driver.run().unwrap();
            while let Some(command) = driver.take_command() {
                if let super::super::MuxOp::Child(id, StreamCommand::Write(_)) = command.into_op() {
                    sent.insert(id);
                }
            }
        }
        assert_eq!(
            sent.len(),
            70,
            "every productive child gets output capacity"
        );
    }

    /// A child that arms its timer at each of `times` in turn and notes
    /// when each one fired.
    struct Alarm {
        times: VecDeque<Instant>,
        fired: Arc<std::sync::Mutex<Vec<(usize, Instant)>>>,
        name: usize,
    }

    impl Layer for Alarm {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            _: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            c: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match c {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn deadline(&self) -> Option<(Instant, ())> {
            self.times.front().map(|at| (*at, ()))
        }
        fn on_timer(&mut self, env: &mut Env<'_, ()>, (): ()) -> Result<bool, Infallible> {
            let at = self.times.pop_front().expect("an armed timer");
            assert!(env.now() >= at, "a timer fired early");
            self.fired.lock().unwrap().push((self.name, at));
            Ok(true)
        }
    }

    #[test]
    fn child_timers_fire_in_time_order_as_children_rearm_and_close() {
        let fired = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ms = |n: u64| Instant::ZERO + std::time::Duration::from_millis(n);
        // Interleaved deadlines, some shared, so the heap moves entries both
        // ways as each child arms its next one.
        let plans: Vec<Vec<u64>> = vec![
            vec![5, 40, 41],
            vec![3, 3, 90],
            vec![7, 20, 60],
            vec![1, 50],
            vec![9, 10, 11, 12],
            vec![30],
        ];
        let made = plans.clone();
        let record = fired.clone();
        let children: Children<Alarm, Top, usize> =
            Children::new(8, 8, move |_, name: usize, _| {
                Some(Alarm {
                    times: made[name].iter().map(|n: &u64| ms(*n)).collect(),
                    fired: record.clone(),
                    name,
                })
            });
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(95))),
            Budget::new(1 << 20),
            Instant::ZERO,
        );
        let mut slots = Slots::new(8);
        let mut ids = Vec::new();
        for name in 0..plans.len() {
            let child = slots.insert(()).unwrap();
            ids.push(child.id());
            let _ = driver.deliver(MuxEvent::Opened(child, name, 8)).unwrap();
        }
        // Children 2 and 5 close at 25 ms, with timers still armed.
        for now in 0..=100 {
            driver.set_now(ms(now));
            driver.run().unwrap();
            if now == 25 {
                for gone in [ids[2], ids[5]] {
                    let _ = driver.deliver(MuxEvent::Closed(gone)).unwrap();
                }
            }
        }
        assert_eq!(driver.deadline(), None);
        let fired = fired.lock().unwrap();
        // Every timer of an open child fired once, at its time, in order.
        assert!(fired.windows(2).all(|w| w[0].1 <= w[1].1));
        for (name, plan) in plans.iter().enumerate() {
            let times: Vec<_> = fired
                .iter()
                .filter(|(k, _)| *k == name)
                .map(|(_, at)| *at)
                .collect();
            let due: Vec<_> = plan
                .iter()
                .map(|n| ms(*n))
                .filter(|at| ![2, 5].contains(&name) || *at <= ms(25))
                .collect();
            assert_eq!(times, due, "child {name}");
        }
    }

    #[test]
    fn equally_due_child_timers_rotate_even_when_they_rearm_immediately() {
        let mut driver = driver(|_, _, _| Reader {
            timer: true,
            ..Reader::default()
        });
        let mut slots = Slots::new(3);
        let mut ids = Vec::new();
        for _ in 0..3 {
            let child = slots.insert(()).unwrap();
            ids.push(child.id());
            let _ = driver.deliver(MuxEvent::Opened(child, "timer", 8)).unwrap();
        }
        driver.run().unwrap();
        let counts: Vec<_> = ids
            .into_iter()
            .map(|id| driver.layer().child(id).unwrap().fired)
            .collect();
        assert!(counts.iter().all(|n| *n > 0));
        assert!(counts.iter().max().unwrap() - counts.iter().min().unwrap() <= 1);
        assert!(driver.exhausted());
    }

    #[test]
    fn a_child_the_budget_cannot_hold_is_refused_and_its_siblings_go_on() {
        let made = Arc::new(AtomicU64::new(0));
        let count = made.clone();
        let children: Children<Reader, Top, ()> = Children::new(8, 8, move |_, (), _| {
            count.fetch_add(1, Ordering::Relaxed);
            Some(Reader::default())
        });
        let budget = Budget::new(100_000);
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(96))),
            budget.clone(),
            Instant::ZERO,
        );
        driver.run().unwrap();
        let idle = budget.used();
        let mut slots = Slots::new(8);
        let first = slots.insert(()).unwrap();
        let a = first.id();
        let _ = driver.deliver(MuxEvent::Opened(first, (), 8)).unwrap();
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        // Nothing is left for a second child's places.
        let other = budget.charge(budget.limit() - budget.used()).unwrap();
        let second = slots.insert(()).unwrap();
        let b = second.id();
        assert!(matches!(
            driver.deliver(MuxEvent::Opened(second, (), 8)),
            Ok(Admit::Taken)
        ));
        assert!(driver.layer().child(b).is_none());
        assert!(
            matches!(driver.take_command().unwrap().into_op(), crate::stdlib::layer::MuxOp::Close(id, Closing::ResourceShortage) if id == b)
        );
        assert_eq!(made.load(Ordering::Relaxed), 1);
        drop(other);
        // The first child still takes its events.
        let _ = driver
            .deliver(MuxEvent::Child(
                a,
                StreamEvent::Data(Chunk::unpaid(Bytes::from_static(b"ab"))),
            ))
            .unwrap();
        driver.run().unwrap();
        assert_eq!(
            driver.layer().child(a).unwrap().held.as_deref(),
            Some(&b"ab"[..])
        );
        // With no children, the router holds what it held idle.
        let _ = driver.deliver(MuxEvent::Closed(a)).unwrap();
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        assert_eq!(budget.used(), idle);
    }

    /// Full places grow every table together, and when the budget has no
    /// room to double them, by the places it has room for: a child that
    /// fits is not refused for places it does not need. What the places
    /// are charged is what every table holds, and with no children left
    /// they shrink back together.
    #[test]
    fn full_places_grow_every_table_by_the_places_that_fit() {
        let children: Children<Reader, Top, ()> =
            Children::new(8, 8, |_, (), _| Some(Reader::default()));
        let budget = Budget::new(100_000);
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(96))),
            budget.clone(),
            Instant::ZERO,
        );
        driver.run().unwrap();
        let idle = budget.used();
        let place = Places::<Reader, Top>::place_bytes();
        let held = |driver: &Driver<Children<Reader, Top, ()>>| {
            let places = &driver.layer().places;
            let count = places.count;
            assert!(places.kids.capacity() >= count);
            assert!(places.order.capacity() >= count);
            assert!(places.timers.capacity() >= count);
            assert!(places.woken.keys.lock().capacity() >= count);
            assert!(places.down.capacity() >= QUEUE + count);
            assert_eq!(
                places.charge.as_ref().unwrap().bytes(),
                Places::<Reader, Top>::queue_bytes() + count * place,
                "charged what the tables hold"
            );
            count
        };
        let mut slots = Slots::new(8);
        let mut open = Vec::new();
        for _ in 0..FLOOR {
            let child = slots.insert(()).unwrap();
            open.push(child.id());
            let _ = driver.deliver(MuxEvent::Opened(child, (), 8)).unwrap();
        }
        assert_eq!(held(&driver), FLOOR);
        // Room for one more place and the child's window, not for twice
        // the places.
        let window = <StreamEvent as Credited>::receive_bytes(8).unwrap();
        let other = budget
            .charge(budget.limit() - budget.used() - place - window)
            .unwrap();
        let child = slots.insert(()).unwrap();
        let id = child.id();
        let _ = driver.deliver(MuxEvent::Opened(child, (), 8)).unwrap();
        assert!(
            driver.layer().child(id).is_some(),
            "the child that fits opens"
        );
        assert_eq!(held(&driver), FLOOR + 1);
        drop(other);
        open.push(id);
        for id in open {
            let _ = driver.deliver(MuxEvent::Closed(id)).unwrap();
        }
        driver.run().unwrap();
        while driver.take_command().is_some() {}
        driver.run().unwrap();
        assert_eq!(held(&driver), FLOOR);
        assert_eq!(budget.used(), idle);
    }

    /// The first credit lends the mux the child's receive window, and
    /// bytes the mux makes in it are taken in with nothing charged or
    /// given back. The window stays the router's: once the child closes,
    /// what the mux kept of it no longer reaches it.
    #[test]
    fn the_first_credit_lends_the_window_and_bytes_made_in_it_move_no_charge() {
        let budget = Budget::new(100_000);
        let child_budget = budget.clone();
        let mut driver = Driver::new(
            Children::<Reader, Top, ()>::new(1, 8, |_, (), _| Some(Reader::default()))
                .budgets(move |_, _, _| child_budget.clone()),
            Arc::new(SeededEntropy::new(Seed::from_u64(96))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        let child = Slots::new(1).insert(()).unwrap();
        let id = child.id();
        let _ = driver.deliver(MuxEvent::Opened(child, (), 8)).unwrap();
        driver.run().unwrap();
        let mut lent = None;
        while let Some(command) = driver.take_command() {
            match command.into_op() {
                super::super::MuxOp::Window(found, units, window) if found == id => {
                    lent = Some((units, window));
                }
                super::super::MuxOp::Credit(found, _) if found == id => {
                    panic!("the first credit lends the window");
                }
                _ => {}
            }
        }
        let (units, kept) = lent.expect("the first credit went to the mux");
        assert_eq!(units, 8);
        let window = kept.upgrade().expect("the child keeps its window");
        assert_eq!(
            window.bytes(),
            <StreamEvent as Credited>::receive_bytes(8).unwrap()
        );

        let used = budget.used();
        let bytes = Chunk::in_window(vec![1; 8], window.clone());
        drop(window);
        let _ = driver
            .deliver(MuxEvent::Child(id, StreamEvent::Data(bytes)))
            .unwrap();
        driver.run().unwrap();
        let layer = driver.layer();
        let inbox = layer.places.kids[layer.key(id).unwrap()].inbox.charged();
        assert_eq!(
            budget.used(),
            used + inbox,
            "the bytes charged or gave back nothing; the inbox paid for its places"
        );
        assert_eq!(layer.child(id).unwrap().held.as_deref(), Some(&[1; 8][..]));

        let _ = driver.deliver(MuxEvent::Closed(id)).unwrap();
        assert!(
            kept.upgrade().is_none(),
            "the window went back with the child"
        );
    }

    /// A child that puts the bytes it takes where the test can keep them
    /// after the child has closed.
    struct Keeper(Arc<std::sync::Mutex<Vec<Chunk>>>);

    impl Layer for Keeper {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = ();
        type Timer = ();
        type Work = ();
        type Done = ();
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, ()>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            if let StreamEvent::Data(chunk) = event {
                self.0.lock().unwrap().push(chunk);
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, ()>,
            c: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match c {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    /// What a closed child left that something still holds never serves
    /// the next child: bytes it took, kept past its close with their
    /// credit lease and their window, give that credit back to no one,
    /// and the next child, opened in the same place, gets credit only
    /// for itself. Once nothing holds them, children that come and go
    /// share nothing either: each gets exactly its own window's credit.
    #[test]
    fn a_closed_childs_parts_still_held_never_reach_the_next_child() {
        let kept = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stash = kept.clone();
        let mut driver = Driver::new(
            Children::<Keeper, Top, ()>::new(1, 8, move |_, (), _| Some(Keeper(stash.clone()))),
            Arc::new(SeededEntropy::new(Seed::from_u64(98))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let mut slots = Slots::new(1);
        // Every credit the router gives child `id`.
        let credit = |driver: &mut Driver<Children<Keeper, Top, ()>>, id: ChildId| {
            std::iter::from_fn(|| driver.take_command())
                .map(|command| match command.into_op() {
                    super::super::MuxOp::Window(found, units, _)
                    | super::super::MuxOp::Credit(found, units) => {
                        assert_eq!(found, id, "credit for a child that is open");
                        units
                    }
                    _ => 0,
                })
                .sum::<u64>()
        };
        let open = |driver: &mut Driver<Children<Keeper, Top, ()>>, slots: &mut Slots<()>| {
            let child = slots.insert(()).unwrap();
            let id = child.id();
            let _ = driver.deliver(MuxEvent::Opened(child, (), 8)).unwrap();
            driver.run().unwrap();
            (id, credit(driver, id))
        };
        let close =
            |driver: &mut Driver<Children<Keeper, Top, ()>>, slots: &mut Slots<()>, id: ChildId| {
                let _ = driver.deliver(MuxEvent::Closed(id)).unwrap();
                slots.remove(id);
                driver.run().unwrap();
                while driver.take_command().is_some() {}
            };
        let (first, granted) = open(&mut driver, &mut slots);
        assert_eq!(granted, 8);
        let _ = driver
            .deliver(MuxEvent::Child(
                first,
                StreamEvent::Data(Chunk::unpaid(vec![1; 4])),
            ))
            .unwrap();
        driver.run().unwrap();
        assert_eq!(kept.lock().unwrap().len(), 1, "the child took the bytes");
        close(&mut driver, &mut slots, first);
        let (second, granted) = open(&mut driver, &mut slots);
        assert_eq!(granted, 8, "the next child's own window");
        // The first child's bytes go now: their credit is the first
        // child's, which is closed.
        kept.lock().unwrap().clear();
        driver.run().unwrap();
        assert_eq!(
            credit(&mut driver, second),
            0,
            "no credit the child did not free"
        );
        // With nothing held, each child that comes and goes gets its own
        // window's credit and no more.
        let mut open_now = second;
        for _ in 0..4 {
            close(&mut driver, &mut slots, open_now);
            let (next, granted) = open(&mut driver, &mut slots);
            assert_eq!(granted, 8);
            driver.run().unwrap();
            assert_eq!(credit(&mut driver, next), 0);
            open_now = next;
        }
    }

    #[test]
    fn a_refused_reservation_never_constructs_a_child() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = called.clone();
        let children: Children<Reader, Top, ()> = Children::new(1, 8, move |_, (), _| {
            flag.store(true, Ordering::Relaxed);
            Some(Reader::default())
        });
        let budget = Budget::new(100_000);
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(92))),
            budget.clone(),
            Instant::ZERO,
        );
        let hog = budget.charge(budget.limit()).unwrap();
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        // With no room for the router's queues, the opening waits for
        // memory: it goes back to the mux, and the connection goes on.
        let Ok(Admit::Blocked(opening)) = driver.deliver(MuxEvent::Opened(child, (), 8)) else {
            panic!("an opening the router cannot pay for goes back to the mux")
        };
        assert!(matches!(&opening, MuxEvent::Opened(child, ..) if child.id() == id));
        assert!(!called.load(Ordering::Relaxed));
        assert!(driver.take_command().is_none(), "nothing is closed");
        drop(hog);
        assert_eq!(budget.used(), 0);
        assert!(matches!(driver.deliver(opening), Ok(Admit::Taken)));
        assert!(called.load(Ordering::Relaxed));
        assert!(driver.layer().child(id).is_some());
    }

    #[test]
    fn an_atomic_command_larger_than_the_declared_limit_closes_the_child() {
        use crate::stdlib::layer::{MessageCommand, MessageEvent, Messages, MuxOp};
        struct Atomic(bool);
        impl Layer for Atomic {
            type Lower = Messages<u8>;
            type Upper = Top;
            type Report = ();
            type Timer = ();
            type Work = Infallible;
            type Done = Infallible;
            type Error = Infallible;
            fn on_event(
                &mut self,
                _: &mut Env<'_, ()>,
                _: MessageEvent<u8>,
            ) -> Result<Admit<MessageEvent<u8>>, Infallible> {
                Ok(Admit::Taken)
            }
            fn on_command(
                &mut self,
                _: &mut Env<'_, ()>,
                c: Infallible,
            ) -> Result<Admit<Infallible>, Infallible> {
                match c {}
            }
            fn take_command(
                &mut self,
                _: &mut Env<'_, Self::Report>,
            ) -> Option<MessageCommand<u8>> {
                std::mem::take(&mut self.0).then_some(MessageCommand::Send(7))
            }
            fn take_event(&mut self) -> Option<Infallible> {
                None
            }
        }
        let children: Children<Atomic, Top> = Children::new(1, 1, |_, (), _| Some(Atomic(true)));
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(93))),
            Budget::new(100_000),
            Instant::ZERO,
        );
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        let id = child.id();
        let _ = driver.deliver(MuxEvent::Opened(child, (), 0)).unwrap();
        driver.run().unwrap();
        assert!(driver.layer().child(id).is_none());
        assert!(
            matches!(driver.take_command().unwrap().into_op(), MuxOp::Close(actual, Closing::Failed) if actual == id)
        );
    }
}

#[cfg(test)]
mod http_children {
    use super::*;
    use crate::stdlib::layer::{
        Chunk, Driver, MessageEvent, Messages, MuxOp, Slots, StreamCommand, StreamEvent, Worker,
    };
    use crate::stdlib::services::stack::Polling;
    use crate::stdlib::web::httpd::{Body, Exchange, Handler, Http1, Reply};
    use crate::{Seed, block_on, lab};
    use http::{Request, Response};
    use std::sync::atomic::AtomicBool;

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    struct Answer {
        name: &'static str,
        dropped: Arc<AtomicBool>,
    }
    impl Handler for Answer {
        fn call(&self, _: Request<Body>, _: &mut Exchange<'_>) -> Reply {
            let name = self.name;
            let dropped = self.dropped.clone();
            Reply::Later(Box::new(move |_| {
                Box::pin(async move {
                    if name == "reset" {
                        let _guard = Dropped(dropped);
                        std::future::pending::<()>().await;
                    }
                    Ok(Response::new(Body::from(name)))
                })
            }))
        }
    }

    #[test]
    fn async_http_children_cancel_without_blocking_siblings_or_control() {
        block_on(lab(Seed::from_u64(38), |fcx| async move {
            let dropped = Arc::new(AtomicBool::new(false));
            let flag = dropped.clone();
            let children: Children<Http1, Messages<u8>, &'static str> =
                Children::new(3, 4096, move |_, name, _| {
                    Some(Http1::new(Answer {
                        name,
                        dropped: flag.clone(),
                    }))
                });
            let mut driver = Driver::new(
                children,
                Arc::new(fcx.clone()),
                Budget::new(8 << 20),
                fcx.now(),
            );
            let mut worker = Polling::in_world(fcx.clone());
            let mut slots = Slots::new(3);
            let mut ids = Vec::new();
            for name in ["stalled", "reset", "ready"] {
                let child = slots.insert(()).unwrap();
                ids.push(child.id());
                let _ = driver.deliver(MuxEvent::Opened(child, name, 4096)).unwrap();
            }
            driver.run().unwrap();
            while driver.take_command().is_some() {}
            for id in &ids {
                let _ = driver
                    .deliver(MuxEvent::Child(
                        *id,
                        StreamEvent::Data(Chunk::unpaid(
                            b"GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n".to_vec(),
                        )),
                    ))
                    .unwrap();
            }
            let _ = driver.deliver(MuxEvent::Credit(ids[2], 4096)).unwrap();
            let mut response = Vec::new();
            for _ in 0..32 {
                driver.run().unwrap();
                worker.work(&mut driver).unwrap();
                while let Some(command) = driver.take_command() {
                    if let MuxOp::Child(id, StreamCommand::Write(bytes)) = command.into_op() {
                        assert_eq!(id, ids[2]);
                        response.extend_from_slice(&bytes);
                        let _ = driver
                            .deliver(MuxEvent::Child(
                                id,
                                StreamEvent::Written(bytes.len() as u64),
                            ))
                            .unwrap();
                    }
                }
            }
            let parsed =
                crate::stdlib::protocols::http1::Response::parse_for(&response, "GET").unwrap();
            assert_eq!(parsed.body, b"ready");
            assert!(!dropped.load(Ordering::Relaxed));
            let _ = driver.deliver(MuxEvent::Closed(ids[1])).unwrap();
            let _ = driver
                .deliver(MuxEvent::Control(MessageEvent::Message(23)))
                .unwrap();
            for _ in 0..8 {
                driver.run().unwrap();
                worker.work(&mut driver).unwrap();
            }
            assert!(dropped.load(Ordering::Relaxed));
            assert!(matches!(
                driver.layer_mut().take_event(),
                Some(MessageEvent::Message(23))
            ));
            assert!(driver.layer().child(ids[0]).is_some());
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }
}
