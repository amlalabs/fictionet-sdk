use super::carrier::CreditLease;
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::task::{Wake, Waker};

use fictionet::stdlib::layer::{
    Admit, Budget, Charge, ChargedDeque, Child, ChildId, CommandOf, Credited, Env, EventOf, Layer,
    Mux, MuxCommand, MuxEvent, OwnedWork, Port, Top, WorkOwner,
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
/// its bound, and the further places go once no child is left. A child
/// whose storage the budget cannot hold is refused
/// ([`ChildReport::Refused`]) and its siblings go on.
///
/// The mux never waits for a child. Credit bounds a child's bytes, but not
/// how many events it holds: many small pieces, completions and ends cost
/// nothing. Each child holds at most 64 events and one urgent event. When an
/// event finds its child's place full, the child is visited at once to
/// take what waits. A child that still takes nothing is overloaded: it alone
/// is refused and closed, its work cancelled, and the event is dropped with
/// it. So any child, however it behaves, holds up neither its siblings nor
/// the connection's own traffic below and above.
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
    /// The open children, each at a key that stays its own while it is open.
    kids: Slab<Kid<B>>,
    /// Their ids and keys, in id order.
    order: Vec<(ChildId, usize)>,
    /// Children to visit, linked through their own `links`.
    ready: List,
    /// Children whose layers may have work to hand over.
    work: List,
    /// The keys of children with a deadline, a binary heap with the first
    /// due at the top. Each child knows where it is.
    timers: Vec<usize>,
    /// How many deadlines have been armed, to order those due together.
    armed: u64,
    /// The children something outside a call reached ([`ChildWake`]).
    woken: Arc<Woken>,
    limit: usize,
    window: u64,
    down: VecDeque<MuxCommand<B::Lower, K>>,
    up: VecDeque<EventOf<K>>,
    // Reservations outlive every allocation they cover during destruction.
    storage: Option<Charge>,
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
    max_command: u64,
    /// Credit the mux may still use for this child's events.
    granted: u64,
    /// Credit of events the layer took, not yet granted again.
    owed: u64,
    /// Credit the mux granted for this child's commands.
    credit: u64,
    /// A command of the layer's that waits for credit.
    outbox: Option<CommandOf<B::Lower>>,
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

impl ChildWake {
    /// The child's [`Env::waker`]: it queues the child, then wakes
    /// `around`, what the child runs in. It changes nothing in the child's
    /// wake, so it stays good while the child is open.
    pub(crate) fn waker_in(self: &Arc<Self>, around: Waker) -> Waker {
        Waker::from(Arc::new(Within {
            child: self.clone(),
            around,
        }))
    }
}

/// A child's [`Env::waker`] ([`ChildWake::waker_in`]).
struct Within {
    child: Arc<ChildWake>,
    around: Waker,
}

impl Wake for Within {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.child.notify();
        self.around.wake_by_ref();
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
    /// A child exceeded admission limits or produced an impossible atomic
    /// command. It was closed at once.
    Refused(ChildId),
}

/// The mux sent a child more than the credit granted for it: a broken mux,
/// so the whole connection stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overrun {
    /// The mux exceeded granted carrier credit.
    Credit(ChildId),
    /// The connection cannot reserve routing storage.
    Budget,
}

impl core::fmt::Display for Overrun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Credit(_) => "the mux sent a child more than its credit",
            Self::Budget => "child routing exceeds the memory budget",
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
            kids: Slab::new(),
            order: Vec::new(),
            ready: List::new(List::READY),
            work: List::new(List::WORK),
            timers: Vec::new(),
            armed: 0,
            woken: Arc::new(Woken {
                any: AtomicBool::new(false),
                keys: Mutex::new(Vec::new()),
            }),
            storage: None,
            limit,
            window,
            down: VecDeque::new(),
            up: VecDeque::new(),
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

    /// The routing storage for `kids` child places: the places themselves,
    /// a vacant place's next key included, with their wake state, their
    /// places in the wake queue, their ids in order and their places in the
    /// deadline heap, the command queue with one closing place per child,
    /// and the control queue.
    fn routing_bytes(kids: usize) -> Option<usize> {
        let place = size_of::<Kid<B>>()
            + size_of::<usize>()
            // The wake state's shared allocation, with its two counts.
            + size_of::<ChildWake>()
            + 2 * size_of::<usize>()
            + size_of::<usize>()
            + size_of::<(ChildId, usize)>()
            + size_of::<usize>();
        kids.checked_mul(place)?.checked_add(
            (QUEUE.checked_add(kids)?)
                .checked_mul(size_of::<MuxCommand<B::Lower, K>>())?
                .checked_add(QUEUE.checked_mul(size_of::<EventOf<K>>())?)?,
        )
    }

    /// Reserves the queues and the first [`FLOOR`] child places the first
    /// time anything arrives. Further places are reserved as children open
    /// ([`Self::make_room`]).
    fn reserve(&mut self, budget: &Budget) -> Result<(), Overrun> {
        if self.storage.is_some() {
            return Ok(());
        }
        let bytes = Self::routing_bytes(FLOOR).ok_or(Overrun::Budget)?;
        let charge = budget.charge(bytes).ok_or(Overrun::Budget)?;
        self.kids = Slab::with_capacity(FLOOR);
        self.order = Vec::with_capacity(FLOOR);
        self.timers = Vec::with_capacity(FLOOR);
        self.woken.keys.lock().reserve_exact(FLOOR);
        self.down = VecDeque::with_capacity(QUEUE + FLOOR);
        self.up = VecDeque::with_capacity(QUEUE);
        self.storage = Some(charge);
        Ok(())
    }

    /// Makes a place for one more child, charging its routing storage
    /// before growing. Places grow geometrically up to the limit and are
    /// kept while children are open. Returns whether there is room.
    fn make_room(&mut self) -> bool {
        if self.kids.len() < self.kids.capacity() {
            return true;
        }
        let places = self
            .kids
            .capacity()
            .saturating_mul(2)
            .max(FLOOR)
            .min(self.limit.max(1));
        let Some(bytes) = Self::routing_bytes(places) else {
            return false;
        };
        let Some(storage) = &mut self.storage else {
            return false;
        };
        if !storage.grow_to(bytes) {
            return false;
        }
        self.kids.reserve_exact(places - self.kids.len());
        self.order.reserve_exact(places - self.order.len());
        self.timers.reserve_exact(places - self.timers.len());
        // Only open children wait in the wake queue, fewer than `places`.
        let mut keys = self.woken.keys.lock();
        let queued = keys.len();
        keys.reserve_exact(places - queued);
        drop(keys);
        self.down.reserve_exact(QUEUE + places - self.down.len());
        true
    }

    /// The key of child `id`, while it is open.
    fn key(&self, id: ChildId) -> Option<usize> {
        let at = self.order.binary_search_by_key(&id, |(key, _)| *key).ok()?;
        Some(self.order[at].1)
    }

    fn remove(&mut self, id: ChildId) -> Option<Kid<B>> {
        let at = self.order.binary_search_by_key(&id, |(key, _)| *key).ok()?;
        let key = self.order.remove(at).1;
        self.ready.unlink(&mut self.kids, key);
        self.work.unlink(&mut self.kids, key);
        if let Some(place) = self.kids[key].heap {
            self.unschedule(place);
        }
        let kid = self.kids.remove(key);
        kid.wake.close();
        Some(kid)
    }

    /// Child `key` was called: its layer may have work, its deadline is
    /// read again, and with `ready` it needs a visit. A timer that `fired`
    /// is armed again even at the same moment, behind the others.
    fn called(&mut self, key: usize, ready: bool, fired: bool) {
        if ready {
            self.ready.push(&mut self.kids, key);
        }
        self.work.push(&mut self.kids, key);
        let due = self.kids[key].layer.deadline();
        self.schedule(key, due, fired);
    }

    /// Sets child `key`'s deadline in the heap.
    fn schedule(&mut self, key: usize, due: Option<(Instant, B::Timer)>, fired: bool) {
        let kid = &mut self.kids[key];
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
            self.timers.push(key);
            self.timers.len() - 1
        });
        let place = self.sift_up(place);
        self.sift_down(place);
    }

    /// Takes the deadline at `place` out of the heap.
    fn unschedule(&mut self, place: usize) {
        let key = self.timers.swap_remove(place);
        self.kids[key].heap = None;
        if place < self.timers.len() {
            let place = self.sift_up(place);
            self.sift_down(place);
        }
    }

    /// When the child at heap `place` is due, and its arming number.
    fn due_at(&self, place: usize) -> (Instant, u64) {
        let kid = &self.kids[self.timers[place]];
        let (at, _) = kid.due.as_ref().expect("a scheduled child has a deadline");
        (*at, kid.armed)
    }

    fn sift_up(&mut self, mut place: usize) -> usize {
        while place > 0 {
            let parent = (place - 1) / 2;
            if self.due_at(parent) <= self.due_at(place) {
                break;
            }
            self.timers.swap(parent, place);
            self.kids[self.timers[place]].heap = Some(place);
            place = parent;
        }
        self.kids[self.timers[place]].heap = Some(place);
        place
    }

    fn sift_down(&mut self, mut place: usize) {
        loop {
            let mut first = place;
            for child in [2 * place + 1, 2 * place + 2] {
                if child < self.timers.len() && self.due_at(child) < self.due_at(first) {
                    first = child;
                }
            }
            if first == place {
                break;
            }
            self.timers.swap(first, place);
            self.kids[self.timers[place]].heap = Some(place);
            place = first;
        }
        self.kids[self.timers[place]].heap = Some(place);
    }

    /// Readies the children something reached from outside a call, in id
    /// order, whatever order their wakes came in.
    fn collect_wakes(&mut self) {
        let any = &self.woken.any;
        if !any.load(Ordering::Relaxed) || !any.swap(false, Ordering::Acquire) {
            return;
        }
        let mut keys = self.woken.keys.lock();
        let kids = &mut self.kids;
        keys.sort_unstable_by_key(|&key| kids[key].id);
        for key in keys.drain(..) {
            // Reads the wake that queued it, and whatever came before it.
            kids[key].wake.woken.swap(false, Ordering::Acquire);
            self.ready.push(kids, key);
            self.work.push(kids, key);
        }
    }

    /// With no children, the places past the first [`FLOOR`] go, so an idle
    /// connection holds the same whatever it held before: its queues and
    /// those places, so one with a few children at a time never gives
    /// places back to take them again. Closing commands still queued keep
    /// their places until the mux takes them.
    fn release_places(&mut self) {
        if !self.kids.is_empty() || self.storage.is_none() || self.kids.capacity() <= FLOOR {
            return;
        }
        self.kids = Slab::with_capacity(FLOOR);
        self.order = Vec::with_capacity(FLOOR);
        self.timers = Vec::with_capacity(FLOOR);
        // Closed children left the wake queue, so it is empty.
        *self.woken.keys.lock() = Vec::with_capacity(FLOOR);
        self.down.shrink_to((QUEUE + FLOOR).max(self.down.len()));
        let places = self.down.capacity().saturating_sub(QUEUE);
        if let (Some(storage), Some(bytes)) = (&mut self.storage, Self::routing_bytes(places)) {
            storage.shrink_to(bytes);
        }
    }

    /// The layer of child `id`, while it is open.
    pub fn child(&self, id: ChildId) -> Option<&B> {
        self.key(id).map(|key| &self.kids[key].layer)
    }

    /// The open children, in order.
    pub fn ids(&self) -> impl Iterator<Item = ChildId> + '_ {
        self.order.iter().map(|(id, _)| *id)
    }

    /// Whether nothing is open or queued either way: until an event comes,
    /// no step can move anything, and there is no timer or work.
    pub(crate) fn is_idle(&self) -> bool {
        self.kids.is_empty() && self.down.is_empty() && self.up.is_empty()
    }

    /// Closes a failed child and reports it.
    fn fail(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        id: ChildId,
        error: B::Error,
    ) {
        if let Some(kid) = self.remove(id) {
            // Closing is bounded by the mux's own limit on children: the
            // mux keeps the slot until it takes this command.
            self.down.push_back(kid.handle.close());
            env.report(ChildReport::Failed(id, error));
        }
    }

    /// Closes a child that broke its limits and reports it. Dropping it
    /// cancels its work.
    fn refuse(&mut self, env: &mut Env<'_, ChildReport<B::Report, B::Error>>, id: ChildId) {
        if let Some(kid) = self.remove(id) {
            self.down.push_back(kid.handle.close());
            env.report(ChildReport::Refused(id));
        }
    }

    /// Whether child `id`'s place is full: its urgent place, or its inbox.
    fn full(&self, id: ChildId, urgent: bool) -> bool {
        self.key(id).is_some_and(|key| {
            let kid = &self.kids[key];
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
        self.ready.unlink(&mut self.kids, key);
        let Some((moved, waiting)) = self.visit_kid(env, key) else {
            return true;
        };
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
        let kid = &mut self.kids[key];
        let id = kid.id;
        let report = move |e| ChildReport::Event(id, e);
        // Until `take_released` below. A closed child takes nothing more.
        kid.wake.enter();
        let mut moved =
            match env.scoped_child(&kid.budget, &kid.wake, report, |env| kid.layer.advance(env)) {
                Ok(moved) => moved,
                Err(e) => {
                    self.fail(env, id, e);
                    return None;
                }
            };
        if let Some(event) = kid.urgent.take() {
            match env.scoped_child(&kid.budget, &kid.wake, report, |env| {
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
            match env.scoped_child(&kid.budget, &kid.wake, report, |env| {
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
            kid.outbox = env.scoped_child(&kid.budget, &kid.wake, report, |env| {
                kid.layer.take_command(env)
            });
            moved |= kid.outbox.is_some();
        }
        let output_idle = kid.outbox.is_none();
        let mut waiting = false;
        if let Some(mut command) = kid.outbox.take() {
            if !command.splittable() && command.credit() > kid.max_command {
                self.refuse(env, id);
                return None;
            }
            if !command.reserve(&kid.budget) {
                self.refuse(env, id);
                return None;
            }
            if self.down.len() < QUEUE - RESERVE {
                match command.admit_credit(kid.credit) {
                    Ok((prefix, rest)) => {
                        kid.credit -= prefix.credit();
                        self.down.push_back(kid.handle.send(prefix));
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
            if self.down.len() < QUEUE {
                self.down.push_back(kid.handle.grant(kid.owed));
                kid.granted += kid.owed;
                kid.owed = 0;
                moved = true;
            } else {
                waiting = true;
            }
        }
        if self.close_finished && output_idle && kid.layer.is_terminal() {
            if self.down.len() < QUEUE {
                let kid = self.remove(id).expect("visited child");
                self.down.push_back(kid.handle.close());
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
        self.reserve(env.budget())?;
        match event {
            MuxEvent::Opened(child, opening, max_command) => {
                let id = child.id();
                if self.down.len() >= QUEUE {
                    return Ok(Admit::Blocked(MuxEvent::Opened(
                        child,
                        opening,
                        max_command,
                    )));
                }
                // A child past the limit, or one whose storage the budget
                // cannot hold, is refused: closed at once, its siblings
                // and the connection untouched.
                let budget = self.budget_for.as_mut().map_or_else(
                    || env.budget().clone(),
                    |select| select(id, &opening, env.budget()),
                );
                let reserved = (self.kids.len() < self.limit && self.make_room())
                    .then(|| {
                        let window =
                            budget.charge(EventOf::<B::Lower>::receive_bytes(self.window)?)?;
                        Some(Arc::new(window))
                    })
                    .flatten();
                let Some(window) = reserved else {
                    self.down.push_back(child.close());
                    env.report(ChildReport::Refused(id));
                    return Ok(Admit::Taken);
                };
                let Some(layer) = (self.make)(id, opening, &budget) else {
                    self.down.push_back(child.close());
                    env.report(ChildReport::Refused(id));
                    return Ok(Admit::Taken);
                };
                let due = layer.deadline();
                assert!(env.fits_below(&layer), "composition is too deep");
                let place = self.kids.vacant_entry();
                let key = place.key();
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
                    owner: WorkOwner::new(),
                    urgent: None,
                    wake: Arc::new(ChildWake::new(key, self.woken.clone())),
                    window,
                    max_command,
                    granted: 0,
                    owed: self.window,
                    credit: 0,
                    outbox: None,
                });
                let at = self
                    .order
                    .binary_search_by_key(&id, |(key, _)| *key)
                    .unwrap_err();
                self.order.insert(at, (id, key));
                self.ready.push(&mut self.kids, key);
                self.work.push(&mut self.kids, key);
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
                            &kid.wake,
                            |event| ChildReport::Event(id, event),
                            |env| kid.layer.on_event(env, event),
                        ) {
                            env.report(ChildReport::Failed(id, error));
                        }
                        self.down.push_back(kid.handle.close());
                    }
                    return Ok(Admit::Taken);
                }
                // A child already gone has nothing to deliver to.
                let Some(key) = self.key(id) else {
                    return Ok(Admit::Taken);
                };
                let cost = event.credit();
                if cost > self.kids[key].granted {
                    return Err(Overrun::Credit(id));
                }
                // A full place gets the child one visit to make room. A
                // child that makes none is overloaded and goes alone: the
                // event is never handed back to block the mux.
                let urgent = B::Lower::urgent(&event);
                if self.full(id, urgent) {
                    self.visit(env, key);
                    if self.full(id, urgent) {
                        self.refuse(env, id);
                    }
                }
                if let Some(key) = self.key(id) {
                    let kid = &mut self.kids[key];
                    if urgent {
                        kid.urgent = Some(event);
                    } else {
                        if !event.reserve_receive(&kid.budget, &kid.window) {
                            self.refuse(env, id);
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
                        if kid.inbox.push_back((event, retained)).is_err() {
                            self.refuse(env, id);
                            return Ok(Admit::Taken);
                        }
                    }
                    self.ready.push(&mut self.kids, key);
                }
            }
            MuxEvent::Credit(id, units) => {
                if let Some(key) = self.key(id) {
                    let kid = &mut self.kids[key];
                    kid.credit = kid.credit.saturating_add(units);
                    self.ready.push(&mut self.kids, key);
                }
            }
            MuxEvent::Closed(id) => {
                self.remove(id);
            }
            MuxEvent::Control(event) => {
                if self.up.len() >= QUEUE {
                    return Ok(Admit::Blocked(MuxEvent::Control(event)));
                }
                self.up.push_back(event);
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<K>,
    ) -> Result<Admit<CommandOf<K>>, Overrun> {
        self.reserve(env.budget())?;
        if self.down.len() >= QUEUE {
            return Ok(Admit::Blocked(command));
        }
        self.down.push_back(MuxCommand::control(command));
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
        let kid = &mut self.kids[key];
        let layer = &mut kid.layer;
        let result = kid.wake.call(|| {
            env.scoped_child(
                &kid.budget,
                &kid.wake,
                move |e| ChildReport::Event(id, e),
                |env| layer.on_timer(env, timer),
            )
        });
        // A child that declines its timer still goes behind its siblings
        // due at the same time, so theirs fire first.
        match result {
            Ok(fired) => {
                self.called(key, true, true);
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
        let kid = &mut self.kids[key];
        let layer = &mut kid.layer;
        let result = kid.wake.call(|| {
            env.scoped_child(
                &kid.budget,
                &kid.wake,
                move |e| ChildReport::Event(id, e),
                |env| layer.on_done(env, done),
            )
        });
        match result {
            Ok(()) => self.called(key, true, false),
            Err(e) => self.fail(env, id, e),
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Overrun> {
        // The queues are the router's fixed state: an idle connection holds
        // them from its first step.
        self.reserve(env.budget())?;
        self.collect_wakes();
        // The children ready now, in list order, at most QUEUE of them. One
        // that stays ready goes to the end and waits for the next advance.
        let mut moved = false;
        for visits in 0..self.ready.len {
            if visits == QUEUE {
                self.release_places();
                return Ok(true);
            }
            let Some(key) = self.ready.head else {
                break;
            };
            moved |= self.visit(env, key);
        }
        self.release_places();
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<MuxCommand<B::Lower, K>> {
        self.down.pop_front()
    }

    fn take_event(&mut self) -> Option<EventOf<K>> {
        self.up.pop_front()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        while let Some(key) = self.work.pop(&mut self.kids) {
            let kid = &mut self.kids[key];
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
            ChildReport::Refused(_) => Some(0),
            ChildReport::Failed(_, _) => None,
        }
    }

    fn depth(&self) -> usize {
        1 + self
            .kids
            .iter()
            .map(|(_, kid)| kid.layer.depth())
            .max()
            .unwrap_or(0)
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        let kid = &self.kids[*self.timers.first()?];
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
        assert!(!driver.layer().woken.any.load(Ordering::Acquire));
        assert!(driver.layer().woken.keys.lock().is_empty());
        driver.run().unwrap();
        assert_eq!(driver.layer().child(id).unwrap().0, 1);
        assert!(matches!(
            driver.take_command().unwrap().into_op(),
            super::super::MuxOp::Credit(found, 1) if found == id
        ));
    }

    #[test]
    fn an_uncharged_payload_that_does_not_fit_refuses_only_its_child() {
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
        let rest = budget.charge(budget.limit() - budget.used()).unwrap();
        assert!(matches!(
            driver.deliver(MuxEvent::Child(ids[0], payload())),
            Ok(Admit::Taken)
        ));
        assert!(driver.layer().child(ids[0]).is_none());
        drop(rest);
        let _ = driver.deliver(MuxEvent::Child(ids[1], payload())).unwrap();
        driver.run().unwrap();
        assert_eq!(driver.layer().child(ids[1]).unwrap().0, 2);
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
                super::super::MuxOp::Close(_) => {
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
        let chunk = driver.layer_mut().kids[0].layer.held.take().unwrap();
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
            let chunk = driver.layer_mut().kids[0].layer.held.take().unwrap();
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
        (id, layer.kids[key].layer.held.take().unwrap())
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
        assert!(!driver.layer().woken.keys.lock().is_empty());
        let _ = driver.deliver(MuxEvent::Closed(queued)).unwrap();
        assert!(driver.layer().woken.keys.lock().is_empty());
        // Closed, then woken: a later child has its place by then.
        let (closed, chunk) = holding(&mut driver, &mut slots);
        let place = driver.layer().key(closed);
        let _ = driver.deliver(MuxEvent::Closed(closed)).unwrap();
        let (later, later_chunk) = holding(&mut driver, &mut slots);
        assert_eq!(driver.layer().key(later), place);
        drop(chunk);
        assert!(driver.layer().woken.keys.lock().is_empty());
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
            super::super::MuxOp::Close(found) if found == id));
        let accepted = slots.insert(()).unwrap();
        let id = accepted.id();
        let _ = driver.deliver(MuxEvent::Opened(accepted, true, 8)).unwrap();
        assert!(driver.layer().child(id).is_some());
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
        assert_eq!(driver.layer().kids[0].inbox.len(), QUEUE);
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
        assert_eq!(driver.layer_mut().kids.len(), 1);
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
            if let MuxOp::Close(id) = command.into_op() {
                closed.push(id);
            }
        }
        closed.sort();
        assert_eq!(closed, [stuck, stuck_urgent]);
        let refused: Vec<_> = driver
            .observations()
            .drain()
            .filter_map(|report| match report {
                ChildReport::Refused(id) => Some(id),
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
            matches!(driver.take_command().unwrap().into_op(), crate::stdlib::layer::MuxOp::Close(id) if id == b)
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

    #[test]
    fn a_refused_reservation_never_constructs_a_child() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = called.clone();
        let children: Children<Reader, Top, ()> = Children::new(1, 8, move |_, (), _| {
            flag.store(true, Ordering::Relaxed);
            Some(Reader::default())
        });
        let budget = Budget::new(0);
        let mut driver = Driver::new(
            children,
            Arc::new(SeededEntropy::new(Seed::from_u64(92))),
            budget.clone(),
            Instant::ZERO,
        );
        let mut slots = Slots::new(1);
        let child = slots.insert(()).unwrap();
        assert!(matches!(
            driver.deliver(MuxEvent::Opened(child, (), 8)),
            Err(Overrun::Budget)
        ));
        assert!(!called.load(Ordering::Relaxed));
        assert_eq!(budget.used(), 0);
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
            matches!(driver.take_command().unwrap().into_op(), MuxOp::Close(actual) if actual == id)
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
