use super::carrier::CreditReturn;
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::task::{Wake, Waker};

use fictionet::stdlib::layer::{
    Admit, Budget, Charge, Child, ChildId, CommandOf, Credited, Env, EventOf, Layer, MAX_DEPTH,
    Mux, MuxCommand, MuxEvent, OwnedWork, Port, Top, WorkOwner,
};
use fictionet::sync::Mutex;
use fictionet::time::Instant;

/// How many commands wait for the mux, and how many of those places only
/// connection control and credit may use.
const QUEUE: usize = 64;
const RESERVE: usize = 8;
const MAX_CHILDREN: usize = 4096;
type ChildFactory<B, O> = dyn FnMut(ChildId, O, &Budget) -> B + Send;
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
/// #     fn take_command(&mut self) -> Option<CommandOf<L>> { None }
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
/// #     fn take_command(&mut self) -> Option<CommandOf<L>> { None }
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
/// not read holds up nothing but itself. An advance visits only the
/// children that have something to do: one that got an event, credit, a
/// timer, a work result or a wake from its work, one whose released
/// payload returned credit, and one whose last visit moved or found the
/// mux's queue full. They are visited in a stable order, at most 64 per
/// advance, continuing after the last visited child. A child's layer
/// changes only when `Children` calls it, so its deadline and depth are
/// kept from its last call. At most 4096 children can be configured; work
/// and deadline scans share that hard bound. Byte receive credit returns
/// when its backing is released; atomic message credit returns on
/// admission, independently of memory.
///
/// The router's queues are charged to the budget from its first step. Each
/// child's place and its inbox are charged as they grow, the places up to the
/// limit and each inbox up to its bound, and the places go once no child is
/// left. A child whose storage the budget cannot hold is refused
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
    kids: Vec<(ChildId, Kid<B>)>,
    /// What each child in `kids`, at the same index, has to do.
    marks: Vec<Marks>,
    /// Set when something outside a call reached a child ([`ChildWake`]).
    woken: Arc<AtomicBool>,
    limit: usize,
    window: u64,
    down: VecDeque<MuxCommand<B::Lower, K>>,
    up: VecDeque<EventOf<K>>,
    /// Where the next advance starts: after this child.
    turn: Option<ChildId>,
    work_turn: Option<ChildId>,
    timer_turn: Option<ChildId>,
    // Reservations outlive every allocation they cover during destruction.
    storage: Option<Charge>,
}

/// Whether a child needs a visit, and whether its layer may have work to
/// hand over.
#[derive(Clone, Copy, Default)]
struct Marks {
    ready: bool,
    work: bool,
}

struct Kid<B: Layer> {
    handle: Child,
    owner: WorkOwner,
    urgent: Option<EventOf<B::Lower>>,
    layer: B,
    budget: Budget,
    /// Events the mux sent within credit that the layer has not taken.
    inbox: VecDeque<(EventOf<B::Lower>, bool)>,
    /// What the inbox is charged: its places, grown as events wait.
    storage: Charge,
    wake: Arc<ChildWake>,
    /// The layer's deadline and depth after its last call.
    due: Option<Instant>,
    depth: usize,
    backing: Arc<Charge>,
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
/// credit returned by payload released elsewhere, and wakes from its work,
/// which may share state with its layer (a tunnel's connection does).
/// Either gets the child visited at the next advance.
pub(crate) struct ChildWake {
    released: AtomicU64,
    /// `Children` is calling the child and collects what it releases.
    calling: AtomicBool,
    woken: AtomicBool,
    /// The flag `Children` checks before looking for woken children.
    any: Arc<AtomicBool>,
    /// The task that polls the child's work, woken with it.
    task: Mutex<Option<Waker>>,
}

impl ChildWake {
    fn new(any: Arc<AtomicBool>) -> ChildWake {
        ChildWake {
            released: AtomicU64::new(0),
            calling: AtomicBool::new(false),
            woken: AtomicBool::new(false),
            any,
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

    fn notify(&self) {
        self.woken.store(true, Ordering::Release);
        self.any.store(true, Ordering::Release);
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
    /// its events and a layer from `make`.
    pub fn new(
        limit: usize,
        window: u64,
        make: impl FnMut(ChildId, O, &Budget) -> B + Send + 'static,
    ) -> Self {
        assert!(
            limit <= MAX_CHILDREN,
            "child limit exceeds the bounded router capacity"
        );
        Children {
            make: Box::new(make),
            budget_for: None,
            close_finished: false,
            kids: Vec::new(),
            marks: Vec::new(),
            woken: Arc::new(AtomicBool::new(false)),
            storage: None,
            limit,
            window,
            down: VecDeque::new(),
            up: VecDeque::new(),
            turn: None,
            work_turn: None,
            timer_turn: None,
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

    /// The routing storage for `kids` child places: the places themselves
    /// with their marks and wake state, the command queue with one closing
    /// place per child, and the control queue.
    fn routing_bytes(kids: usize) -> Option<usize> {
        let place = size_of::<(ChildId, Kid<B>)>()
            + size_of::<Marks>()
            // The wake state's shared allocation, with its two counts.
            + size_of::<ChildWake>()
            + 2 * size_of::<usize>();
        kids.checked_mul(place)?.checked_add(
            (QUEUE.checked_add(kids)?)
                .checked_mul(size_of::<MuxCommand<B::Lower, K>>())?
                .checked_add(QUEUE.checked_mul(size_of::<EventOf<K>>())?)?,
        )
    }

    /// Reserves the queues the first time anything arrives. Child places
    /// are reserved as children open ([`Self::make_room`]).
    fn reserve(&mut self, budget: &Budget) -> Result<(), Overrun> {
        if self.storage.is_some() {
            return Ok(());
        }
        let bytes = Self::routing_bytes(0).ok_or(Overrun::Budget)?;
        let charge = budget.charge(bytes).ok_or(Overrun::Budget)?;
        self.kids = Vec::new();
        self.down = VecDeque::with_capacity(QUEUE);
        self.up = VecDeque::with_capacity(QUEUE);
        self.storage = Some(charge);
        Ok(())
    }

    /// Makes a place for one more child, charging its routing storage
    /// before growing. Places grow geometrically up to the limit and are
    /// kept once made. Returns whether there is room.
    fn make_room(&mut self) -> bool {
        if self.kids.len() < self.kids.capacity() {
            return true;
        }
        let places = self
            .kids
            .capacity()
            .saturating_mul(2)
            .max(4)
            .min(self.limit.max(1));
        let Some(bytes) = Self::routing_bytes(places) else {
            return false;
        };
        let Some(storage) = &mut self.storage else {
            return false;
        };
        if !storage.set(bytes) {
            return false;
        }
        self.kids.reserve_exact(places - self.kids.len());
        self.marks.reserve_exact(places - self.marks.len());
        self.down.reserve_exact(QUEUE + places - self.down.len());
        true
    }

    /// Where child `id` is in `kids`, which is in id order.
    fn index(&self, id: ChildId) -> Option<usize> {
        self.kids.binary_search_by_key(&id, |(key, _)| *key).ok()
    }

    fn kid_mut(&mut self, id: ChildId) -> Option<&mut Kid<B>> {
        let index = self.index(id)?;
        Some(&mut self.kids[index].1)
    }

    fn remove(&mut self, id: ChildId) -> Option<Kid<B>> {
        let index = self.index(id)?;
        self.marks.remove(index);
        Some(self.kids.remove(index).1)
    }

    /// Child `id` was called: its layer may have work, its deadline and
    /// depth are read again, and with `ready` it needs a visit.
    fn called(&mut self, id: ChildId, ready: bool) {
        if let Some(index) = self.index(id) {
            self.called_at(index, ready);
        }
    }

    fn called_at(&mut self, index: usize, ready: bool) {
        let marks = &mut self.marks[index];
        marks.ready |= ready;
        marks.work = true;
        let kid = &mut self.kids[index].1;
        kid.due = kid.layer.deadline().map(|(at, _)| at);
        kid.depth = kid.layer.depth();
    }

    /// Marks the children something reached from outside a call.
    fn collect_wakes(&mut self) {
        if !self.woken.load(Ordering::Relaxed) || !self.woken.swap(false, Ordering::Acquire) {
            return;
        }
        for ((_, kid), marks) in self.kids.iter().zip(&mut self.marks) {
            if kid.wake.woken.load(Ordering::Relaxed)
                && kid.wake.woken.swap(false, Ordering::Acquire)
            {
                *marks = Marks {
                    ready: true,
                    work: true,
                };
            }
        }
    }

    /// With no children the places go, so an idle connection holds the same
    /// whatever it held before. Closing commands still queued keep their
    /// places until the mux takes them.
    fn release_places(&mut self) {
        if !self.kids.is_empty() || self.storage.is_none() {
            return;
        }
        self.kids = Vec::new();
        self.marks = Vec::new();
        self.down.shrink_to(QUEUE.max(self.down.len()));
        let places = self.down.capacity().saturating_sub(QUEUE);
        if let (Some(storage), Some(bytes)) = (&mut self.storage, Self::routing_bytes(places)) {
            storage.set(bytes);
        }
    }

    /// The layer of child `id`, while it is open.
    pub fn child(&self, id: ChildId) -> Option<&B> {
        self.index(id).map(|index| &self.kids[index].1.layer)
    }

    /// The open children, in order.
    pub fn ids(&self) -> impl Iterator<Item = ChildId> + '_ {
        self.kids.iter().map(|(id, _)| *id)
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
        self.index(id).is_some_and(|index| {
            let kid = &self.kids[index].1;
            if urgent {
                kid.urgent.is_some()
            } else {
                kid.inbox.len() >= QUEUE
            }
        })
    }

    /// One visit to child `id`: its internal work, one event in, one
    /// command out, and credit granted again. Returns whether anything
    /// moved. The child stays ready if something moved or if the mux's
    /// queue had no room for what it has to send.
    fn visit_child(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        id: ChildId,
    ) -> bool {
        self.index(id)
            .is_some_and(|index| self.visit_at(env, index))
    }

    /// The same for the child at `index`.
    fn visit_at(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        index: usize,
    ) -> bool {
        self.marks[index].ready = false;
        let Some((moved, waiting)) = self.visit_kid(env, index) else {
            return true;
        };
        self.called_at(index, moved || waiting);
        moved
    }

    /// The visit itself: whether anything moved and whether the child waits
    /// for room in the mux's queue, or `None` if the child was closed.
    fn visit_kid(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        index: usize,
    ) -> Option<(bool, bool)> {
        let (id, kid) = &mut self.kids[index];
        let id = *id;
        let report = move |e| ChildReport::Event(id, e);
        // Until `take_released` below. A closed child takes nothing more.
        kid.wake.enter();
        let mut moved = match env.scoped_in(&kid.budget, report, |env| kid.layer.advance(env)) {
            Ok(moved) => moved,
            Err(e) => {
                self.fail(env, id, e);
                return None;
            }
        };
        if let Some(event) = kid.urgent.take() {
            match env.scoped_in(&kid.budget, report, |env| kid.layer.on_event(env, event)) {
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
            match env.scoped_in(&kid.budget, report, |env| kid.layer.on_event(env, event)) {
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
                    kid.inbox.push_front((rest, retained));
                    moved = true;
                }
                Ok(Admit::Blocked(event)) => kid.inbox.push_front((event, retained)),
                Err(e) => {
                    self.fail(env, id, e);
                    return None;
                }
            }
        }
        if kid.outbox.is_none() {
            kid.outbox = kid.layer.take_command();
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
                        // The inbox grows as events wait in it (`admit`).
                        let storage = budget.charge(0)?;
                        let backing =
                            budget.charge(EventOf::<B::Lower>::receive_bytes(self.window)?)?;
                        Some((storage, Arc::new(backing)))
                    })
                    .flatten();
                let Some((storage, backing)) = reserved else {
                    self.down.push_back(child.close());
                    env.report(ChildReport::Refused(id));
                    return Ok(Admit::Taken);
                };
                let layer = (self.make)(id, opening, &budget);
                let depth = layer.depth();
                assert!(depth < MAX_DEPTH, "composition depth exceeded");
                let kid = Kid {
                    handle: child,
                    due: layer.deadline().map(|(at, _)| at),
                    depth,
                    layer,
                    budget,
                    owner: WorkOwner::new(),
                    urgent: None,
                    inbox: VecDeque::new(),
                    storage,
                    wake: Arc::new(ChildWake::new(self.woken.clone())),
                    backing,
                    max_command,
                    granted: 0,
                    owed: self.window,
                    credit: 0,
                    outbox: None,
                };
                let index = self
                    .kids
                    .binary_search_by_key(&id, |(key, _)| *key)
                    .unwrap_err();
                self.kids.insert(index, (id, kid));
                self.marks.insert(
                    index,
                    Marks {
                        ready: true,
                        work: true,
                    },
                );
            }
            MuxEvent::Child(id, mut event) => {
                // Reset ends this lifetime immediately. Notify the child, then
                // discard its refused input, output, credit and work together.
                if event.terminal_reset() {
                    if let Some(mut kid) = self.remove(id) {
                        kid.owner.cancel();
                        if let Err(error) = env.scoped_in(
                            &kid.budget,
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
                let Some(index) = self.index(id) else {
                    return Ok(Admit::Taken);
                };
                let cost = event.credit();
                if cost > self.kids[index].1.granted {
                    return Err(Overrun::Credit(id));
                }
                // A full place gets the child one visit to make room. A
                // child that makes none is overloaded and goes alone: the
                // event is never handed back to block the mux.
                let urgent = event.urgent();
                if self.full(id, urgent) {
                    self.visit_child(env, id);
                    if self.full(id, urgent) {
                        self.refuse(env, id);
                    }
                }
                if let Some(index) = self.index(id) {
                    let kid = &mut self.kids[index].1;
                    if urgent {
                        kid.urgent = Some(event);
                    } else {
                        if kid.inbox.len() == kid.inbox.capacity() {
                            // Charge the inbox's growth before it grows; a
                            // child the budget cannot hold is refused.
                            let places = (kid.inbox.capacity() * 2).clamp(4, QUEUE);
                            let bytes = places * size_of::<(EventOf<B::Lower>, bool)>();
                            if !kid.storage.set(bytes) {
                                self.refuse(env, id);
                                return Ok(Admit::Taken);
                            }
                            kid.inbox.reserve_exact(places - kid.inbox.len());
                        }
                        if !event.reserve_receive(&kid.budget, &kid.backing) {
                            return Err(Overrun::Budget);
                        }
                        kid.granted -= cost;
                        let retained = if cost > 0 {
                            event.retain_credit(CreditReturn::new(kid.wake.clone(), cost))
                        } else {
                            false
                        };
                        kid.inbox.push_back((event, retained));
                    }
                    self.marks[index].ready = true;
                }
            }
            MuxEvent::Credit(id, units) => {
                if let Some(index) = self.index(id) {
                    let kid = &mut self.kids[index].1;
                    kid.credit = kid.credit.saturating_add(units);
                    self.marks[index].ready = true;
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
    ) -> Result<(), Overrun> {
        let Some(kid) = self.kid_mut(id) else {
            return Ok(());
        };
        let layer = &mut kid.layer;
        let result = kid.wake.call(|| {
            env.scoped_in(
                &kid.budget,
                move |e| ChildReport::Event(id, e),
                |env| layer.on_timer(env, timer),
            )
        });
        self.timer_turn = Some(id);
        match result {
            Ok(()) => self.called(id, true),
            Err(e) => self.fail(env, id, e),
        }
        Ok(())
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        (id, done): Self::Done,
    ) -> Result<(), Overrun> {
        let Some(kid) = self.kid_mut(id) else {
            return Ok(());
        };
        let layer = &mut kid.layer;
        let result = kid.wake.call(|| {
            env.scoped_in(
                &kid.budget,
                move |e| ChildReport::Event(id, e),
                |env| layer.on_done(env, done),
            )
        });
        match result {
            Ok(()) => self.called(id, true),
            Err(e) => self.fail(env, id, e),
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Overrun> {
        // The queues are the router's fixed state: an idle connection holds
        // them from its first step.
        self.reserve(env.budget())?;
        self.collect_wakes();
        // Ready children after the turn, then from the start up to it, each
        // at most once and at most QUEUE of them. A visit closes no child but
        // its own, so the places after it move down by one when it does.
        let turn = self.turn;
        let start = turn.map_or(0, |turn| self.kids.partition_point(|(id, _)| *id <= turn));
        let mut index = start;
        let mut end = self.kids.len();
        let mut wrapped = start == 0;
        let mut first = None;
        let mut last = None;
        let mut visits = 0;
        let mut moved = false;
        let mut more = false;
        loop {
            if index >= end {
                if wrapped {
                    break;
                }
                wrapped = true;
                index = 0;
                end = start;
                continue;
            }
            if !self.marks[index].ready {
                index += 1;
                continue;
            }
            if visits == QUEUE {
                more = true;
                break;
            }
            let id = self.kids[index].0;
            first.get_or_insert(id);
            last = Some(id);
            visits += 1;
            let open = self.kids.len();
            moved |= self.visit_at(env, index);
            if self.kids.len() < open {
                end -= 1;
            } else {
                index += 1;
            }
        }
        // A sweep that reached every ready child starts the next one after
        // the child it visited first, so each child in turn goes first.
        self.turn = if more { last } else { first.or(turn) };
        self.release_places();
        Ok(moved || more)
    }

    fn take_command(&mut self) -> Option<MuxCommand<B::Lower, K>> {
        self.down.pop_front()
    }

    fn take_event(&mut self) -> Option<EventOf<K>> {
        self.up.pop_front()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        let start = self
            .work_turn
            .map_or(0, |id| self.kids.partition_point(|(key, _)| *key <= id));
        for offset in 0..self.kids.len() {
            let index = (start + offset) % self.kids.len();
            if !self.marks[index].work {
                continue;
            }
            let (id, kid) = &mut self.kids[index];
            let id = *id;
            let layer = &mut kid.layer;
            let Some(work) = kid.wake.call(|| layer.take_work()) else {
                self.marks[index].work = false;
                continue;
            };
            let work = ChildWork {
                id,
                work: kid.owner.own(work),
                wake: kid.wake.clone(),
                finished: false,
            };
            self.work_turn = Some(id);
            // Handing work over can change the layer, as a session's idle
            // timer stops while its work runs.
            self.called(id, true);
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
            .map(|(_, kid)| kid.depth)
            .max()
            .unwrap_or(0)
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        let (id, kid) = self
            .kids
            .iter()
            .filter(|(_, kid)| kid.due.is_some())
            .min_by_key(|(id, kid)| {
                (kid.due, !self.timer_turn.is_none_or(|last| *id > last), *id)
            })?;
        kid.layer.deadline().map(|(at, timer)| (at, (*id, timer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Seed;
    use crate::entropy::SeededEntropy;
    use crate::stdlib::layer::{ByteStream, Chunk, Driver, Slots, StreamCommand, StreamEvent};
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
        fn take_command(&mut self) -> Option<StreamCommand> {
            self.writes.pop_front().or_else(|| {
                self.productive
                    .then(|| StreamCommand::Write(Chunk::new(vec![1])))
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
        fn on_timer(&mut self, _: &mut Env<'_, ()>, _: ()) -> Result<(), Infallible> {
            self.fired += 1;
            Ok(())
        }
    }

    fn driver(
        make: impl FnMut(ChildId, &'static str, &Budget) -> Reader + Send + 'static,
    ) -> Driver<Children<Reader, Top, &'static str>> {
        Driver::new(
            Children::new(3, 8, make),
            Arc::new(SeededEntropy::new(Seed::from_u64(91))),
            Budget::new(100_000),
            Instant::ZERO,
        )
    }

    #[test]
    fn terminal_children_drain_every_command_before_closing() {
        let mut driver = driver(|_, _, _| Reader {
            terminal: true,
            writes: [
                StreamCommand::Write(Chunk::new(b"first".to_vec())),
                StreamCommand::Write(Chunk::new(b"last".to_vec())),
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
            Reader::default()
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
                writes: VecDeque::from([StreamCommand::Write(Chunk::new(Bytes::from_static(
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
            while let Some(command) = driver.layer_mut().take_command() {
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
                StreamEvent::Data(Chunk::new(Bytes::from_static(b"abc"))),
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
        while driver.layer_mut().take_command().is_some() {}
        let _ = driver
            .deliver(MuxEvent::Child(
                id,
                StreamEvent::Data(Chunk::new(Bytes::from_static(b"abc"))),
            ))
            .unwrap();
        driver.run().unwrap();
        assert!(driver.layer_mut().take_command().is_none());
        let chunk = driver.layer_mut().kids[0].1.layer.held.take().unwrap();
        driver.run().unwrap();
        assert!(driver.layer_mut().take_command().is_none());
        drop(chunk);
        driver.run().unwrap();
        assert!(matches!(
            driver.layer_mut().take_command().unwrap().into_op(),
            super::super::MuxOp::Credit(_, 3)
        ));
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
                        StreamEvent::Data(Chunk::new(Bytes::new()))
                    ))
                    .unwrap()
                    .moved()
            );
        }
        // Empty data costs no credit, but holds one of the bounded places.
        assert_eq!(driver.layer().kids[0].1.inbox.len(), QUEUE);
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
                        StreamEvent::Data(Chunk::new(Vec::new()))
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
        assert_eq!(driver.layer_mut().kids[0].1.layer.completions, 9);
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
        fn take_command(&mut self) -> Option<StreamCommand> {
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
            Children::new(3, 8, |_, refuse, _| Probe { refuse, taken: 0 });
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
                MuxEvent::Child(stuck, StreamEvent::Data(Chunk::new(Bytes::new()))),
                MuxEvent::Child(stuck_urgent, StreamEvent::Written(1)),
                MuxEvent::Child(ready, StreamEvent::Data(Chunk::new(Bytes::new()))),
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
        while let Some(command) = driver.layer_mut().take_command() {
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
        let children: Children<Reader, Top> = Children::new(70, 8, |_, (), _| Reader {
            productive: true,
            ..Reader::default()
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
            while let Some(command) = driver.layer_mut().take_command() {
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
            Reader::default()
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
        while driver.layer_mut().take_command().is_some() {}
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
            matches!(driver.layer_mut().take_command().unwrap().into_op(), crate::stdlib::layer::MuxOp::Close(id) if id == b)
        );
        assert_eq!(made.load(Ordering::Relaxed), 1);
        drop(other);
        // The first child still takes its events.
        let _ = driver
            .deliver(MuxEvent::Child(
                a,
                StreamEvent::Data(Chunk::new(Bytes::from_static(b"ab"))),
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
        while driver.layer_mut().take_command().is_some() {}
        assert_eq!(budget.used(), idle);
    }

    #[test]
    fn a_refused_reservation_never_constructs_a_child() {
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = called.clone();
        let children: Children<Reader, Top, ()> = Children::new(1, 8, move |_, (), _| {
            flag.store(true, Ordering::Relaxed);
            Reader::default()
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
            fn take_command(&mut self) -> Option<MessageCommand<u8>> {
                std::mem::take(&mut self.0).then_some(MessageCommand::Send(7))
            }
            fn take_event(&mut self) -> Option<Infallible> {
                None
            }
        }
        let children: Children<Atomic, Top> = Children::new(1, 1, |_, (), _| Atomic(true));
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
            matches!(driver.layer_mut().take_command().unwrap().into_op(), MuxOp::Close(actual) if actual == id)
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
                    Http1::new(Answer {
                        name,
                        dropped: flag.clone(),
                    })
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
            while driver.layer_mut().take_command().is_some() {}
            for id in &ids {
                let _ = driver
                    .deliver(MuxEvent::Child(
                        *id,
                        StreamEvent::Data(Chunk::new(
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
                while let Some(command) = driver.layer_mut().take_command() {
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
