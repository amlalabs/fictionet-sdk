use super::carrier::CreditReturn;
use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use fictionet::stdlib::layer::{
    Admit, Budget, Charge, Child, ChildId, CommandOf, Credited, Env, EventOf, Layer, MAX_DEPTH,
    Mux, MuxCommand, MuxEvent, OwnedWork, Port, Top, WorkOwner,
};
use fictionet::time::Instant;

/// How many commands wait for the mux, and how many of those places only
/// connection control and credit may use.
const QUEUE: usize = 64;
const RESERVE: usize = 8;
const MAX_CHILDREN: usize = 4096;
type ChildFactory<B, O> = dyn FnMut(ChildId, O, &Budget) -> B + Send;

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
/// not read holds up nothing but itself. Children are visited in a stable
/// order, at most 64 per advance, continuing after the last visited child.
/// At most 4096 children can be configured; work and deadline scans share
/// that hard bound. Byte receive credit returns when its backing is released;
/// atomic message credit returns on admission, independently of memory.
///
/// The router's queues are charged to the budget from its first step. Each
/// child's place and its inbox are charged as they grow, the places up to the
/// limit and each inbox up to its bound, and the places go once no child is
/// left. A child whose storage the budget cannot hold is refused
/// ([`ChildReport::Refused`]) and its siblings go on.
pub struct Children<B, K, O = ()>
where
    B: Layer<Upper = Top>,
    EventOf<B::Lower>: Credited,
    CommandOf<B::Lower>: Credited,
    K: Port,
{
    make: Box<ChildFactory<B, O>>,
    kids: Vec<(ChildId, Kid<B>)>,
    limit: usize,
    window: u64,
    down: VecDeque<MuxCommand<B::Lower, K>>,
    up: VecDeque<EventOf<K>>,
    /// The child visited first last time.
    turn: Option<ChildId>,
    work_turn: Option<ChildId>,
    timer_turn: Option<ChildId>,
    remaining_visits: usize,
    sweep_first: Option<ChildId>,
    // Reservations outlive every allocation they cover during destruction.
    storage: Option<Charge>,
}

struct Kid<B: Layer> {
    handle: Child,
    owner: WorkOwner,
    urgent: Option<EventOf<B::Lower>>,
    layer: B,
    /// Events the mux sent within credit that the layer has not taken.
    inbox: VecDeque<(EventOf<B::Lower>, bool)>,
    /// What the inbox is charged: its places, grown as events wait.
    storage: Charge,
    released: Arc<AtomicU64>,
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
            kids: Vec::new(),
            storage: None,
            limit,
            window,
            down: VecDeque::new(),
            up: VecDeque::new(),
            turn: None,
            work_turn: None,
            timer_turn: None,
            remaining_visits: 0,
            sweep_first: None,
        }
    }

    /// The routing storage for `kids` child places: the places themselves,
    /// the command queue with one closing place per child, and the control
    /// queue.
    fn routing_bytes(kids: usize) -> Option<usize> {
        kids.checked_mul(size_of::<(ChildId, Kid<B>)>())?
            .checked_add(
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
        self.down.reserve_exact(QUEUE + places - self.down.len());
        true
    }

    fn remove(&mut self, id: ChildId) -> Option<Kid<B>> {
        let index = self.kids.iter().position(|(key, _)| *key == id)?;
        Some(self.kids.remove(index).1)
    }

    /// With no children the places go, so an idle connection holds the same
    /// whatever it held before. Closing commands still queued keep their
    /// places until the mux takes them.
    fn release_places(&mut self) {
        if !self.kids.is_empty() || self.storage.is_none() {
            return;
        }
        self.kids = Vec::new();
        self.down.shrink_to(QUEUE.max(self.down.len()));
        let places = self.down.capacity().saturating_sub(QUEUE);
        if let (Some(storage), Some(bytes)) = (&mut self.storage, Self::routing_bytes(places)) {
            storage.set(bytes);
        }
    }

    /// The layer of child `id`, while it is open.
    pub fn child(&self, id: ChildId) -> Option<&B> {
        self.kids
            .iter()
            .find(|(key, _)| *key == id)
            .map(|(_, kid)| &kid.layer)
    }

    /// The open children, in order.
    pub fn ids(&self) -> impl Iterator<Item = ChildId> + '_ {
        self.kids.iter().map(|(id, _)| *id)
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

    /// One visit to child `id`: its internal work, one event in, one
    /// command out, and credit granted again. Returns whether anything
    /// moved.
    fn visit_child(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        id: ChildId,
    ) -> Result<bool, Overrun> {
        let Some(kid) = self
            .kids
            .iter_mut()
            .find(|(key, _)| *key == id)
            .map(|(_, kid)| kid)
        else {
            return Ok(false);
        };
        let report = move |e| ChildReport::Event(id, e);
        let mut moved = match env.scoped(report, |env| kid.layer.advance(env)) {
            Ok(moved) => moved,
            Err(e) => {
                self.fail(env, id, e);
                return Ok(true);
            }
        };
        if let Some(event) = kid.urgent.take() {
            match env.scoped(report, |env| kid.layer.on_event(env, event)) {
                Ok(Admit::Taken | Admit::Closed(_)) => moved = true,
                Ok(Admit::Blocked(event) | Admit::Partial(event)) => kid.urgent = Some(event),
                Err(e) => {
                    self.fail(env, id, e);
                    return Ok(true);
                }
            }
        }
        if let Some((event, retained)) = kid.inbox.pop_front() {
            let cost = event.credit();
            match env.scoped(report, |env| kid.layer.on_event(env, event)) {
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
                    return Ok(true);
                }
            }
        }
        if kid.outbox.is_none() {
            kid.outbox = kid.layer.take_command();
            moved |= kid.outbox.is_some();
        }
        if let Some(mut command) = kid.outbox.take() {
            if !command.splittable() && command.credit() > kid.max_command {
                let kid = self.remove(id).expect("live child");
                self.down.push_back(kid.handle.close());
                env.report(ChildReport::Refused(id));
                return Ok(true);
            }
            if !command.reserve(env.budget()) {
                return Err(Overrun::Budget);
            }
            if self.down.len() < QUEUE - RESERVE {
                match command.admit_credit(kid.credit) {
                    Ok((prefix, rest)) => {
                        kid.credit -= prefix.credit();
                        self.down.push_back(kid.handle.send(prefix));
                        kid.outbox = rest;
                        moved = true;
                    }
                    Err(command) => kid.outbox = Some(command),
                }
            } else {
                kid.outbox = Some(command);
            }
        }
        kid.owed += kid.released.swap(0, Ordering::Relaxed);
        if kid.owed > 0 && self.down.len() < QUEUE {
            self.down.push_back(kid.handle.grant(kid.owed));
            kid.granted += kid.owed;
            kid.owed = 0;
            moved = true;
        }
        Ok(moved)
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
    type Work = (ChildId, OwnedWork<B::Work>);
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
                let reserved = (self.kids.len() < self.limit && self.make_room())
                    .then(|| {
                        // The inbox grows as events wait in it (`admit`).
                        let storage = env.budget().charge(0)?;
                        let backing = env
                            .budget()
                            .charge(EventOf::<B::Lower>::receive_bytes(self.window)?)?;
                        Some((storage, Arc::new(backing)))
                    })
                    .flatten();
                let Some((storage, backing)) = reserved else {
                    self.down.push_back(child.close());
                    env.report(ChildReport::Refused(id));
                    return Ok(Admit::Taken);
                };
                let layer = (self.make)(id, opening, env.budget());
                assert!(layer.depth() < MAX_DEPTH, "composition depth exceeded");
                let kid = Kid {
                    handle: child,
                    layer,
                    owner: WorkOwner::new(),
                    urgent: None,
                    inbox: VecDeque::new(),
                    storage,
                    released: Arc::new(AtomicU64::new(0)),
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
            }
            MuxEvent::Child(id, mut event) => {
                // Reset ends this lifetime immediately. Notify the child, then
                // discard its refused input, output, credit and work together.
                if event.terminal_reset() {
                    if let Some(mut kid) = self.remove(id) {
                        kid.owner.cancel();
                        if let Err(error) = env.scoped(
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
                if let Some(kid) = self
                    .kids
                    .iter_mut()
                    .find(|(key, _)| *key == id)
                    .map(|(_, kid)| kid)
                {
                    let cost = event.credit();
                    if cost > kid.granted {
                        return Err(Overrun::Credit(id));
                    }
                    if event.urgent() {
                        if kid.urgent.is_some() {
                            return Ok(Admit::Blocked(MuxEvent::Child(id, event)));
                        }
                        kid.urgent = Some(event);
                    } else {
                        if kid.inbox.len() >= QUEUE {
                            return Ok(Admit::Blocked(MuxEvent::Child(id, event)));
                        }
                        if kid.inbox.len() == kid.inbox.capacity() {
                            // Charge the inbox's growth before it grows; a
                            // child the budget cannot hold is refused.
                            let places = (kid.inbox.capacity() * 2).clamp(4, QUEUE);
                            let bytes = places * size_of::<(EventOf<B::Lower>, bool)>();
                            if !kid.storage.set(bytes) {
                                let kid = self.remove(id).expect("live child");
                                kid.owner.cancel();
                                self.down.push_back(kid.handle.close());
                                env.report(ChildReport::Refused(id));
                                return Ok(Admit::Taken);
                            }
                            kid.inbox.reserve_exact(places - kid.inbox.len());
                        }
                        if !event.reserve_receive(env.budget(), &kid.backing) {
                            return Err(Overrun::Budget);
                        }
                        kid.granted -= cost;
                        let retained = if cost > 0 {
                            event.retain_credit(CreditReturn::new(kid.released.clone(), cost))
                        } else {
                            false
                        };
                        kid.inbox.push_back((event, retained));
                    }
                }
            }
            MuxEvent::Credit(id, units) => {
                if let Some(kid) = self
                    .kids
                    .iter_mut()
                    .find(|(key, _)| *key == id)
                    .map(|(_, kid)| kid)
                {
                    kid.credit = kid.credit.saturating_add(units);
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
        self.remaining_visits = 0;
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
        let Some(kid) = self
            .kids
            .iter_mut()
            .find(|(key, _)| *key == id)
            .map(|(_, kid)| kid)
        else {
            return Ok(());
        };
        self.timer_turn = Some(id);
        if let Err(e) = env.scoped(
            move |e| ChildReport::Event(id, e),
            |env| kid.layer.on_timer(env, timer),
        ) {
            self.fail(env, id, e);
        }
        Ok(())
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        (id, done): Self::Done,
    ) -> Result<(), Overrun> {
        let Some(kid) = self
            .kids
            .iter_mut()
            .find(|(key, _)| *key == id)
            .map(|(_, kid)| kid)
        else {
            return Ok(());
        };
        if let Err(e) = env.scoped(
            move |e| ChildReport::Event(id, e),
            |env| kid.layer.on_done(env, done),
        ) {
            self.fail(env, id, e);
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Overrun> {
        // The queues are the router's fixed state: an idle connection holds
        // them from its first step.
        self.reserve(env.budget())?;
        if self.remaining_visits == 0 {
            self.remaining_visits = self.kids.len();
            self.sweep_first = None;
        }
        let count = self.remaining_visits.min(QUEUE);
        let mut last = self.turn;
        let mut moved = false;
        for _ in 0..count {
            let next = self
                .kids
                .iter()
                .map(|(id, _)| *id)
                .find(|id| last.is_none_or(|last| *id > last))
                .or_else(|| self.kids.first().map(|(id, _)| *id));
            let Some(id) = next else {
                break;
            };
            self.sweep_first.get_or_insert(id);
            last = Some(id);
            moved |= self.visit_child(env, id)?;
        }
        self.turn = last;
        self.remaining_visits = self.remaining_visits.saturating_sub(count);
        if self.kids.is_empty() {
            self.remaining_visits = 0;
        }
        if self.remaining_visits == 0 {
            self.turn = self.sweep_first;
        }
        self.release_places();
        Ok(moved || self.remaining_visits > 0)
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
            .and_then(|id| self.kids.iter().position(|(key, _)| *key > id))
            .unwrap_or(0);
        for offset in 0..self.kids.len() {
            let index = (start + offset) % self.kids.len();
            let (id, kid) = &mut self.kids[index];
            if let Some(work) = kid.layer.take_work() {
                self.work_turn = Some(*id);
                return Some((*id, kid.owner.own(work)));
            }
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
        self.kids
            .iter()
            .filter_map(|(id, kid)| kid.layer.deadline().map(|(at, t)| (at, (*id, t))))
            .min_by_key(|(at, (id, _))| (*at, !self.timer_turn.is_none_or(|last| *id > last), *id))
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
    }

    impl Layer for Reader {
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
        assert!(matches!(
            driver
                .deliver(MuxEvent::Child(
                    a,
                    StreamEvent::Data(Chunk::new(Bytes::new()))
                ))
                .unwrap(),
            Admit::Blocked(_)
        ));
        let (first, work) = driver.layer_mut().take_work().unwrap();
        let (second, _) = driver.layer_mut().take_work().unwrap();
        assert_ne!(first, second);
        assert_eq!([first, second], [a, b]);
        assert!(!work.cancelled());
        let _ = driver
            .deliver(MuxEvent::Child(a, StreamEvent::Reset))
            .unwrap();
        assert!(work.cancelled());
        assert_eq!(driver.layer_mut().take_work().unwrap().0, b);
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
