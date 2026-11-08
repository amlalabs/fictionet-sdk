use std::collections::{BTreeMap, VecDeque};
use std::ops::Bound;

use fictionet::stdlib::layer::{
    Admit, Child, ChildId, CommandOf, Credited, Env, EventOf, Layer, Mux, MuxCommand, MuxEvent,
    Port, Top,
};
use fictionet::time::Instant;

/// How many commands wait for the mux, and how many of those places only
/// connection control and credit may use.
const QUEUE: usize = 64;
const RESERVE: usize = 8;

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
/// Every child gets `window` credit units for its events, granted again as
/// its layer takes them, so a child that stops reading holds at most
/// `window` units and nothing else. A child's commands wait in a place of
/// their own until the mux grants credit for them, so a child the peer does
/// not read holds up nothing but itself. Children are visited in a stable
/// order that starts one further on each time.
pub struct Children<B, K>
where
    B: Layer<Upper = Top>,
    EventOf<B::Lower>: Credited,
    CommandOf<B::Lower>: Credited,
    K: Port,
{
    make: Box<dyn FnMut() -> B + Send>,
    kids: BTreeMap<ChildId, Kid<B>>,
    limit: usize,
    window: u64,
    down: VecDeque<MuxCommand<B::Lower, K>>,
    up: VecDeque<EventOf<K>>,
    /// The child visited first last time.
    turn: Option<ChildId>,
    visit: Vec<ChildId>,
}

struct Kid<B: Layer> {
    handle: Child,
    layer: B,
    /// Events the mux sent within credit that the layer has not taken.
    inbox: VecDeque<EventOf<B::Lower>>,
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
    /// A child opened when the limit was reached. It was closed at once.
    Refused(ChildId),
}

/// The mux sent a child more than the credit granted for it: a broken mux,
/// so the whole connection stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overrun(pub ChildId);

impl core::fmt::Display for Overrun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the mux sent a child more than its credit")
    }
}

impl core::error::Error for Overrun {}

impl<B, K> Children<B, K>
where
    B: Layer<Upper = Top>,
    EventOf<B::Lower>: Credited,
    CommandOf<B::Lower>: Credited,
    K: Port,
{
    /// At most `limit` children at once, each with `window` credit units for
    /// its events and a layer from `make`.
    pub fn new(limit: usize, window: u64, make: impl FnMut() -> B + Send + 'static) -> Self {
        Children {
            make: Box::new(make),
            kids: BTreeMap::new(),
            limit,
            window,
            down: VecDeque::new(),
            up: VecDeque::new(),
            turn: None,
            visit: Vec::new(),
        }
    }

    /// The layer of child `id`, while it is open.
    pub fn child(&self, id: ChildId) -> Option<&B> {
        self.kids.get(&id).map(|kid| &kid.layer)
    }

    /// The open children, in order.
    pub fn ids(&self) -> impl Iterator<Item = ChildId> + '_ {
        self.kids.keys().copied()
    }

    /// Closes a failed child and reports it.
    fn fail(
        &mut self,
        env: &mut Env<'_, ChildReport<B::Report, B::Error>>,
        id: ChildId,
        error: B::Error,
    ) {
        if let Some(kid) = self.kids.remove(&id) {
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
    ) -> bool {
        let Some(kid) = self.kids.get_mut(&id) else {
            return false;
        };
        let report = move |e| ChildReport::Event(id, e);
        let mut moved = match env.scoped(report, |env| kid.layer.advance(env)) {
            Ok(moved) => moved,
            Err(e) => {
                self.fail(env, id, e);
                return true;
            }
        };
        if let Some(event) = kid.inbox.pop_front() {
            let cost = event.credit();
            match env.scoped(report, |env| kid.layer.on_event(env, event)) {
                Ok(Admit::Taken | Admit::Closed(_)) => {
                    kid.owed += cost;
                    moved = true;
                }
                Ok(Admit::Partial(rest)) => {
                    kid.owed += cost - rest.credit().min(cost);
                    kid.inbox.push_front(rest);
                    moved = true;
                }
                Ok(Admit::Blocked(event)) => kid.inbox.push_front(event),
                Err(e) => {
                    self.fail(env, id, e);
                    return true;
                }
            }
        }
        if kid.outbox.is_none() {
            kid.outbox = kid.layer.take_command();
            moved |= kid.outbox.is_some();
        }
        if let Some(command) = kid.outbox.take() {
            let cost = command.credit();
            if cost <= kid.credit && self.down.len() < QUEUE - RESERVE {
                kid.credit -= cost;
                self.down.push_back(kid.handle.send(command));
                moved = true;
            } else {
                kid.outbox = Some(command);
            }
        }
        if kid.owed > 0 && self.down.len() < QUEUE {
            self.down.push_back(kid.handle.grant(kid.owed));
            kid.granted += kid.owed;
            kid.owed = 0;
            moved = true;
        }
        moved
    }
}

impl<B, K> Layer for Children<B, K>
where
    B: Layer<Upper = Top>,
    EventOf<B::Lower>: Credited,
    CommandOf<B::Lower>: Credited,
    K: Port,
{
    type Lower = Mux<B::Lower, K>;
    type Upper = K;
    type Report = ChildReport<B::Report, B::Error>;
    type Timer = (ChildId, B::Timer);
    type Work = (ChildId, B::Work);
    type Done = (ChildId, B::Done);
    type Error = Overrun;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: MuxEvent<B::Lower, K>,
    ) -> Result<Admit<MuxEvent<B::Lower, K>>, Overrun> {
        match event {
            MuxEvent::Opened(child) => {
                let id = child.id();
                if self.kids.len() >= self.limit {
                    self.down.push_back(child.close());
                    env.report(ChildReport::Refused(id));
                    return Ok(Admit::Taken);
                }
                let kid = Kid {
                    handle: child,
                    layer: (self.make)(),
                    inbox: VecDeque::new(),
                    granted: 0,
                    owed: self.window,
                    credit: 0,
                    outbox: None,
                };
                self.kids.insert(id, kid);
            }
            MuxEvent::Child(id, event) => {
                // A child already gone has nothing to deliver to.
                if let Some(kid) = self.kids.get_mut(&id) {
                    let cost = event.credit();
                    if cost > kid.granted {
                        return Err(Overrun(id));
                    }
                    kid.granted -= cost;
                    kid.inbox.push_back(event);
                }
            }
            MuxEvent::Credit(id, units) => {
                if let Some(kid) = self.kids.get_mut(&id) {
                    kid.credit = kid.credit.saturating_add(units);
                }
            }
            MuxEvent::Closed(id) => {
                self.kids.remove(&id);
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
        _env: &mut Env<'_, Self::Report>,
        command: CommandOf<K>,
    ) -> Result<Admit<CommandOf<K>>, Overrun> {
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
        let Some(kid) = self.kids.get_mut(&id) else {
            return Ok(());
        };
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
        let Some(kid) = self.kids.get_mut(&id) else {
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
        let mut visit = std::mem::take(&mut self.visit);
        visit.clear();
        match self.turn {
            Some(turn) => {
                let after = (Bound::Excluded(turn), Bound::Unbounded);
                visit.extend(self.kids.range(after).map(|(id, _)| *id));
                visit.extend(self.kids.range(..=turn).map(|(id, _)| *id));
            }
            None => visit.extend(self.kids.keys().copied()),
        }
        self.turn = visit.first().copied();
        let mut moved = false;
        for id in &visit {
            moved |= self.visit_child(env, *id);
        }
        self.visit = visit;
        Ok(moved)
    }

    fn take_command(&mut self) -> Option<MuxCommand<B::Lower, K>> {
        self.down.pop_front()
    }

    fn take_event(&mut self) -> Option<EventOf<K>> {
        self.up.pop_front()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        self.kids
            .iter_mut()
            .find_map(|(id, kid)| kid.layer.take_work().map(|work| (*id, work)))
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        self.kids
            .iter()
            .filter_map(|(id, kid)| kid.layer.deadline().map(|(at, t)| (at, (*id, t))))
            .min_by_key(|(at, _)| *at)
    }
}
