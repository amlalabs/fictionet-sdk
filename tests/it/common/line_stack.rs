//! Line protocols as layer stacks, for the tests of the stack runners and
//! of hosts. An application answers one line at a time and reaches the
//! layer's own entry points through [`Out`]: its writes go down as stream
//! commands, its timers are the layer's deadline, its work goes to the
//! runner as the layer's work, and a handover is a [`Handoff`] that a
//! [`Switch`](fictionet::stdlib::layer::Switch) acts on. [`Lined`] runs one
//! over a byte stream; [`Datagrammed`] runs one over UDP, each datagram's
//! lines on their own.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use fictionet::stdlib::codec::{Decode, Ending, LineError, Lines, Stream};
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Charge, Chunk, Datagram, DatagramCommand, DatagramEvent, Datagrams,
    Env, Handoff, Handover, Layer, StreamCommand, StreamEvent, Timers, Top,
};
use fictionet::stdlib::network::{ConnInfo, tcp};
use fictionet::stdlib::services::stack::{self, Job, StreamLimits};
use fictionet::time::Instant;
use fictionet::{Cx, Entropy};

/// How many lines one `advance` hands the application.
const LINES_PER_ADVANCE: usize = 64;

/// What the application can do from any of its calls.
pub(crate) struct Out<'a, T, W, N> {
    now: Instant,
    entropy: &'a dyn Entropy,
    budget: &'a Budget,
    writes: &'a mut VecDeque<Chunk>,
    over_budget: &'a mut bool,
    timers: &'a mut Timers<T>,
    work: &'a mut VecDeque<W>,
    close: &'a mut bool,
    holding: &'a mut bool,
    next: &'a mut Option<N>,
}

impl<T: Clone + Eq, W, N> Out<'_, T, W, N> {
    /// Sends `bytes` after what was sent before. They are charged to the
    /// stack's budget until the transport takes them; a write the budget
    /// has no room for ends the connection.
    pub(crate) fn write(&mut self, bytes: &[u8]) {
        match self.budget.charge(bytes.len()) {
            Some(charge) => self
                .writes
                .push_back(Chunk::with_charge(bytes.to_vec(), charge)),
            None => *self.over_budget = true,
        }
    }

    /// Ends the connection once what was written is sent: no more input
    /// is read.
    pub(crate) fn close(&mut self) {
        *self.close = true;
    }

    /// Arms `timer` to go off `after` from now.
    pub(crate) fn set_timer(&mut self, timer: T, after: Duration) {
        self.timers.set(timer, self.now + after);
    }

    /// Disarms `timer`.
    pub(crate) fn cancel_timer(&mut self, timer: T) {
        self.timers.cancel(&timer);
    }

    /// Hands `work` to whatever runs the stack; its result comes back to
    /// [`LineApp::done`].
    pub(crate) fn start(&mut self, work: W) {
        self.work.push_back(work);
    }

    /// The same, and reads no more lines until the work is done, so what
    /// it brings back is answered in order.
    pub(crate) fn start_in_order(&mut self, work: W) {
        self.work.push_back(work);
        *self.holding = true;
    }

    /// Stops reading lines: once what was written is sent, the stack hands
    /// the rest of the input to `next`.
    pub(crate) fn hand_over(&mut self, next: N) {
        *self.next = Some(next);
    }

    /// A number from the stack's entropy.
    pub(crate) fn random_u64(&self) -> u64 {
        self.entropy.random_u64()
    }
}

/// The calls a line application gets from [`Lined`].
pub(crate) type LineOut<'a, A> =
    Out<'a, <A as LineApp>::Timer, <A as LineApp>::Work, <A as LineApp>::Next>;

/// A server that reads lines.
pub(crate) trait LineApp: Send + 'static {
    /// Its timer names.
    type Timer: Clone + Eq + Send + 'static;
    /// The work it hands the runner.
    type Work: Send + 'static;
    /// What that work brings back.
    type Done;
    /// What it hands the rest of the input to.
    type Next;
    /// Why it gives up on a connection.
    type Error;

    /// The longest line it reads, without the line ending.
    fn max_line(&self) -> usize {
        64
    }

    /// The connection opened.
    fn open(&mut self, _out: &mut LineOut<'_, Self>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The next line, or a line past [`max_line`](Self::max_line).
    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        out: &mut LineOut<'_, Self>,
    ) -> Result<(), Self::Error>;

    /// `timer` went off.
    fn timer(
        &mut self,
        _timer: Self::Timer,
        _out: &mut LineOut<'_, Self>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Work it started finished.
    fn done(&mut self, _done: Self::Done, _out: &mut LineOut<'_, Self>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// The peer sent everything; the connection closes after this call's
    /// writes.
    fn ended(&mut self, _out: &mut LineOut<'_, Self>) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Why a line stack gave up on its connection.
#[derive(Debug)]
pub(crate) enum LinedError<E> {
    /// The application gave up.
    App(E),
    /// The budget had no room for the line buffer or a write.
    Budget,
}

impl<E: fmt::Display> fmt::Display for LinedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinedError::App(e) => e.fmt(f),
            LinedError::Budget => f.write_str("no room in the budget"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LinedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LinedError::App(e) => Some(e),
            LinedError::Budget => None,
        }
    }
}

/// A line application over a byte stream. The line buffer, as it may
/// grow, is charged to the stack's budget before anything is read or
/// written.
pub(crate) struct Lined<A: LineApp> {
    app: A,
    stream: Stream<Lines>,
    charge: Option<Charge>,
    opened: bool,
    writes: VecDeque<Chunk>,
    timers: Timers<A::Timer>,
    work: VecDeque<A::Work>,
    close: bool,
    /// The application waits for its work before it reads on.
    holding: bool,
    next: Option<A::Next>,
    /// The peer ended its direction.
    peer_ended: bool,
    /// The application heard that.
    ended_heard: bool,
    end_sent: bool,
    reset: bool,
}

impl<A: LineApp> Lined<A> {
    pub(crate) fn new(app: A) -> Lined<A> {
        let stream = Stream::new(Lines::new(app.max_line(), Ending::LfOrCrlf));
        Lined {
            app,
            stream,
            charge: None,
            opened: false,
            writes: VecDeque::new(),
            timers: Timers::new(),
            work: VecDeque::new(),
            close: false,
            holding: false,
            next: None,
            peer_ended: false,
            ended_heard: false,
            end_sent: false,
            reset: false,
        }
    }

    /// The application.
    pub(crate) fn app(&self) -> &A {
        &self.app
    }

    /// When `timer` goes off, if it is armed.
    pub(crate) fn timer(&self, timer: &A::Timer) -> Option<Instant> {
        self.timers.get(timer)
    }

    fn call(
        &mut self,
        env: &Env<'_, Infallible>,
        f: impl FnOnce(&mut A, &mut LineOut<'_, A>) -> Result<(), A::Error>,
    ) -> Result<(), LinedError<A::Error>> {
        let mut over_budget = false;
        let mut out = Out {
            now: env.now(),
            entropy: env.entropy(),
            budget: env.budget(),
            writes: &mut self.writes,
            over_budget: &mut over_budget,
            timers: &mut self.timers,
            work: &mut self.work,
            close: &mut self.close,
            holding: &mut self.holding,
            next: &mut self.next,
        };
        f(&mut self.app, &mut out).map_err(LinedError::App)?;
        if over_budget {
            return Err(LinedError::Budget);
        }
        Ok(())
    }

    /// Whether lines may still go to the application.
    fn reading(&self) -> bool {
        !self.close && !self.holding && self.next.is_none() && !self.reset
    }
}

impl<A: LineApp> Layer for Lined<A> {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = A::Timer;
    type Work = A::Work;
    type Done = A::Done;
    type Error = LinedError<A::Error>;

    fn is_terminal(&self) -> bool {
        self.reset || (self.end_sent && (self.close || self.peer_ended))
    }

    fn on_event(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Self::Error> {
        match event {
            StreamEvent::Written(_) => Ok(Admit::Taken),
            StreamEvent::Reset => {
                self.reset = true;
                self.writes.clear();
                self.work.clear();
                Ok(Admit::Taken)
            }
            event if !self.opened => Ok(Admit::Blocked(event)),
            event if self.next.is_some() => Ok(Admit::Blocked(event)),
            event if self.close || self.peer_ended => Ok(Admit::Closed(event)),
            StreamEvent::Data(mut chunk) => {
                let took = self.stream.push(&chunk);
                if took == chunk.len() {
                    return Ok(Admit::Taken);
                }
                if took == 0 {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                chunk.advance(took);
                Ok(Admit::Partial(StreamEvent::Data(chunk)))
            }
            StreamEvent::Ended => {
                self.peer_ended = true;
                self.stream.end();
                Ok(Admit::Taken)
            }
        }
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Self::Error> {
        match command {}
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Infallible>,
        timer: A::Timer,
    ) -> Result<bool, Self::Error> {
        if !self.timers.fire(&timer, env.now()) {
            return Ok(false);
        }
        if !self.reset {
            self.call(env, |app, out| app.timer(timer, out))?;
        }
        Ok(true)
    }

    fn on_done(&mut self, env: &mut Env<'_, Infallible>, done: A::Done) -> Result<(), Self::Error> {
        if self.reset {
            return Ok(());
        }
        self.holding = false;
        self.call(env, |app, out| app.done(done, out))
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Self::Error> {
        if self.reset {
            return Ok(false);
        }
        let mut moved = false;
        if !self.opened {
            // The buffer keeps a consumed prefix until it is as long as
            // what is left, so it grows to twice its limit.
            let limit = self
                .stream
                .limit()
                .max(Decode::capacity(self.stream.decoder()));
            let charge = env.budget().charge(limit * 2).ok_or(LinedError::Budget)?;
            self.charge = Some(charge);
            self.opened = true;
            self.call(env, |app, out| app.open(out))?;
            moved = true;
        }
        for _ in 0..LINES_PER_ADVANCE {
            // A due timer goes before the next line: the driver fires it
            // before it advances the stack again. A reply goes below before
            // the next line is read.
            let due = self.timers.next().is_some_and(|(at, _)| at <= env.now());
            if !self.reading() || due || !self.writes.is_empty() {
                break;
            }
            let Some(item) = self.stream.next() else {
                break;
            };
            let line = match item {
                Ok(line) => line,
                Err(fail) => unreachable!("lines never fail: {fail:?}"),
            };
            self.call(env, |app, out| app.line(line, out))?;
            moved = true;
        }
        if self.peer_ended && !self.ended_heard && self.reading() && self.stream.is_done() {
            self.ended_heard = true;
            self.call(env, |app, out| app.ended(out))?;
            self.close = true;
            moved = true;
        }
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        if self.reset {
            return None;
        }
        if let Some(chunk) = self.writes.pop_front() {
            return Some(StreamCommand::Write(chunk));
        }
        if self.close && !self.end_sent {
            self.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn take_work(&mut self) -> Option<A::Work> {
        self.work.pop_front()
    }

    fn deadline(&self) -> Option<(Instant, A::Timer)> {
        self.timers.next()
    }
}

impl<A: LineApp> Handoff for Lined<A> {
    type Next = A::Next;

    fn handover(&mut self) -> Option<Handover<A::Next, ByteStream, Top>> {
        if !self.writes.is_empty() {
            return None;
        }
        let next = self.next.take()?;
        let mut below = Vec::new();
        if !self.stream.unread().is_empty() {
            below.push(StreamEvent::Data(Chunk::new(self.stream.unread().to_vec())));
        }
        if self.peer_ended {
            below.push(StreamEvent::Ended);
        }
        Some(Handover {
            next,
            below,
            above: Vec::new(),
        })
    }
}

/// Serves every connection `listener` accepts with the stack `make`
/// gives, each run by [`stack::stream`] in a task of its own with
/// `limits`, numbered from 1, as a host's port does.
pub(crate) fn listen<L, M>(fcx: &Cx, mut listener: tcp::Listener, limits: StreamLimits, make: M)
where
    L: Layer<Lower = ByteStream, Upper = Top> + Send + 'static,
    L::Work: Job<Done = L::Done>,
    L::Report: Send,
    L::Done: Send,
    L::Error: Send,
    M: Fn() -> L + Send + Sync + 'static,
{
    fcx.spawn(move |fcx| async move {
        let mut id = 0;
        while let Ok(conn) = listener.accept(&fcx).await {
            id += 1;
            let info = ConnInfo::new(id, conn.local_addr(), conn.peer_addr());
            let layer = make();
            fcx.spawn(move |fcx| async move {
                let budget = Budget::unlimited();
                let _ = stack::stream(&fcx, conn, &info, layer, budget, limits, |_| {}).await;
                Ok(())
            });
        }
        Ok(())
    });
}

/// What a datagram application can do: send datagrams, and arm timers.
pub(crate) struct Sends<'a, T> {
    now: Instant,
    local: Option<SocketAddr>,
    sends: &'a mut VecDeque<(Vec<u8>, SocketAddr)>,
    timers: &'a mut Timers<T>,
}

impl<T: Clone + Eq> Sends<'_, T> {
    /// Sends `bytes` to `to`.
    pub(crate) fn send_to(&mut self, to: SocketAddr, bytes: Vec<u8>) {
        self.sends.push_back((bytes, to));
    }

    /// Arms `timer` to go off `after` from now.
    pub(crate) fn set_timer(&mut self, timer: T, after: Duration) {
        self.timers.set(timer, self.now + after);
    }

    /// The socket's own address, if the stack was told it.
    pub(crate) fn local(&self) -> Option<SocketAddr> {
        self.local
    }
}

/// A server that reads the lines of each datagram on their own.
pub(crate) trait DatagramApp: Send + 'static {
    /// Its timer names.
    type Timer: Clone + Eq + Send + 'static;

    /// The socket opened.
    fn open(&mut self, _sends: &mut Sends<'_, Self::Timer>) {}

    /// The next line of a datagram from `from`.
    fn line(
        &mut self,
        line: Result<Vec<u8>, LineError>,
        from: SocketAddr,
        sends: &mut Sends<'_, Self::Timer>,
    );

    /// `timer` went off.
    fn timer(&mut self, _timer: Self::Timer, _sends: &mut Sends<'_, Self::Timer>) {}

    /// Every line of a datagram from `from` was read.
    fn finished(&mut self, _from: SocketAddr, _sends: &mut Sends<'_, Self::Timer>) {}
}

/// A line application over datagrams. Each datagram's lines are read with
/// a fresh reader, and an answer goes back to the datagram's sender only
/// when the application sends it.
pub(crate) struct Datagrammed<A: DatagramApp> {
    app: A,
    local: Option<SocketAddr>,
    opened: bool,
    sends: VecDeque<(Vec<u8>, SocketAddr)>,
    timers: Timers<A::Timer>,
    ended: bool,
}

impl<A: DatagramApp> Datagrammed<A> {
    /// Runs `app` on a socket at `local`, if known.
    pub(crate) fn new(app: A, local: Option<SocketAddr>) -> Datagrammed<A> {
        Datagrammed {
            app,
            local,
            opened: false,
            sends: VecDeque::new(),
            timers: Timers::new(),
            ended: false,
        }
    }

    fn call(&mut self, now: Instant, f: impl FnOnce(&mut A, &mut Sends<'_, A::Timer>)) {
        let mut sends = Sends {
            now,
            local: self.local,
            sends: &mut self.sends,
            timers: &mut self.timers,
        };
        f(&mut self.app, &mut sends);
    }
}

impl<A: DatagramApp> Layer for Datagrammed<A> {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Top;
    type Report = Infallible;
    type Timer = A::Timer;
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: DatagramEvent<SocketAddr>,
    ) -> Result<Admit<DatagramEvent<SocketAddr>>, Infallible> {
        let datagram = match event {
            event if !self.opened => return Ok(Admit::Blocked(event)),
            DatagramEvent::Datagram(d) => d,
            DatagramEvent::Ended => {
                self.ended = true;
                return Ok(Admit::Taken);
            }
        };
        let from = *datagram.meta();
        let mut lines = Stream::new(Lines::new(64, Ending::LfOrCrlf));
        let _ = lines.push(datagram.payload());
        lines.end();
        while let Some(item) = lines.next() {
            let line = match item {
                Ok(line) => line,
                Err(fail) => unreachable!("lines never fail: {fail:?}"),
            };
            self.call(env.now(), |app, sends| app.line(line, from, sends));
        }
        self.call(env.now(), |app, sends| app.finished(from, sends));
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Infallible>,
        timer: A::Timer,
    ) -> Result<bool, Infallible> {
        let fired = self.timers.fire(&timer, env.now());
        if fired {
            self.call(env.now(), |app, sends| app.timer(timer, sends));
        }
        Ok(fired)
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        if self.opened {
            return Ok(false);
        }
        self.opened = true;
        self.call(env.now(), |app, sends| app.open(sends));
        Ok(true)
    }

    fn take_command(
        &mut self,
        _: &mut Env<'_, Self::Report>,
    ) -> Option<DatagramCommand<SocketAddr>> {
        let (bytes, to) = self.sends.pop_front()?;
        Some(DatagramCommand::Send(Datagram::new(Chunk::new(bytes), to)))
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn deadline(&self) -> Option<(Instant, A::Timer)> {
        if self.ended {
            return None;
        }
        self.timers.next()
    }
}
