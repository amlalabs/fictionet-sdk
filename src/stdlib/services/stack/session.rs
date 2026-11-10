use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};

use fictionet::Cx;
use fictionet::stdlib::layer::{Admit, ByteStream, Env, Layer, StreamCommand, StreamEvent, Top};
use fictionet::time::Instant;

use super::lifetime::{Expiry, Lifetime, Outstanding};
use super::{Job, StreamLimits};

/// Stream lifetime and timeouts for an application on a transport child.
/// The transport remains responsible for closing and retiring its socket.
pub struct Session<L> {
    layer: L,
    lifetime: Lifetime,
    now: Instant,
    /// Bytes handed below that the application has not heard were written.
    pending: u64,
    /// The application refused the input it was last offered.
    refused: bool,
    reset: bool,
    event: Option<StreamEvent>,
    command: Option<StreamCommand>,
    jobs: Arc<AtomicUsize>,
    /// The budget refused a charge the application made, and it has not
    /// moved since: it waits for memory, which is not waiting for the peer.
    memory: bool,
}

impl<L: Layer> Session<L> {
    /// Applies the stream adapter's idle and stalled-write policy: one
    /// policy decides for both. When a write stalls past its limit the
    /// application hears a reset and the session asks the transport for
    /// one, where the adapter ends its run.
    pub fn new(layer: L, limits: StreamLimits, now: Instant) -> Self {
        Self {
            layer,
            lifetime: Lifetime::new(limits),
            now,
            pending: 0,
            refused: false,
            reset: false,
            event: None,
            command: None,
            jobs: Arc::new(AtomicUsize::new(0)),
            memory: false,
        }
    }
}

impl<L: Layer> Session<L> {
    /// What is under way. The application waits for memory when a charge
    /// of its was refused, or when a part of it waits on a budget view of
    /// its own (a child of [`Children`](fictionet::stdlib::layer::Children)).
    fn outstanding(&self) -> Outstanding {
        Outstanding {
            output: self.pending > 0,
            input: self.refused || self.event.is_some(),
            work: self.jobs.load(Ordering::Relaxed) > 0,
            memory: self.memory || self.layer.waits_for_memory(),
        }
    }

    /// Calls the application, as a part of the session, and notes whether
    /// the budget refused a charge it made in the call. A refusal has the
    /// session wait for memory; a call that `moved` without one ends the
    /// wait. So does an [`advance`](Layer::advance) without one, since a
    /// layer tries a refused charge again there.
    fn part<R, T, E>(
        &mut self,
        env: &mut Env<'_, R>,
        call: impl FnOnce(&mut L, &mut Env<'_, R>) -> Result<T, E>,
        moved: impl FnOnce(&T) -> bool,
    ) -> Result<T, E> {
        let since = env.budget().refusals();
        let layer = &mut self.layer;
        let result = env.part(|env| call(layer, env))?;
        if env.budget().refused_since(since) {
            self.memory = true;
        } else if moved(&result) {
            self.memory = false;
        }
        Ok(result)
    }

    fn settle(&mut self) {
        self.lifetime.settle(self.now, self.outstanding());
    }
}

/// A session timer or one belonging to the application.
#[derive(Clone, PartialEq, Eq)]
pub enum SessionTimer<T> {
    /// The application's timer.
    Application(T),
    /// No input or work arrived during the idle interval.
    Idle,
    /// A write made no progress before its deadline.
    Write,
}

/// Application work whose lifetime suspends the session's idle timer.
pub struct SessionWork<W> {
    work: W,
    active: Option<Arc<AtomicUsize>>,
}

impl<W> Drop for SessionWork<W> {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl<W: Job> Job for SessionWork<W> {
    type Done = W::Done;
    fn cancelled(&self) -> bool {
        self.work.cancelled()
    }
    fn poll(&mut self, fcx: Option<&Cx>, cx: &mut Context<'_>) -> Poll<W::Done> {
        let result = self.work.poll(fcx, cx);
        if result.is_ready()
            && let Some(active) = self.active.take()
        {
            active.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }
}

impl<L> Layer for Session<L>
where
    L: Layer<Lower = ByteStream, Upper = Top>,
    L::Work: Job<Done = L::Done>,
{
    type Lower = ByteStream;
    type Upper = Top;
    type Report = L::Report;
    type Timer = SessionTimer<L::Timer>;
    type Work = SessionWork<L::Work>;
    type Done = L::Done;
    type Error = L::Error;
    fn report_bytes(report: &Self::Report) -> Option<usize> {
        L::report_bytes(report)
    }
    fn depth(&self) -> usize {
        1 + self.layer.depth()
    }
    fn waits_for_memory(&self) -> bool {
        self.layer.waits_for_memory()
    }
    fn is_terminal(&self) -> bool {
        self.reset
            || (self.command.is_none()
                && self
                    .lifetime
                    .finished(self.layer.is_terminal(), self.outstanding()))
    }
    fn on_event(
        &mut self,
        env: &mut Env<'_, L::Report>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, L::Error> {
        if matches!(event, StreamEvent::Reset) {
            self.event = None;
        }
        // A refused idle EOF may be waiting for a final write to complete.
        // Completions and reset must pass it, just as they pass refused data.
        if self.event.is_some() && !matches!(event, StreamEvent::Written(_)) {
            return Ok(Admit::Blocked(event));
        }
        let (ended, reset, written, input) = match &event {
            StreamEvent::ReceiveReset(error) | StreamEvent::SendStopped(error) => match *error {},
            StreamEvent::Ended => (true, false, 0, true),
            StreamEvent::Reset => (true, true, 0, false),
            StreamEvent::Written(n) => (false, false, *n, false),
            StreamEvent::Data(_) => (false, false, 0, true),
        };
        let admitted = self.part(
            env,
            |layer, env| layer.on_event(env, event),
            |admitted| admitted.moved() || matches!(admitted, Admit::Closed(_)),
        )?;
        self.now = env.now();
        let closed = matches!(&admitted, Admit::Closed(_));
        if input {
            self.refused = matches!(&admitted, Admit::Blocked(_) | Admit::Partial(_));
        }
        if closed {
            self.lifetime.end_input();
        }
        if admitted.moved() || closed {
            if ended {
                self.lifetime.end_input();
            }
            self.reset |= reset;
            if input {
                self.lifetime.took_input();
            }
            if written > 0 {
                self.lifetime.wrote();
            }
            self.pending = self.pending.saturating_sub(written);
        }
        self.settle();
        Ok(admitted)
    }
    fn on_command(
        &mut self,
        _: &mut Env<'_, L::Report>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, L::Error> {
        match command {}
    }
    fn on_timer(
        &mut self,
        env: &mut Env<'_, L::Report>,
        timer: Self::Timer,
    ) -> Result<bool, L::Error> {
        match timer {
            SessionTimer::Application(timer) => {
                let worked = self.part(env, |layer, env| layer.on_timer(env, timer), |w| *w)?;
                self.now = env.now();
                self.settle();
                Ok(worked)
            }
            SessionTimer::Idle => {
                self.lifetime.expire(Expiry::Idle);
                self.event = Some(StreamEvent::Ended);
                self.settle();
                Ok(true)
            }
            SessionTimer::Write => {
                self.lifetime.expire(Expiry::Stalled);
                self.reset = true;
                self.command = Some(StreamCommand::Reset);
                let _ = self.part(
                    env,
                    |layer, env| layer.on_event(env, StreamEvent::Reset),
                    |_| true,
                )?;
                Ok(true)
            }
        }
    }
    fn on_done(&mut self, env: &mut Env<'_, L::Report>, done: L::Done) -> Result<(), L::Error> {
        // The application heard its work finish: that moved it.
        self.part(env, |layer, env| layer.on_done(env, done), |_| true)?;
        self.now = env.now();
        self.settle();
        Ok(())
    }
    fn advance(&mut self, env: &mut Env<'_, L::Report>) -> Result<bool, L::Error> {
        self.now = env.now();
        let mut moved = false;
        if let Some(event) = self.event.take() {
            match self.part(
                env,
                |layer, env| layer.on_event(env, event),
                |admitted| !matches!(admitted, Admit::Blocked(_)),
            )? {
                Admit::Blocked(event) | Admit::Partial(event) => self.event = Some(event),
                _ => {
                    // The idle EOF is in: the input is over.
                    self.lifetime.end_input();
                    moved = true;
                }
            }
        }
        // The layer tries a refused charge again here (rule 9): an advance
        // without a refusal ends the wait for memory.
        moved |= self.part(env, |layer, env| layer.advance(env), |_| true)?;
        self.settle();
        Ok(moved)
    }
    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        let taken = match self.command.take() {
            Some(command) => Some(command),
            None => self
                .part(
                    env,
                    |layer, env| Ok::<_, Infallible>(layer.take_command(env)),
                    Option::is_some,
                )
                .unwrap_or_else(|never| match never {}),
        };
        let Some(command) = taken else {
            // A command the application could not pay for waits for memory.
            self.now = env.now();
            self.settle();
            return None;
        };
        match &command {
            StreamCommand::ResetSend(error) | StreamCommand::StopReceive(error) => match *error {},
            StreamCommand::Write(bytes) => {
                self.now = env.now();
                self.pending = self.pending.saturating_add(bytes.len() as u64);
                self.settle();
            }
            StreamCommand::End => self.lifetime.end_output(),
            StreamCommand::Reset => self.reset = true,
        }
        Some(command)
    }
    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
    fn take_work(&mut self) -> Option<Self::Work> {
        let work = self.layer.take_work()?;
        self.jobs.fetch_add(1, Ordering::Relaxed);
        self.settle();
        Some(SessionWork {
            work,
            active: Some(self.jobs.clone()),
        })
    }
    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        let application = self
            .layer
            .deadline()
            .map(|(at, timer)| (at, SessionTimer::Application(timer)));
        let lifetime = self.lifetime.deadline().map(|(at, expiry)| {
            let timer = match expiry {
                Expiry::Idle => SessionTimer::Idle,
                Expiry::Stalled => SessionTimer::Write,
            };
            (at, timer)
        });
        [application, lifetime]
            .into_iter()
            .flatten()
            .min_by_key(|(at, _)| *at)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::layer::{Budget, Charge, Chunk, Harness};
    use std::time::Duration;

    #[derive(Default)]
    struct Flush {
        write: Option<StreamCommand>,
        started: bool,
        written: bool,
        ended: bool,
    }
    impl Layer for Flush {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            match event {
                StreamEvent::Ended if !self.written => {
                    if !self.started {
                        self.write = Some(StreamCommand::Write(Chunk::unpaid(b"last".to_vec())));
                        self.started = true;
                    }
                    return Ok(Admit::Blocked(StreamEvent::Ended));
                }
                StreamEvent::Written(4) => self.written = true,
                StreamEvent::Ended => {
                    self.ended = true;
                    self.write = Some(StreamCommand::End);
                }
                StreamEvent::Reset => panic!("a writable stream must finish without reset"),
                _ => {}
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            self.write.take()
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
        fn is_terminal(&self) -> bool {
            self.ended
        }
    }

    #[test]
    fn write_completion_passes_an_idle_eof_waiting_for_a_flush() {
        let mut session = Harness::new(
            Seed::from_u64(1),
            Session::new(
                Flush::default(),
                StreamLimits {
                    idle: Some(Duration::from_millis(1)),
                    write_timeout: Some(Duration::from_millis(10)),
                },
                Instant::ZERO,
            ),
        );
        session.settle().unwrap();
        session.advance(Duration::from_millis(1)).unwrap();
        assert_eq!(session.take_output(), b"last");
        assert!(session.ended());
        assert!(session.layer().is_terminal());
    }

    /// Takes the first bytes, then refuses input until its own timer goes
    /// off `pause` later. Notes when its input ended.
    struct Refuses {
        pause: Duration,
        until: Option<Instant>,
        took_first: bool,
        input_ended: Option<Instant>,
    }
    impl Layer for Refuses {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;
        fn on_event(
            &mut self,
            env: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            match event {
                StreamEvent::Data(_) if self.until.is_some() => return Ok(Admit::Blocked(event)),
                StreamEvent::Data(_) if !self.took_first => {
                    self.took_first = true;
                    self.until = Some(env.now() + self.pause);
                }
                StreamEvent::Ended => self.input_ended = Some(env.now()),
                _ => {}
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn on_timer(&mut self, _: &mut Env<'_, Infallible>, _: ()) -> Result<bool, Infallible> {
            self.until = None;
            Ok(true)
        }
        fn deadline(&self) -> Option<(Instant, ())> {
            self.until.map(|at| (at, ()))
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    /// The idle limit counts only time spent waiting for the peer. Bytes the
    /// application refuses are not waiting on the peer, so the idle clock
    /// starts only once the application takes them, as it does over a
    /// connection (`the_idle_clock_restarts_when_the_stack_takes_input_again`).
    #[test]
    fn the_idle_clock_waits_while_the_application_refuses_input() {
        let idle = Duration::from_millis(300);
        let pause = Duration::from_millis(1_000);
        let mut session = Harness::new(
            Seed::from_u64(1),
            Session::new(
                Refuses {
                    pause,
                    until: None,
                    took_first: false,
                    input_ended: None,
                },
                StreamLimits {
                    idle: Some(idle),
                    write_timeout: None,
                },
                Instant::ZERO,
            ),
        );
        session.push(b"a").unwrap();
        session.push(b"b").unwrap();
        assert_eq!(
            session.unread(),
            1,
            "the application refuses the second byte"
        );
        session.advance(Duration::from_secs(5)).unwrap();
        let ended = session.layer().layer.input_ended.expect("input ended");
        assert!(
            ended.since_start() >= pause + idle,
            "input ended at {:?}, within the idle limit of the application taking input again",
            ended.since_start()
        );
    }

    /// Asks the budget for `want` bytes on each advance until it gets them
    /// (rule 9). Notes when its input ended.
    struct Hungry {
        want: usize,
        held: Option<Charge>,
        input_ended: Option<Instant>,
    }
    impl Layer for Hungry {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;
        fn on_event(
            &mut self,
            env: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            if matches!(event, StreamEvent::Ended) {
                self.input_ended.get_or_insert(env.now());
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
            if self.held.is_some() {
                return Ok(false);
            }
            self.held = env.budget().charge(self.want);
            Ok(self.held.is_some())
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    /// An application waiting for memory is not waiting for its peer: the
    /// idle limit does not count while it waits, however long, and counts
    /// from when it got its memory.
    #[test]
    fn the_idle_clock_waits_while_the_application_waits_for_memory() {
        let idle = Duration::from_millis(300);
        let budget = Budget::new(1024);
        let hog = budget.charge(budget.limit() - 100).unwrap();
        let mut session = Harness::with_budget(
            Seed::from_u64(1),
            Session::new(
                Hungry {
                    want: 512,
                    held: None,
                    input_ended: None,
                },
                StreamLimits {
                    idle: Some(idle),
                    write_timeout: None,
                },
                Instant::ZERO,
            ),
            budget.clone(),
        );
        session.settle().unwrap();
        session.advance(idle * 10).unwrap();
        assert!(session.layer().layer.held.is_none(), "no room yet");
        assert_eq!(
            session.layer().layer.input_ended,
            None,
            "the idle limit ran while the application waited for memory"
        );

        let freed = idle * 10;
        drop(hog);
        session.settle().unwrap();
        assert!(session.layer().layer.held.is_some(), "the retry fits");
        session.advance(idle * 10).unwrap();
        let ended = session
            .layer()
            .layer
            .input_ended
            .expect("the idle limit runs once the application has its memory");
        assert!(
            ended.since_start() >= freed + idle,
            "input ended at {:?}, within the idle limit of the memory coming",
            ended.since_start()
        );
    }

    /// Asks for `want` bytes on each advance through a view of the budget
    /// of its own, as a child of a router does, and says it waits for
    /// memory while that view is refused. Notes when its input ended.
    struct OwnView {
        want: usize,
        view: Option<Budget>,
        held: Option<Charge>,
        input_ended: Option<Instant>,
    }
    impl Layer for OwnView {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;
        fn waits_for_memory(&self) -> bool {
            self.view.is_some() && self.held.is_none()
        }
        fn on_event(
            &mut self,
            env: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            if matches!(event, StreamEvent::Ended) {
                self.input_ended.get_or_insert(env.now());
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
            if self.held.is_some() {
                return Ok(false);
            }
            let view = self.view.get_or_insert_with(|| env.budget().view());
            self.held = view.charge(self.want);
            Ok(self.held.is_some())
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    /// A part of the application that waits for memory on a view of its
    /// own, which the session's budget never sees refused, is waiting all
    /// the same: the idle limit does not count while it waits, and counts
    /// from when it got its memory.
    #[test]
    fn the_idle_clock_waits_while_a_part_waits_on_its_own_view() {
        let idle = Duration::from_millis(300);
        let budget = Budget::new(1024);
        let hog = budget.charge(budget.limit() - 100).unwrap();
        let mut session = Harness::with_budget(
            Seed::from_u64(2),
            Session::new(
                OwnView {
                    want: 512,
                    view: None,
                    held: None,
                    input_ended: None,
                },
                StreamLimits {
                    idle: Some(idle),
                    write_timeout: None,
                },
                Instant::ZERO,
            ),
            budget.clone(),
        );
        session.settle().unwrap();
        session.advance(idle * 10).unwrap();
        assert!(session.layer().layer.held.is_none(), "no room yet");
        assert!(session.layer().waits_for_memory(), "the part's wait shows");
        assert_eq!(
            session.layer().layer.input_ended,
            None,
            "the idle limit ran while a part waited for memory"
        );

        let freed = idle * 10;
        drop(hog);
        session.settle().unwrap();
        assert!(session.layer().layer.held.is_some(), "the retry fits");
        assert!(!session.layer().waits_for_memory());
        session.advance(idle * 10).unwrap();
        let ended = session
            .layer()
            .layer
            .input_ended
            .expect("the idle limit runs once the part has its memory");
        assert!(
            ended.since_start() >= freed + idle,
            "input ended at {:?}, within the idle limit of the memory coming",
            ended.since_start()
        );
    }

    /// Refuses input as closed and ends its own direction once input comes.
    #[derive(Default)]
    pub(in super::super) struct Closes {
        closed: bool,
        end_sent: bool,
    }
    impl Layer for Closes {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;
        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            self.closed = true;
            Ok(Admit::Closed(event))
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            (self.closed && !self.end_sent).then(|| {
                self.end_sent = true;
                StreamCommand::End
            })
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    /// Input refused as closed is over, as it is over a connection: an
    /// application that also ended its direction is done at once, without
    /// waiting for the idle limit.
    #[test]
    fn input_refused_as_closed_is_over() {
        let mut session = Harness::new(
            Seed::from_u64(1),
            Session::new(
                Closes::default(),
                StreamLimits {
                    idle: Some(Duration::from_millis(300)),
                    write_timeout: None,
                },
                Instant::ZERO,
            ),
        );
        session.push(b"x").unwrap();
        assert!(session.input_closed());
        assert!(session.ended());
        assert!(session.layer().is_terminal());
    }

    /// A write stalled past its limit gives up on the peer: the application
    /// hears the reset and the session is done, as the stream adapter ends
    /// its run. Bytes that go out start the limit again.
    #[test]
    fn a_write_stalled_past_its_limit_gives_up_and_progress_restarts_the_limit() {
        let limit = Duration::from_millis(300);
        let mut session = Harness::new(
            Seed::from_u64(1),
            Session::new(
                Says {
                    write: Some(StreamCommand::Write(Chunk::unpaid(b"four".to_vec()))),
                    reset_at: None,
                },
                StreamLimits {
                    idle: None,
                    write_timeout: Some(limit),
                },
                Instant::ZERO,
            ),
        );
        session.withhold();
        session.settle().unwrap();
        session.advance(Duration::from_millis(200)).unwrap();
        session.allow(1).unwrap();
        session.advance(Duration::from_millis(250)).unwrap();
        assert_eq!(
            session.layer().layer.reset_at,
            None,
            "a byte went out 250 ms ago, within the limit"
        );
        assert!(!session.layer().is_terminal());
        session.advance(Duration::from_millis(100)).unwrap();
        let reset_at = session
            .layer()
            .layer
            .reset_at
            .expect("the application heard the reset");
        assert!(reset_at.since_start() >= Duration::from_millis(200) + limit);
        assert!(session.layer().is_terminal());
        assert_eq!(session.output().len(), 1);
    }

    /// Input is no sign the peer reads: a peer that keeps sending while it
    /// takes none of the output still runs into the write limit.
    #[test]
    fn input_from_a_peer_that_reads_nothing_does_not_hold_off_the_write_limit() {
        let limit = Duration::from_millis(300);
        let mut session = Harness::new(
            Seed::from_u64(1),
            Session::new(
                Says {
                    write: Some(StreamCommand::Write(Chunk::unpaid(b"four".to_vec()))),
                    reset_at: None,
                },
                StreamLimits {
                    idle: None,
                    write_timeout: Some(limit),
                },
                Instant::ZERO,
            ),
        );
        session.withhold();
        session.settle().unwrap();
        for _ in 0..10 {
            session.advance(Duration::from_millis(200)).unwrap();
            session.push(b"x").unwrap();
        }
        let reset_at = session
            .layer()
            .layer
            .reset_at
            .expect("the write limit ran out while the peer kept sending");
        assert!(
            reset_at.since_start() <= limit + Duration::from_millis(200),
            "the reset came at {:?}, long after the limit",
            reset_at.since_start()
        );
        assert!(session.output().is_empty(), "the peer read nothing");
    }

    /// Writes once, takes everything, and notes when it heard a reset.
    struct Says {
        write: Option<StreamCommand>,
        reset_at: Option<Instant>,
    }
    impl Layer for Says {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;
        fn on_event(
            &mut self,
            env: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            if matches!(event, StreamEvent::Reset) {
                self.reset_at.get_or_insert(env.now());
            }
            Ok(Admit::Taken)
        }
        fn on_command(
            &mut self,
            _: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }
        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            self.write.take()
        }
        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    #[test]
    fn the_application_is_lent_one_level_less_and_the_stacks_waker() {
        use fictionet::stdlib::layer::probe::{Call, Probe, Task};
        use fictionet::stdlib::layer::{Budget, Driver, MAX_DEPTH};
        let (probe, notes) = Probe::<ByteStream, Top>::new();
        let session = Session::new(probe, StreamLimits::default(), Instant::ZERO);
        let mut driver = Driver::new(
            session,
            Arc::new(fictionet::SeededEntropy::new(Seed::from_u64(1))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        let (task, waker) = Task::new();
        driver.set_waker(&waker);
        let _ = driver
            .deliver(StreamEvent::Data(Chunk::unpaid(b"in".to_vec())))
            .unwrap();
        driver.run().unwrap();
        assert!(driver.take_command().is_none());
        driver.complete(()).unwrap();
        // The application sits one level below the session, at the top.
        let room = MAX_DEPTH - (driver.layer().depth() - 1);
        notes.assert_lent(
            &[
                Call::Event,
                Call::Timer,
                Call::Advance,
                Call::TakeCommand,
                Call::Done,
            ],
            room,
            &task,
        );
    }
}
