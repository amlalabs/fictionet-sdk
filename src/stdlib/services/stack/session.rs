use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};

use fictionet::Cx;
use fictionet::stdlib::layer::{Admit, ByteStream, Env, Layer, StreamCommand, StreamEvent, Top};
use fictionet::time::Instant;

use super::{Job, StreamLimits};

/// Stream lifetime and timeouts for an application on a transport child.
/// The transport remains responsible for closing and retiring its socket.
pub struct Session<L> {
    layer: L,
    limits: StreamLimits,
    now: Instant,
    idle: Option<Instant>,
    write: Option<Instant>,
    pending: u64,
    input_end: bool,
    output_end: bool,
    reset: bool,
    event: Option<StreamEvent>,
    command: Option<StreamCommand>,
    jobs: Arc<AtomicUsize>,
}

impl<L> Session<L> {
    /// Applies the same idle and stalled-write policy as the stream adapter.
    pub fn new(layer: L, limits: StreamLimits, now: Instant) -> Self {
        Self {
            layer,
            limits,
            now,
            idle: None,
            write: None,
            pending: 0,
            input_end: false,
            output_end: false,
            reset: false,
            event: None,
            command: None,
            jobs: Arc::new(AtomicUsize::new(0)),
        }
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
    fn is_terminal(&self) -> bool {
        self.reset
            || (self.output_end
                && (self.layer.is_terminal() || self.input_end)
                && self.pending == 0
                && self.jobs.load(Ordering::Relaxed) == 0
                && self.command.is_none())
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
        let (ended, reset, written, data) = match &event {
            StreamEvent::Ended => (true, false, 0, false),
            StreamEvent::Reset => (true, true, 0, false),
            StreamEvent::Written(n) => (false, false, *n, false),
            StreamEvent::Data(_) => (false, false, 0, true),
        };
        let admitted = self.layer.on_event(env, event)?;
        if admitted.moved() || matches!(&admitted, Admit::Closed(_)) {
            self.now = env.now();
            self.input_end |= ended;
            self.reset |= reset;
            if data {
                self.idle = None;
            }
            if written > 0 {
                self.pending = self.pending.saturating_sub(written);
                self.write = (self.pending > 0)
                    .then(|| self.limits.write_timeout.map(|by| self.now + by))
                    .flatten();
            }
        }
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
    ) -> Result<(), L::Error> {
        match timer {
            SessionTimer::Application(timer) => self.layer.on_timer(env, timer),
            SessionTimer::Idle => {
                self.idle = None;
                self.input_end = true;
                self.event = Some(StreamEvent::Ended);
                Ok(())
            }
            SessionTimer::Write => {
                self.write = None;
                self.reset = true;
                self.command = Some(StreamCommand::Reset);
                let _ = self.layer.on_event(env, StreamEvent::Reset)?;
                Ok(())
            }
        }
    }
    fn on_done(&mut self, env: &mut Env<'_, L::Report>, done: L::Done) -> Result<(), L::Error> {
        self.layer.on_done(env, done)
    }
    fn advance(&mut self, env: &mut Env<'_, L::Report>) -> Result<bool, L::Error> {
        self.now = env.now();
        let mut moved = false;
        if let Some(event) = self.event.take() {
            match self.layer.on_event(env, event)? {
                Admit::Blocked(event) | Admit::Partial(event) => self.event = Some(event),
                _ => moved = true,
            }
        }
        moved |= self.layer.advance(env)?;
        if self.pending > 0 || self.jobs.load(Ordering::Relaxed) > 0 || self.input_end {
            self.idle = None;
        } else if self.idle.is_none() {
            self.idle = self.limits.idle.map(|by| self.now + by);
        }
        Ok(moved)
    }
    fn take_command(&mut self) -> Option<StreamCommand> {
        let command = self.command.take().or_else(|| self.layer.take_command())?;
        match &command {
            StreamCommand::Write(bytes) => {
                if self.pending == 0 {
                    self.write = self.limits.write_timeout.map(|by| self.now + by);
                }
                self.pending = self.pending.saturating_add(bytes.len() as u64);
                self.idle = None;
            }
            StreamCommand::End => self.output_end = true,
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
        self.idle = None;
        Some(SessionWork {
            work,
            active: Some(self.jobs.clone()),
        })
    }
    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        [
            self.layer
                .deadline()
                .map(|(at, timer)| (at, SessionTimer::Application(timer))),
            self.idle.map(|at| (at, SessionTimer::Idle)),
            self.write.map(|at| (at, SessionTimer::Write)),
        ]
        .into_iter()
        .flatten()
        .min_by_key(|(at, _)| *at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::layer::{Chunk, Harness};
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
                        self.write = Some(StreamCommand::Write(Chunk::new(b"last".to_vec())));
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
        fn take_command(&mut self) -> Option<StreamCommand> {
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
}
