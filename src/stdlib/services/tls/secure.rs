use super::{Handshake, Negotiation, TlsLayer};
use fictionet::stdlib::layer::{
    Admit, ByteStream, Chain, CommandOf, Env, EventOf, Later, Layer, Side, StreamCommand,
    StreamEvent, Successor,
};
use fictionet::time::Instant;

/// A TLS negotiation layer with the layer above it made once the handshake is done,
/// from what the handshake settled: the name in the client's hello and the
/// protocol both sides agreed on with ALPN.
///
/// The default is [`Chain`]`<TlsLayer, `[`Later`]`<U>>`: the plaintext the client sends
/// right after its handshake waits in order until `make` has made the layer
/// above, then reaches it first. A handshake that fails never makes it.
/// Once negotiation reports failure, no more plaintext reaches the application,
/// including plaintext it previously refused. Control events and final commands
/// still pass through, and TLS still drains its alerts.
///
/// It is also what STARTTLS switches to: a plaintext layer whose
/// [`Handoff`](fictionet::stdlib::layer::Handoff) names a `Secure` as what
/// comes next runs in a [`Switch`](fictionet::stdlib::layer::Switch), and
/// `make` carries the plaintext session's context into the layer above.
/// As the switch's [`Successor`] it reads none of the bytes that came
/// before it took over.
pub struct Secure<U: Layer<Lower = ByteStream>, F, T: Negotiation = TlsLayer> {
    chain: Chain<Driven<T>, Later<U>>,
    make: Option<F>,
    refused: bool,
    reset_sent: bool,
}

impl<U, F, T> Secure<U, F, T>
where
    U: Layer<Lower = ByteStream>,
    T: Negotiation,
    F: FnOnce(&T) -> Option<U>,
{
    /// `tls`, with what `make` makes from it above, once its handshake is
    /// done. Returning `None` refuses the connection and emits one reset.
    pub fn new(tls: T, make: F) -> Secure<U, F, T> {
        Secure {
            chain: Chain::new(
                Driven {
                    tls,
                    event: None,
                    urgent: None,
                },
                Later::new(),
            ),
            make: Some(make),
            refused: false,
            reset_sent: false,
        }
    }

    /// The TLS layer.
    pub fn tls(&self) -> &T {
        &self.chain.lower().tls
    }

    /// The layer above, once it is made.
    pub fn upper(&self) -> Option<&U> {
        self.chain.upper().get()
    }
}

impl<U, F, T> Layer for Secure<U, F, T>
where
    U: Layer<Lower = ByteStream>,
    T: Negotiation,
    F: FnOnce(&T) -> Option<U>,
{
    type Lower = ByteStream;
    type Upper = U::Upper;
    type Report = Side<T::Report, U::Report>;
    type Timer = Side<T::Timer, U::Timer>;
    type Work = Side<T::Work, U::Work>;
    type Done = Side<T::Done, U::Done>;
    type Error = Side<T::Error, U::Error>;

    fn report_bytes(report: &Self::Report) -> Option<usize> {
        match report {
            Side::Lower(report) => T::report_bytes(report),
            Side::Upper(report) => U::report_bytes(report),
        }
    }

    fn depth(&self) -> usize {
        self.chain.depth()
    }

    fn is_terminal(&self) -> bool {
        self.refused || self.chain.is_terminal()
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Self::Error> {
        if self.refused {
            return Ok(Admit::Closed(event));
        }
        self.chain.on_event(env, event)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<U::Upper>,
    ) -> Result<Admit<CommandOf<U::Upper>>, Self::Error> {
        if self.refused {
            return Ok(Admit::Closed(command));
        }
        self.chain.on_command(env, command)
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        timer: Self::Timer,
    ) -> Result<(), Self::Error> {
        self.chain.on_timer(env, timer)
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        done: Self::Done,
    ) -> Result<(), Self::Error> {
        self.chain.on_done(env, done)
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Self::Error> {
        if self.refused {
            return Ok(false);
        }
        let lower = env.scoped(Side::Lower, |env| self.chain.lower_mut().step(env));
        let mut moved = lower.as_ref().copied().unwrap_or(false);
        match self.tls().handshake() {
            Handshake::Pending => return lower.map_err(Side::Lower),
            Handshake::Failed => {
                moved |= self
                    .chain
                    .retain_events(|event| !matches!(event, StreamEvent::Data(_)));
                let driven = self.chain.lower_mut();
                for slot in [&mut driven.event, &mut driven.urgent] {
                    if matches!(slot, Some(StreamEvent::Data(_))) {
                        *slot = None;
                        moved = true;
                    }
                }
            }
            Handshake::Established { .. } => {
                if let Some(make) = self.make.take() {
                    let Some(upper) = make(self.tls()) else {
                        self.refused = true;
                        return Ok(true);
                    };
                    self.chain.upper_mut().set(upper);
                    moved = true;
                }
            }
        }
        let upper = self.chain.advance(env);
        // Deliver already-produced control before surfacing the lower error.
        // The connection still fails on this turn, with its original error.
        lower.map_err(Side::Lower)?;
        Ok(upper? || moved)
    }

    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<CommandOf<ByteStream>> {
        if self.refused {
            return (!std::mem::replace(&mut self.reset_sent, true))
                .then_some(StreamCommand::Reset);
        }
        self.chain.take_command(env)
    }

    fn take_event(&mut self) -> Option<EventOf<U::Upper>> {
        self.chain.take_event()
    }

    fn take_urgent(&mut self) -> Option<EventOf<U::Upper>> {
        self.chain.take_urgent()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        if self.refused {
            return None;
        }
        self.chain.take_work()
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        if self.refused {
            return None;
        }
        self.chain.deadline()
    }
}

/// STARTTLS: a plaintext layer names a `Secure` as what comes next. TLS
/// starts on the carrier when it takes over and reads none of the bytes
/// that came before, so no plaintext the client pipelined after its request
/// reaches it, whatever the plaintext layer did with them.
impl<U, F, T> Successor<Secure<U, F, T>> for Secure<U, F, T>
where
    U: Layer<Lower = ByteStream>,
    T: Negotiation,
    F: FnOnce(&T) -> Option<U>,
{
    fn succeed(next: Secure<U, F, T>) -> Secure<U, F, T> {
        next
    }

    fn inherits(event: &StreamEvent) -> bool {
        !matches!(event, StreamEvent::Data(_))
    }
}

// Stage the lower step and its output before checking negotiation. Chain
// must not call into TLS between that check and application delivery.
struct Driven<T> {
    tls: T,
    event: Option<StreamEvent>,
    urgent: Option<StreamEvent>,
}

impl<T: Negotiation> Driven<T> {
    fn step(&mut self, env: &mut Env<'_, T::Report>) -> Result<bool, T::Error> {
        let advanced = self.tls.advance(env);
        let mut moved = false;
        if self.urgent.is_none() {
            self.urgent = self.tls.take_urgent();
            moved |= self.urgent.is_some();
        }
        if self.event.is_none() {
            self.event = self.tls.take_event();
            moved |= self.event.is_some();
        }
        advanced.map(|progress| progress || moved)
    }
}

impl<T: Negotiation> Layer for Driven<T> {
    type Lower = ByteStream;
    type Upper = ByteStream;
    type Report = T::Report;
    type Timer = T::Timer;
    type Work = T::Work;
    type Done = T::Done;
    type Error = T::Error;

    fn report_bytes(report: &Self::Report) -> Option<usize> {
        T::report_bytes(report)
    }

    fn depth(&self) -> usize {
        self.tls.depth()
    }

    fn is_terminal(&self) -> bool {
        self.tls.is_terminal()
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Self::Error> {
        self.tls.on_event(env, event)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: StreamCommand,
    ) -> Result<Admit<StreamCommand>, Self::Error> {
        self.tls.on_command(env, command)
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        timer: Self::Timer,
    ) -> Result<(), Self::Error> {
        self.tls.on_timer(env, timer)
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        done: Self::Done,
    ) -> Result<(), Self::Error> {
        self.tls.on_done(env, done)
    }

    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        self.tls.take_command(env)
    }

    fn take_event(&mut self) -> Option<StreamEvent> {
        self.urgent.take().or_else(|| self.event.take())
    }

    fn take_urgent(&mut self) -> Option<StreamEvent> {
        self.urgent.take()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        self.tls.take_work()
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        self.tls.deadline()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::layer::{Harness, StreamCommand, Top};

    #[derive(Debug)]
    struct Select;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Selected {
        Accept,
        Refuse,
        FailWhenAdvanced,
        FailWhenTaken,
        FailWithError,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Deadline;

    #[derive(Debug, PartialEq, Eq)]
    struct Expired;

    // A stream replacement whose asynchronous selection determines its
    // handshake. Early plaintext exercises the deferred application's edge.
    struct Replacement {
        state: Handshake<'static>,
        event: Option<StreamEvent>,
        urgent: Option<StreamEvent>,
        select: Option<Select>,
        fail_on_advance: bool,
        fail_on_take: bool,
        fail_with_error: bool,
    }

    impl Replacement {
        fn new() -> Self {
            Self {
                state: Handshake::Pending,
                event: None,
                urgent: None,
                select: Some(Select),
                fail_on_advance: false,
                fail_on_take: false,
                fail_with_error: false,
            }
        }
    }

    impl Negotiation for Replacement {
        fn handshake(&self) -> Handshake<'_> {
            self.state
        }
    }

    impl Layer for Replacement {
        type Lower = ByteStream;
        type Upper = ByteStream;
        type Report = Selected;
        type Timer = Deadline;
        type Work = Select;
        type Done = Selected;
        type Error = Expired;

        fn report_bytes(_: &Self::Report) -> Option<usize> {
            Some(0)
        }

        fn on_event(
            &mut self,
            _: &mut Env<'_, Selected>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Expired> {
            if self.event.is_some() {
                return Ok(Admit::Blocked(event));
            }
            self.event = Some(event);
            Ok(Admit::Taken)
        }

        fn on_command(
            &mut self,
            _: &mut Env<'_, Selected>,
            command: StreamCommand,
        ) -> Result<Admit<StreamCommand>, Expired> {
            Ok(Admit::Blocked(command))
        }

        fn on_done(
            &mut self,
            env: &mut Env<'_, Selected>,
            selected: Selected,
        ) -> Result<(), Expired> {
            self.state = match selected {
                Selected::Accept => Handshake::Established {
                    server_name: Some("site.example"),
                    alpn: Some(b"example"),
                },
                Selected::Refuse => Handshake::Failed,
                Selected::FailWhenTaken => {
                    self.fail_on_take = true;
                    self.state
                }
                Selected::FailWithError => {
                    self.fail_on_advance = true;
                    self.fail_with_error = true;
                    self.state
                }
                Selected::FailWhenAdvanced => {
                    self.fail_on_advance = true;
                    self.state
                }
            };
            env.report(selected);
            Ok(())
        }

        fn advance(&mut self, _: &mut Env<'_, Selected>) -> Result<bool, Expired> {
            if std::mem::take(&mut self.fail_on_advance) {
                self.state = Handshake::Failed;
                if std::mem::take(&mut self.fail_with_error) {
                    Err(Expired)
                } else {
                    Ok(true)
                }
            } else {
                Ok(false)
            }
        }

        fn on_timer(&mut self, _: &mut Env<'_, Selected>, _: Deadline) -> Result<(), Expired> {
            self.state = Handshake::Failed;
            Err(Expired)
        }

        fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
            None
        }

        fn take_event(&mut self) -> Option<StreamEvent> {
            self.event.take()
        }

        fn take_urgent(&mut self) -> Option<StreamEvent> {
            if std::mem::take(&mut self.fail_on_take) {
                self.state = Handshake::Failed;
            }
            self.urgent.take()
        }

        fn take_work(&mut self) -> Option<Select> {
            self.select.take()
        }

        fn deadline(&self) -> Option<(Instant, Deadline)> {
            matches!(self.state, Handshake::Pending)
                .then_some((Instant::ZERO + Duration::from_secs(1), Deadline))
        }
    }

    struct Application {
        ready: Arc<AtomicBool>,
        received: Vec<u8>,
        received_count: Arc<AtomicUsize>,
        ended: bool,
        reset: bool,
        written: u64,
    }

    impl Layer for Application {
        type Lower = ByteStream;
        type Upper = Top;
        type Report = Infallible;
        type Timer = Infallible;
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;

        fn on_event(
            &mut self,
            _: &mut Env<'_, Infallible>,
            event: StreamEvent,
        ) -> Result<Admit<StreamEvent>, Infallible> {
            if !self.ready.load(Ordering::Relaxed) {
                return Ok(Admit::Blocked(event));
            }
            match event {
                StreamEvent::Data(chunk) => {
                    self.received_count
                        .fetch_add(chunk.len(), Ordering::Relaxed);
                    self.received.extend_from_slice(&chunk);
                }
                StreamEvent::Ended => self.ended = true,
                StreamEvent::Written(n) => self.written += n,
                StreamEvent::Reset => self.reset = true,
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
            None
        }

        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    fn application(
        builds: Arc<AtomicUsize>,
        ready: Arc<AtomicBool>,
    ) -> impl FnOnce(&Replacement) -> Option<Application> {
        move |tls| {
            assert_eq!(
                tls.handshake(),
                Handshake::Established {
                    server_name: Some("site.example"),
                    alpn: Some(b"example"),
                }
            );
            builds.fetch_add(1, Ordering::Relaxed);
            Some(Application {
                ready,
                received: Vec::new(),
                received_count: Arc::new(AtomicUsize::new(0)),
                ended: false,
                reset: false,
                written: 0,
            })
        }
    }

    #[test]
    fn replacement_defers_construction_and_preserves_plaintext_order() {
        let builds = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(AtomicBool::new(false));
        let secure = Secure::new(
            Replacement::new(),
            application(builds.clone(), ready.clone()),
        );
        let mut h = Harness::new(Seed::from_u64(42), secure);
        let chunks: &[&[u8]] = &[b"first", b"second", b"third"];
        h.push(chunks[0]).unwrap();
        h.push(chunks[1]).unwrap();
        assert_eq!(builds.load(Ordering::Relaxed), 0);
        assert!(h.layer().upper().is_none());
        assert!(matches!(h.work(), Some(Side::Lower(Select))));
        assert!(h.work().is_none());
        h.complete(Side::Lower(Selected::Accept)).unwrap();
        assert_eq!(builds.load(Ordering::Relaxed), 1);
        assert!(h.layer().upper().unwrap().received.is_empty());
        h.push(chunks[2]).unwrap();
        h.end().unwrap();
        ready.store(true, Ordering::Relaxed);
        h.settle().unwrap();
        assert_eq!(h.layer().upper().unwrap().received, chunks.concat());
        assert!(h.layer().upper().unwrap().ended);
        assert_eq!(builds.load(Ordering::Relaxed), 1);
        let reports: Vec<_> = h.driver().observations().drain().collect();
        assert_eq!(reports, [Side::Lower(Selected::Accept)]);
        assert!(h.layer().deadline().is_none());
    }

    #[test]
    fn failed_negotiation_delivers_control_to_the_established_application() {
        let ready = Arc::new(AtomicBool::new(true));
        let secure = Secure::new(
            Replacement::new(),
            application(Arc::new(AtomicUsize::new(0)), ready),
        );
        let mut h = fictionet::stdlib::layer::Driver::new(
            secure,
            Arc::new(fictionet::SeededEntropy::new(Seed::from_u64(46))),
            fictionet::stdlib::layer::Budget::unlimited(),
            Instant::ZERO,
        );
        h.complete(Side::Lower(Selected::Accept)).unwrap();
        h.run().unwrap();
        h.complete(Side::Lower(Selected::Refuse)).unwrap();
        for event in [
            StreamEvent::Written(17),
            StreamEvent::Ended,
            StreamEvent::Reset,
        ] {
            assert!(matches!(h.deliver(event).unwrap(), Admit::Taken));
            h.run().unwrap();
        }
        let app = h.layer().upper().unwrap();
        assert_eq!(app.written, 17);
        assert!(app.ended);
        assert!(app.reset);
    }

    #[test]
    fn a_lower_error_is_returned_after_delivering_its_last_controls() {
        let secure = Secure::new(
            Replacement::new(),
            application(
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicBool::new(true)),
            ),
        );
        let mut driver = fictionet::stdlib::layer::Driver::new(
            secure,
            Arc::new(fictionet::SeededEntropy::new(Seed::from_u64(48))),
            fictionet::stdlib::layer::Budget::unlimited(),
            Instant::ZERO,
        );
        driver.complete(Side::Lower(Selected::Accept)).unwrap();
        driver.run().unwrap();
        driver.layer_mut().chain.lower_mut().tls.urgent = Some(StreamEvent::Written(17));
        assert!(matches!(
            driver.deliver(StreamEvent::Reset).unwrap(),
            Admit::Taken
        ));
        driver
            .complete(Side::Lower(Selected::FailWithError))
            .unwrap();
        assert_eq!(driver.run(), Err(Side::Lower(Expired)));
        let app = driver.layer().upper().unwrap();
        assert_eq!(app.written, 17);
        assert!(app.reset);
    }

    #[test]
    fn failure_stops_plaintext_waiting_for_the_application() {
        for failure in [
            Selected::Refuse,
            Selected::FailWhenAdvanced,
            Selected::FailWhenTaken,
        ] {
            let builds = Arc::new(AtomicUsize::new(0));
            let ready = Arc::new(AtomicBool::new(false));
            let secure = Secure::new(
                Replacement::new(),
                application(builds.clone(), ready.clone()),
            );
            let mut h = Harness::new(Seed::from_u64(45), secure);
            h.complete(Side::Lower(Selected::Accept)).unwrap();
            let received = h.layer().upper().unwrap().received_count.clone();
            h.push(b"authenticated but not yet delivered").unwrap();
            ready.store(true, Ordering::Relaxed);
            h.complete(Side::Lower(failure)).unwrap();
            h.settle().unwrap();
            assert_eq!(received.load(Ordering::Relaxed), 0);
            assert_eq!(builds.load(Ordering::Relaxed), 1);
            assert!(h.layer().upper().unwrap().received.is_empty());
        }
    }

    #[test]
    fn failed_replacement_never_constructs_an_application() {
        let builds = Arc::new(AtomicUsize::new(0));
        let secure = Secure::new(
            Replacement::new(),
            application(builds.clone(), Arc::new(AtomicBool::new(true))),
        );
        let mut h = Harness::new(Seed::from_u64(43), secure);
        h.push(b"plaintext waiting for negotiation").unwrap();
        h.complete(Side::Lower(Selected::Refuse)).unwrap();
        h.settle().unwrap();
        h.advance(Duration::from_secs(2)).unwrap();
        assert_eq!(builds.load(Ordering::Relaxed), 0);
        assert!(h.layer().upper().is_none());
        assert_eq!(h.layer().tls().handshake(), Handshake::Failed);
    }

    #[test]
    fn refusing_an_established_application_resets_once() {
        let secure = Secure::new(Replacement::new(), |_| None::<Application>);
        let mut h = Harness::new(Seed::from_u64(47), secure);
        h.complete(Side::Lower(Selected::Accept)).unwrap();
        assert!(h.layer().is_terminal());
        assert!(h.layer().upper().is_none());
        assert!(h.was_reset());
        h.settle().unwrap();
        assert!(h.driver().take_command().is_none());
    }

    #[test]
    fn replacement_timer_and_error_types_reach_the_driver() {
        let builds = Arc::new(AtomicUsize::new(0));
        let secure = Secure::new(
            Replacement::new(),
            application(builds.clone(), Arc::new(AtomicBool::new(true))),
        );
        assert_eq!(
            secure.deadline(),
            Some((
                Instant::ZERO + Duration::from_secs(1),
                Side::Lower(Deadline)
            ))
        );
        let mut h = Harness::new(Seed::from_u64(44), secure);
        assert_eq!(h.advance(Duration::from_secs(1)), Err(Side::Lower(Expired)));
        assert_eq!(builds.load(Ordering::Relaxed), 0);
        assert!(h.layer().upper().is_none());
        assert_eq!(h.layer().tls().handshake(), Handshake::Failed);
    }
}
