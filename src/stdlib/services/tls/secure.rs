use super::{Handshake, Negotiation, TlsLayer};
use fictionet::stdlib::layer::{
    Admit, ByteStream, Chain, CommandOf, Env, EventOf, Later, Layer, Side, StreamEvent,
};
use fictionet::time::Instant;

/// A TLS negotiation layer with the layer above it made once the handshake is done,
/// from what the handshake settled: the name in the client's hello and the
/// protocol both sides agreed on with ALPN.
///
/// The default is [`Chain`]`<TlsLayer, `[`Later`]`<U>>`: the plaintext the client sends
/// right after its handshake waits in order until `make` has made the layer
/// above, then reaches it first. A handshake that fails never makes it.
///
/// It is also what STARTTLS switches to: a plaintext layer whose
/// [`Handoff`](fictionet::stdlib::layer::Handoff) names a `Secure` as what
/// comes next runs in a [`Switch`](fictionet::stdlib::layer::Switch), and
/// `make` carries the plaintext session's context into the layer above.
pub struct Secure<U: Layer<Lower = ByteStream>, F, T: Negotiation = TlsLayer> {
    chain: Chain<T, Later<U>>,
    make: Option<F>,
}

impl<U, F, T> Secure<U, F, T>
where
    U: Layer<Lower = ByteStream>,
    T: Negotiation,
    F: FnOnce(&T) -> U,
{
    /// `tls`, with what `make` makes from it above, once its handshake is
    /// done.
    pub fn new(tls: T, make: F) -> Secure<U, F, T> {
        Secure {
            chain: Chain::new(tls, Later::new()),
            make: Some(make),
        }
    }

    /// The TLS layer.
    pub fn tls(&self) -> &T {
        self.chain.lower()
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
    F: FnOnce(&T) -> U,
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
        self.chain.is_terminal()
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Self::Error> {
        self.chain.on_event(env, event)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<U::Upper>,
    ) -> Result<Admit<CommandOf<U::Upper>>, Self::Error> {
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
        let tls = self.chain.lower();
        let settled = matches!(tls.handshake(), Handshake::Established { .. });
        let mut moved = false;
        if settled && let Some(make) = self.make.take() {
            let upper = make(self.chain.lower());
            self.chain.upper_mut().set(upper);
            moved = true;
        }
        Ok(self.chain.advance(env)? || moved)
    }

    fn take_command(&mut self) -> Option<CommandOf<ByteStream>> {
        self.chain.take_command()
    }

    fn take_event(&mut self) -> Option<EventOf<U::Upper>> {
        self.chain.take_event()
    }

    fn take_urgent(&mut self) -> Option<EventOf<U::Upper>> {
        self.chain.take_urgent()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        self.chain.take_work()
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        self.chain.deadline()
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
        select: Option<Select>,
    }

    impl Replacement {
        fn new() -> Self {
            Self {
                state: Handshake::Pending,
                event: None,
                select: Some(Select),
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
            };
            env.report(selected);
            Ok(())
        }

        fn on_timer(&mut self, _: &mut Env<'_, Selected>, _: Deadline) -> Result<(), Expired> {
            self.state = Handshake::Failed;
            Err(Expired)
        }

        fn take_command(&mut self) -> Option<StreamCommand> {
            None
        }

        fn take_event(&mut self) -> Option<StreamEvent> {
            self.event.take()
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
        ended: bool,
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
                StreamEvent::Data(chunk) => self.received.extend_from_slice(&chunk),
                StreamEvent::Ended => self.ended = true,
                StreamEvent::Written(_) | StreamEvent::Reset => {}
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
            None
        }

        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    fn application(
        builds: Arc<AtomicUsize>,
        ready: Arc<AtomicBool>,
    ) -> impl FnOnce(&Replacement) -> Application {
        move |tls| {
            assert_eq!(
                tls.handshake(),
                Handshake::Established {
                    server_name: Some("site.example"),
                    alpn: Some(b"example"),
                }
            );
            builds.fetch_add(1, Ordering::Relaxed);
            Application {
                ready,
                received: Vec::new(),
                ended: false,
            }
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
