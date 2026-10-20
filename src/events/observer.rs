use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::time::Instant;
use crate::{Cx, sync::Mutex};

use super::{ConnInfo, Event, Interest, KeyRef, Loss, PacketRef, Stream, TopologyRef};

/// Metadata available before constructing an event.
#[derive(Clone, Copy, Debug)]
pub struct Metadata {
    /// The service or component reporting the fact.
    pub source: &'static str,
    /// The kind of fact.
    pub kind: &'static str,
}

/// Stream, order and run time assigned before fan-out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// The independently numbered stream.
    pub stream: Stream,
    /// Sequence within this stream, starting at 1 after interest filtering.
    pub seq: u64,
    /// Time on the run's clock, including simulated time in a lab.
    pub at: Instant,
}

/// A borrowed observation from one of the run's typed streams.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Observation<'a> {
    /// A structured service or network fact.
    Event(&'a Event),
    /// A successful link crossing.
    Packet(PacketRef<'a>),
    /// A TLS secret.
    TlsKey(KeyRef<'a>),
    /// A topology change.
    Topology(TopologyRef<'a>),
}

impl Observation<'_> {
    /// Metadata for this observation's own interest filter.
    pub fn interest(&self) -> Interest<'_> {
        match self {
            Self::Event(event) => Interest::Event(
                Metadata {
                    source: event.source,
                    kind: event.kind,
                },
                &event.conn,
            ),
            Self::Packet(packet) => Interest::Packet(*packet),
            Self::TlsKey(key) => Interest::TlsKey(super::KeyMeta {
                label: key.label,
                connection: key.connection,
            }),
            Self::Topology(topology) => Interest::Topology(topology.kind()),
        }
    }
}

/// A run's immutable observation destination.
///
/// Install one through [`RunOptions`](crate::RunOptions). Delivery is
/// synchronous and serialized per stream. Streams may arrive concurrently
/// from different threads, with no ordering between streams. Callbacks run
/// outside cable, network, queue and group locks. Per-link order is kept.
/// Return promptly and never call back into the world. I/O belongs on a
/// bounded worker queue.
///
/// Interest checks precede observation work. Event-only observers must decline
/// packets, TLS keys and topology. Topology interest is fixed at run start.
/// Keep all interests and limits fixed for repeatable lab runs.
/// Connection context is explicit, including during interest checks.
/// Packet callbacks run at the crossing; topology made during a task poll
/// arrives after it returns. Packet numbers count every interested successful
/// crossing. Declined crossings consume no numbers. Event numbers are separate.
pub trait Observer: Send + Sync + 'static {
    /// Whether producing this observation is useful. Keep this check cheap.
    fn enabled(&self, interest: Interest<'_>) -> bool;
    /// Receives a borrowed observation with its run-assigned stamp.
    fn observe(&self, stamp: Stamp, observation: Observation<'_>);
    /// Reports facts lost before delivery, such as a full producer staging buffer.
    fn lost(&self, _loss: Loss) {}
    /// Seals input when the run ends, including cancellation or drop.
    fn end(&self, _at: Instant) {}
}

/// A fixed set of destinations sharing observations and stamps.
///
/// Interest is the union of the children. Each delivery is filtered for each
/// child using its own observation metadata. Filtering can leave sequence gaps
/// in a child's input. Loss and run end are forwarded to every child.
pub struct Fanout(Vec<Arc<dyn Observer>>);

impl Fanout {
    /// Combines the destinations. Their interest filters are unioned.
    pub fn new(observers: Vec<Arc<dyn Observer>>) -> Self {
        Self(observers)
    }
}

impl Observer for Fanout {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        self.0.iter().any(|o| o.enabled(interest))
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        for observer in &self.0 {
            if observer.enabled(observation.interest()) {
                observer.observe(stamp, observation.clone());
            }
        }
    }

    fn lost(&self, loss: Loss) {
        for observer in &self.0 {
            observer.lost(loss.clone());
        }
    }

    fn end(&self, at: Instant) {
        for observer in &self.0 {
            observer.end(at);
        }
    }
}

/// An emitter with explicitly borrowed connection context.
#[derive(Clone, Copy)]
pub struct Emitter<'a> {
    pub(crate) cx: &'a Cx,
    pub(crate) connection: &'a ConnInfo,
}

impl Emitter<'_> {
    /// Checks interest before doing longer-lived tracking work.
    pub fn enabled(&self, source: &'static str, kind: &'static str) -> bool {
        self.cx
            .run
            .observer
            .enabled(Interest::Event(Metadata { source, kind }, self.connection))
    }

    /// Builds an event only when a destination is interested.
    pub fn emit(
        &self,
        source: &'static str,
        kind: &'static str,
        build: impl FnOnce(Event) -> Event,
    ) {
        if self.enabled(source, kind) {
            self.cx
                .emit_observation(build(Event::new(source, kind)).conn(self.connection));
        }
    }
}

/// Stream numbering and serialized delivery for a run or service harness.
/// All destinations share stamps. Call [`Self::enabled`] before constructing events.
pub struct Dispatch {
    observer: Option<Arc<dyn Observer>>,
    state: Mutex<State>,
    ended: AtomicBool,
    deliveries: RwLock<()>,
    clock: Option<Arc<crate::clock::Clock>>,
    topology: [bool; 5],
    pub(crate) run_id: u64,
    next_link: std::sync::atomic::AtomicU64,
    next_host: std::sync::atomic::AtomicU64,
}

struct State {
    seq: u64,
    topology: u64,
    keys: u64,
    ended: bool,
}

impl Dispatch {
    pub(crate) const fn empty() -> Self {
        Self {
            observer: None,
            ended: AtomicBool::new(false),
            deliveries: RwLock::new(()),
            state: Mutex::new(State {
                seq: 0,
                topology: 0,
                keys: 0,
                ended: false,
            }),
            clock: None,
            topology: [false; 5],
            run_id: 0,
            next_link: std::sync::atomic::AtomicU64::new(1),
            next_host: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Creates a dispatch with an optional, fixed destination.
    pub fn new(observer: Option<Arc<dyn Observer>>) -> Self {
        let topology = [
            super::TopologyKind::Task,
            super::TopologyKind::Group,
            super::TopologyKind::Host,
            super::TopologyKind::Link,
            super::TopologyKind::Connection,
        ]
        .map(|kind| {
            observer
                .as_ref()
                .is_some_and(|o| o.enabled(Interest::Topology(kind)))
        });
        Self {
            observer,
            topology,
            ..Self::empty()
        }
    }

    pub(crate) fn for_run(
        observer: Option<Arc<dyn Observer>>,
        run_id: u64,
        clock: &Arc<crate::clock::Clock>,
    ) -> Arc<Self> {
        let mut dispatch = Self::new(observer);
        if dispatch.observer.is_some() {
            dispatch.clock = Some(clock.clone());
        }
        dispatch.run_id = run_id;
        Arc::new(dispatch)
    }

    pub(crate) fn installed(&self) -> bool {
        self.observer.is_some()
    }

    pub(crate) fn packet(&self, seq: &mut u64, packet: PacketRef<'_>) {
        let _deliveries = self.deliveries.read().unwrap_or_else(|e| e.into_inner());
        if self.ended.load(Ordering::Acquire) {
            return;
        }
        *seq += 1;
        self.observer
            .as_ref()
            .expect("registered observer")
            .observe(
                Stamp {
                    stream: Stream::Packets(packet.link),
                    seq: *seq,
                    at: self.clock.as_ref().expect("run clock").now(),
                },
                Observation::Packet(packet),
            );
    }

    pub(crate) fn topology_enabled(&self, kind: super::TopologyKind) -> bool {
        self.topology[kind as usize]
    }

    pub(crate) fn next_link(&self) -> super::LinkId {
        super::LinkId(
            self.next_link
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub(crate) fn next_host(&self) -> super::HostId {
        super::HostId(
            self.next_host
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub(crate) fn has_topology(&self) -> bool {
        self.topology.iter().any(|enabled| *enabled)
    }

    pub(crate) fn topology(&self, item: TopologyRef<'_>) {
        if self.topology_enabled(item.kind())
            && let Some(item) = super::staging::stage(self, item)
        {
            self.publish(Stream::Topology, Observation::Topology(item));
        }
    }

    pub(crate) fn key(&self, key: KeyRef<'_>) {
        if self.enabled(Interest::TlsKey(super::KeyMeta {
            label: key.label,
            connection: key.connection,
        })) {
            self.publish(Stream::Keys, Observation::TlsKey(key));
        }
    }

    fn publish(&self, stream: Stream, item: Observation<'_>) {
        let Some(observer) = &self.observer else {
            return;
        };
        let mut state = self.state.lock();
        if state.ended {
            return;
        }
        let seq = match stream {
            Stream::Topology => &mut state.topology,
            Stream::Keys => &mut state.keys,
            _ => unreachable!(),
        };
        *seq += 1;
        observer.observe(
            Stamp {
                stream,
                seq: *seq,
                at: self.clock.as_ref().expect("run clock").now(),
            },
            item,
        );
    }

    /// Checks interest without reading the clock or numbering an event.
    pub fn enabled(&self, interest: Interest<'_>) -> bool {
        self.observer.as_ref().is_some_and(|observer| {
            !self.ended.load(Ordering::Acquire) && observer.enabled(interest)
        })
    }

    /// Delivers an interested event, assigning its sequence and reading run time.
    pub fn emit(&self, mut event: Event, at: impl FnOnce() -> Instant) {
        let Some(observer) = &self.observer else {
            return;
        };
        let mut state = self.state.lock();
        if state.ended {
            return;
        }
        state.seq += 1;
        let stamp = Stamp {
            stream: fictionet::events::Stream::Events,
            seq: state.seq,
            at: at(),
        };
        event.seq = stamp.seq;
        event.at = stamp.at;
        observer.observe(stamp, Observation::Event(&event));
    }

    /// Reports observations a producer omitted before delivery. A zero
    /// count, or a loss after the run ends, reports nothing.
    pub fn lost(&self, loss: Loss) {
        if loss.count != 0
            && let Some(observer) = &self.observer
        {
            let state = self.state.lock();
            if !state.ended {
                observer.lost(loss);
            }
        }
    }

    /// Seals delivery and ends the observer once.
    pub fn end(&self, at: impl FnOnce() -> Instant) {
        let Some(observer) = &self.observer else {
            return;
        };
        let _deliveries = self.deliveries.write().unwrap_or_else(|e| e.into_inner());
        let mut state = self.state.lock();
        if !state.ended {
            state.ended = true;
            self.ended.store(true, Ordering::Release);
            observer.end(at());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RunOptions, Seed, block_on, lab};
    use fictionet::events::recorder::Recorder;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn interest_checks_do_not_take_the_delivery_lock() {
        let dispatch = Arc::new(Dispatch::new(Some(Arc::new(Recorder::default()))));
        let state = dispatch.state.lock();
        let checking = dispatch.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            tx.send(checking.enabled(Interest::Event(
                Metadata {
                    source: "test",
                    kind: "check",
                },
                &ConnInfo::default(),
            )))
            .unwrap();
        });
        let enabled = rx.recv_timeout(Duration::from_secs(5));
        drop(state);
        thread.join().unwrap();
        assert!(enabled.expect("interest check must finish while delivery is locked"));
        dispatch.end(|| Instant::ZERO);
        assert!(!dispatch.enabled(Interest::Event(
            Metadata {
                source: "test",
                kind: "check"
            },
            &ConnInfo::default()
        )));
    }

    #[test]
    fn absent_observer_does_not_build_events() {
        block_on(lab(
            fictionet::RunOptions::new(Seed::from_u64(1)),
            |cx| async move {
                assert!(cx.run.observer.shared().is_none());
                assert!(!cx.event_enabled("shop", "order"));
                cx.emit("shop", "order", |_| panic!("unobserved event was built"));
                let conn = ConnInfo::default();
                cx.emitter(&conn).emit("shop", "order", |_| {
                    panic!("unobserved connection event was built")
                });
                Ok(())
            },
        ))
        .unwrap();
        let dispatch = Dispatch::new(None);
        dispatch.emit(Event::new("shop", "order"), || panic!("clock read"));
        dispatch.topology(TopologyRef::TaskRemoved {
            task: super::super::TaskId(1),
        });
        dispatch.key(KeyRef {
            label: "CLIENT_RANDOM",
            client_random: &[],
            secret: &[],
            connection: None,
        });
        dispatch.end(|| panic!("clock read"));
        let state = dispatch.state.lock();
        assert_eq!((state.seq, state.topology, state.keys), (0, 0, 0));
        assert!(dispatch.clock.is_none());
        assert_eq!(dispatch.next_link.load(Ordering::Relaxed), 1);
        assert_eq!(dispatch.next_host.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unobserved_drop_details_are_not_extracted() {
        block_on(lab(
            fictionet::RunOptions::new(Seed::from_u64(1)),
            |cx| async move {
                crate::stdlib::network::ip::emit_drop(
                    &cx,
                    &ConnInfo::default(),
                    "lan",
                    &crate::Packet(vec![0xff]),
                    "malformed",
                    || panic!("drop detail was built"),
                    |_| panic!("drop was enriched"),
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn bounded_builders_report_truncation_without_copying_large_text() {
        let memory = Arc::new(Recorder::default());
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(memory.clone()),
            |cx| async move {
                let text = "x".repeat(1 << 20);
                cx.emit("test", "large", |event| {
                    event
                        .field("text", text.as_str())
                        .summary(format_args!("{text}"))
                });
                Ok(())
            },
        ))
        .unwrap();
        let events = memory.after(0, 10);
        assert!(events[1].size() < 16 * 1024);
        assert!(events[1].str("text").unwrap().ends_with("[truncated]"));
        assert_eq!(events[1].summary.len(), 4096);
        assert!(memory.all()[0..].iter().any(Event::is_truncated));
    }

    #[test]
    fn run_metadata_is_bounded_without_losing_the_event() {
        let memory = Arc::new(Recorder::default());
        block_on(lab(
            RunOptions::new(Seed::from_u64(1))
                .observer(memory.clone())
                .fields(crate::events::Fields::new().with("large", "x".repeat(1 << 20))),
            |_| async { Ok(()) },
        ))
        .unwrap();
        let start = &memory.after(0, 1)[0];
        assert!(start.str("large").unwrap().ends_with("[truncated]"));
        assert!(start.size() < 8192);
        assert!(memory.all()[0..].iter().any(Event::is_truncated));
    }

    #[test]
    fn caller_metadata_cannot_displace_run_identity() {
        let memory = Arc::new(Recorder::default());
        let mut fields = crate::events::Fields::new();
        for name in [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
            "r", "s", "t", "u", "v", "w", "x", "y", "z", "aa", "bb", "cc", "dd", "ee", "ff",
        ] {
            fields.set(name, "x".repeat(4096));
        }
        fields.set("seed", "wrong");
        fields.set("rng", "wrong");
        fields.set("wall", "wrong");
        let seed = Seed::from_u64(1);
        block_on(lab(
            RunOptions::new(seed)
                .observer(memory.clone())
                .fields(fields),
            |_| async { Ok(()) },
        ))
        .unwrap();
        let events = memory.all();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_truncated());
        assert_eq!(events[0].str("seed"), Some(seed.to_string().as_str()));
        assert_eq!(events[0].str("rng"), Some("chacha20-v1"));
        assert!(events[0].get("wall").unwrap().is_null());
    }

    fn records() -> Vec<Event> {
        let memory = Arc::new(Recorder::default());
        let options = RunOptions::new(Seed::from_u64(42))
            .observer(memory.clone())
            .fields(crate::events::Fields::new().with("world", "shop"));
        block_on(lab(options, |cx| async move {
            cx.emit("shop", "order", |e| e.field("item", "pump"));
            cx.sleep(Duration::from_secs(2)).await?;
            cx.emit("shop", "order", |e| e.field("item", "valve"));
            Ok(())
        }))
        .unwrap();
        memory.after(0, 10)
    }

    #[test]
    fn stamps_are_repeatable_and_start_is_automatic() {
        let events = records();
        assert_eq!(events, records());
        assert_eq!(events.len(), 3);
        assert!(events[0].is("run", "start"));
        assert_eq!(events[0].at, Instant::ZERO);
        assert_eq!(events[0].u64("unused"), None);
        assert_eq!(
            events[0]
                .fields
                .iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["world", "wall", "seed", "rng"]
        );
        let start = events[0].to_json();
        assert_eq!(
            start.get("node").and_then(|value| value.as_str()),
            Some("t1")
        );
        assert_eq!(
            start.get("task").and_then(|value| value.as_str()),
            Some("world")
        );
        assert_eq!(events[2].at.since_start(), Duration::from_secs(2));
        assert_eq!(events.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2, 3]);
    }

    #[test]
    fn start_precedes_world_builder_emissions() {
        let memory = Arc::new(Recorder::default());
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(memory.clone()),
            |cx| {
                cx.emit("test", "building", |event| event);
                cx.spawn(|cx| async move {
                    cx.emit("test", "child", |event| event);
                    Ok(())
                });
                async { Ok(()) }
            },
        ))
        .unwrap();
        let events = memory.all();
        assert!(events[0].is("run", "start"));
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].origin.as_ref().unwrap().task, 1);
        assert!(events[1].is("test", "building"));
        assert_eq!(events[2].origin.as_ref().unwrap().task, 2);
    }

    struct Orders(Arc<Recorder>);
    impl Observer for Orders {
        fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
            let fictionet::events::Interest::Event(metadata, _) = interest else {
                return false;
            };
            metadata.source == "shop"
        }
        fn observe(&self, stamp: Stamp, item: Observation<'_>) {
            self.0.observe(stamp, item);
        }
    }

    #[test]
    fn fanout_shares_stamps_and_filters_each_recipient() {
        let all = Arc::new(Recorder::default());
        let orders = Arc::new(Recorder::default());
        let fanout = Fanout::new(vec![all.clone(), Arc::new(Orders(orders.clone()))]);
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(Arc::new(fanout)),
            |cx| async move {
                cx.emit("shop", "order", |e| e.field("item", "pump"));
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(all.of("shop", "order"), orders.of("shop", "order"));
        assert_eq!(orders.after(0, 10)[0].seq, 2);
        assert!(orders.of("run", "start").is_empty());
    }

    struct Ended(Arc<AtomicUsize>);
    impl Observer for Ended {
        fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
            let fictionet::events::Interest::Event(_, _) = interest else {
                return false;
            };
            false
        }
        fn observe(&self, _: Stamp, _: Observation<'_>) {
            panic!("filtered record");
        }
        fn end(&self, _: Instant) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn filtered_events_do_not_build_and_end_is_once() {
        let ended = Arc::new(AtomicUsize::new(0));
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(Arc::new(Ended(ended.clone()))),
            |cx| async move {
                cx.emit("shop", "order", |_| panic!("filtered event was built"));
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(ended.load(Ordering::Relaxed), 1);
    }
}
