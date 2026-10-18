use std::sync::Arc;

use crate::time::Instant;
use crate::{Cx, sync::Mutex};

use super::{ConnInfo, Event};

/// Metadata available before constructing an event.
#[derive(Clone, Copy, Debug)]
pub struct Metadata {
    /// The service or component reporting the fact.
    pub source: &'static str,
    /// The kind of fact.
    pub kind: &'static str,
}

/// Order and time assigned by the run, before fan-out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// Sequence number, starting at one after interest filtering.
    pub seq: u64,
    /// Time on the run's clock.
    pub at: Instant,
}

/// A borrowed observation. Additional typed streams may be added later.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum Observation<'a> {
    /// A structured service or network fact.
    Event(&'a Event),
}

/// A run's immutable observation destination.
///
/// Delivery is synchronous and serialized. Implementations must return promptly
/// and must not call back into the world. I/O belongs on a bounded worker queue.
/// Interest must stay fixed for repeatable lab evidence. Connection context is
/// explicit, including during the interest check.
pub trait Observer: Send + Sync + 'static {
    /// Whether constructing this event is useful.
    fn enabled(&self, metadata: Metadata, connection: &ConnInfo) -> bool;
    /// Receives a borrowed fact with its run-assigned stamp.
    fn observe(&self, stamp: Stamp, observation: Observation<'_>);
    /// Seals input when the run ends, including cancellation or drop.
    fn end(&self, _at: Instant) {}
}

/// A fixed set of destinations sharing one event and stamp.
pub struct Fanout(Vec<Arc<dyn Observer>>);

impl Fanout {
    /// Combines the destinations. Their interest filters are unioned.
    pub fn new(observers: Vec<Arc<dyn Observer>>) -> Self {
        Self(observers)
    }
}

impl Observer for Fanout {
    fn enabled(&self, metadata: Metadata, connection: &ConnInfo) -> bool {
        self.0.iter().any(|o| o.enabled(metadata, connection))
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation;
        let metadata = Metadata {
            source: event.source,
            kind: event.kind,
        };
        for observer in &self.0 {
            if observer.enabled(metadata, &event.conn) {
                observer.observe(stamp, observation);
            }
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
            .enabled(Metadata { source, kind }, self.connection)
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

pub(crate) struct Dispatch {
    observer: Option<Arc<dyn Observer>>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    seq: u64,
    ended: bool,
}

impl Dispatch {
    pub(crate) fn new(observer: Option<Arc<dyn Observer>>) -> Self {
        Self {
            observer,
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn enabled(&self, metadata: Metadata, connection: &ConnInfo) -> bool {
        self.observer
            .as_ref()
            .is_some_and(|o| o.enabled(metadata, connection))
    }

    pub(crate) fn emit(&self, mut event: Event, at: impl FnOnce() -> Instant) {
        let Some(observer) = &self.observer else {
            return;
        };
        let mut state = self.state.lock();
        if state.ended {
            return;
        }
        state.seq += 1;
        let stamp = Stamp {
            seq: state.seq,
            at: at(),
        };
        event.seq = stamp.seq;
        event.at = stamp.at;
        observer.observe(stamp, Observation::Event(&event));
    }

    pub(crate) fn end(&self, at: impl FnOnce() -> Instant) {
        let Some(observer) = &self.observer else {
            return;
        };
        let mut state = self.state.lock();
        if !state.ended {
            state.ended = true;
            observer.end(at());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Limits, Memory};
    use crate::{RunOptions, Seed, block_on, lab};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn absent_observer_does_not_build_events() {
        block_on(lab(Seed::from_u64(1), |cx| async move {
            assert!(!cx.event_enabled("shop", "order"));
            cx.emit("shop", "order", |_| panic!("unobserved event was built"));
            let conn = ConnInfo::default();
            cx.emitter(&conn).emit("shop", "order", |_| {
                panic!("unobserved connection event was built")
            });
            Ok(())
        }))
        .unwrap();
        let dispatch = Dispatch::new(None);
        dispatch.emit(Event::new("shop", "order"), || panic!("clock read"));
        assert_eq!(dispatch.state.lock().seq, 0);
    }

    fn records() -> Vec<Event> {
        let memory = Arc::new(Memory::default());
        let options = RunOptions::new(Seed::from_u64(42)).observer(memory.clone());
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
        assert_eq!(events[2].at.since_start(), Duration::from_secs(2));
        assert_eq!(events.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2, 3]);
    }

    struct Orders(Arc<Memory>);
    impl Observer for Orders {
        fn enabled(&self, metadata: Metadata, _: &ConnInfo) -> bool {
            metadata.source == "shop"
        }
        fn observe(&self, stamp: Stamp, item: Observation<'_>) {
            self.0.observe(stamp, item);
        }
    }

    #[test]
    fn fanout_shares_stamps_and_filters_each_recipient() {
        let all = Arc::new(Memory::default());
        let orders = Arc::new(Memory::default());
        let fanout = Fanout::new(vec![all.clone(), Arc::new(Orders(orders.clone()))]);
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(Arc::new(fanout)),
            |cx| async move {
                cx.emit("shop", "order", |e| e.field("item", "pump"));
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(
            all.checked_of("shop", "order").unwrap(),
            orders.checked_of("shop", "order").unwrap()
        );
        assert_eq!(orders.after(0, 10)[0].seq, 2);
        assert!(orders.checked_of("run", "start").unwrap().is_empty());
    }

    #[test]
    fn memory_flood_is_bounded_and_cannot_be_graded() {
        let memory = Arc::new(Memory::new(Limits::new(3, 4096)));
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(memory.clone()),
            |cx| async move {
                for i in 0..1000u64 {
                    cx.emit("shop", "order", |e| e.field("item", i));
                }
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(memory.retained().0, 3);
        assert!(memory.retained().1 <= 4096);
        assert_eq!(memory.dropped(), 998);
        assert_eq!(memory.checked_of("shop", "order").unwrap_err().dropped, 998);
        assert!(memory.checked_of("unrelated", "kind").is_err());
        assert_eq!(memory.after(0, usize::MAX).len(), 3);
    }

    #[test]
    fn oversized_events_are_rejected_without_evicting_retained_evidence() {
        let memory = Memory::new(Limits::new(4, 2048));
        memory.observe(
            Stamp {
                seq: 1,
                at: Instant::ZERO,
            },
            Observation::Event(&Event::new("shop", "order")),
        );
        memory.observe(
            Stamp {
                seq: 2,
                at: Instant::ZERO,
            },
            Observation::Event(&Event::new("shop", "order").summary("x".repeat(4096))),
        );
        assert_eq!(memory.retained().0, 1);
        assert_eq!(memory.dropped(), 1);
        assert_eq!(memory.last(), 2);
        assert_eq!(memory.after(0, 4)[0].seq, 1);
    }

    struct Ended(Arc<AtomicUsize>);
    impl Observer for Ended {
        fn enabled(&self, _: Metadata, _: &ConnInfo) -> bool {
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
