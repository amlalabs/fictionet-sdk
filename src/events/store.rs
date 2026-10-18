#![deny(clippy::let_underscore_must_use)]

use fictionet::sync::{Mutex, MutexGuard};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::task::Waker;

use crate::time::Instant;

use super::repeat::{RepeatKey, Window};
use super::{
    Event, EventLog, Fields, MAX_EVENT_BYTES, MAX_EVENTS, MAX_OPEN_REPEAT_BYTES, MAX_REPEAT_BYTES,
    MAX_REPEATS, REPEAT_WINDOW,
};

/// How many runs of repeats are counted at once. Past this, the oldest
/// count is recorded early.
const OPEN_WINDOWS: usize = 1024;

/// A callback given to [`EventLog::subscribe`].
type Subscriber = Arc<dyn Fn(&Arc<Event>) + Send + Sync>;

/// A subscriber and the events waiting for it, delivered in order.
struct Subscription {
    f: Subscriber,
    delivery: Mutex<Delivery>,
}

/// The events queued for a subscriber, and whether a caller is draining
/// them.
#[derive(Default)]
struct Delivery {
    pending: VecDeque<Arc<Event>>,
    draining: bool,
}

/// Releases the drainer if a callback unwinds. The panic still propagates.
struct Drainer<'a> {
    delivery: &'a Mutex<Delivery>,
    active: bool,
}

impl Drop for Drainer<'_> {
    fn drop(&mut self) {
        if self.active {
            self.delivery.lock().draining = false;
        }
    }
}

impl Subscription {
    /// Called with the store locked, so replay and live events share its order.
    fn enqueue(&self, events: &[Arc<Event>]) {
        self.delivery.lock().pending.extend(events.iter().cloned());
    }

    fn drain(&self) {
        let mut delivery = self.delivery.lock();
        if delivery.draining {
            return;
        }
        delivery.draining = true;
        let mut drainer = Drainer {
            delivery: &self.delivery,
            active: true,
        };
        loop {
            let Some(event) = delivery.pending.pop_front() else {
                // Release ownership while locked, before another caller can take it.
                delivery.draining = false;
                drainer.active = false;
                return;
            };
            drop(delivery);
            (self.f)(&event);
            delivery = self.delivery.lock();
        }
    }
}

/// What a run's log holds.
pub(crate) struct Store {
    pub(super) mode: crate::RunMode,
    pub(super) state: Mutex<State>,
    /// Lines file sinks could not keep up with, or could not write.
    pub(super) lost: Arc<AtomicU64>,
    /// A native writer failed, even if it had no lines left to count.
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    pub(super) writer_failed: Arc<AtomicBool>,
}

/// One bounded part of the log: its events, oldest first.
pub(super) struct Part {
    pub(super) events: VecDeque<Arc<Event>>,
    bytes: usize,
    max: usize,
    max_bytes: usize,
}

impl Part {
    fn new(max: usize, max_bytes: usize) -> Part {
        Part {
            events: VecDeque::new(),
            bytes: 0,
            max,
            max_bytes,
        }
    }

    /// Keeps `event`, of `size` bytes, and drops the oldest past the
    /// bounds. Rejects an event that cannot fit by itself. Returns how
    /// many it dropped or rejected.
    fn push(&mut self, event: Arc<Event>, size: usize) -> u64 {
        if self.max == 0 || size > self.max_bytes {
            return 1;
        }
        self.events.push_back(event);
        self.bytes += size;
        let mut dropped = 0;
        while self.events.len() > self.max || self.bytes > self.max_bytes {
            let Some(old) = self.events.pop_front() else {
                break;
            };
            self.bytes -= old.size();
            dropped += 1;
        }
        dropped
    }
}

pub(super) struct State {
    /// Every event but repeats.
    pub(super) events: Part,
    pub(super) repeats: Part,
    /// The number of the last event recorded.
    pub(super) last: u64,
    /// How many events were dropped for the limits.
    pub(super) dropped: u64,
    /// The latest time an event was recorded at.
    clock: Instant,
    /// The runs of repeats being counted.
    open: HashMap<Arc<RepeatKey>, Window>,
    /// Bytes charged to open keys and windows, apart from either history.
    open_bytes: usize,
    max_open_bytes: usize,
    /// The same, oldest first, each with when its count is due.
    due: VecDeque<(Instant, Arc<RepeatKey>)>,
    pub(super) waiters: BTreeMap<u64, Waker>,
    pub(super) next_waiter: u64,
    /// Shared, so recording takes a reference count, not a copy.
    subscribers: Arc<[Arc<Subscription>]>,
    /// Whether the run is over.
    pub(super) closed: bool,
    /// The file writers' threads, joined when the run is over.
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    pub(super) writers: Vec<super::sink::Writer>,
}

impl State {
    pub(super) fn next_repeat(&self) -> Option<Instant> {
        self.due
            .iter()
            .find_map(|(at, key)| (self.open[key].count > 0).then_some(*at))
    }

    /// Numbers and keeps `event`, adding it to `out` for subscribers.
    fn keep(&mut self, mut event: Event, repeat: bool, out: &mut Vec<Arc<Event>>) {
        self.last += 1;
        event.seq = self.last;
        let size = event.size();
        let event = Arc::new(event);
        let part = if repeat {
            &mut self.repeats
        } else {
            &mut self.events
        };
        self.dropped += part.push(event.clone(), size);
        if !self.subscribers.is_empty() {
            out.push(event);
        }
    }

    /// Moves the clock to `at`, recording the counts that are due by then.
    fn advance(&mut self, at: Instant, out: &mut Vec<Arc<Event>>) {
        self.clock = self.clock.max(at);
        while self.due.front().is_some_and(|(due, _)| *due <= self.clock) {
            self.close_oldest(out);
        }
    }

    /// Records the count of the oldest run of repeats, and forgets it.
    fn close_oldest(&mut self, out: &mut Vec<Arc<Event>>) {
        let Some((_, key)) = self.due.pop_front() else {
            return;
        };
        if let Some(window) = self.open.remove(&key) {
            self.open_bytes -= key.size() + window.size();
            if let Some(event) = window.summary() {
                self.keep(event, true, out);
            }
        }
    }
}

impl Store {
    pub(crate) fn new(mode: crate::RunMode) -> Arc<Store> {
        Arc::new(Store {
            mode,
            state: Mutex::new(State {
                events: Part::new(MAX_EVENTS, MAX_EVENT_BYTES),
                repeats: Part::new(MAX_REPEATS, MAX_REPEAT_BYTES),
                last: 0,
                dropped: 0,
                clock: Instant::ZERO,
                open: HashMap::new(),
                open_bytes: 0,
                max_open_bytes: MAX_OPEN_REPEAT_BYTES,
                due: VecDeque::new(),
                waiters: BTreeMap::new(),
                next_waiter: 0,
                subscribers: Arc::new([]),
                closed: false,
                #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
                writers: Vec::new(),
            }),
            lost: Arc::new(AtomicU64::new(0)),
            #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
            writer_failed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Numbers `event`, keeps it, and calls the subscribers.
    pub(crate) fn push(&self, event: Event) {
        let mut out = Vec::new();
        let mut s = self.state.lock();
        s.advance(event.at, &mut out);
        s.keep(event, false, &mut out);
        Store::tell(s, &out, true);
    }

    /// Keeps `event` as a repeat, or counts it. See
    /// [Repeats](crate::events#repeats).
    pub(crate) fn push_repeat(&self, mut event: Event, detail: Fields) {
        let key = RepeatKey {
            source: event.source,
            kind: event.kind,
            conn: std::mem::take(&mut event.conn),
            fields: std::mem::take(&mut event.fields),
        };
        let mut out = Vec::new();
        let mut s = self.state.lock();
        s.advance(event.at, &mut out);
        loop {
            let available = s.max_open_bytes - s.open_bytes;
            let Some(window) = s.open.get_mut(&key) else {
                break;
            };
            let before = window.ranges_size();
            if window.add(event.at, &detail, available) {
                let growth = window.ranges_size() - before;
                s.open_bytes += growth;
                Store::tell(s, &out, true);
                return;
            }
            s.close_oldest(&mut out);
        }
        event.conn = key.conn.clone();
        event.fields = key.fields.clone();
        let first = Window {
            first: event.clone(),
            count: 0,
            last: event.at,
            ranges: Vec::new(),
        };
        let size = key.size() + first.size();
        if size <= s.max_open_bytes {
            while s.open.len() >= OPEN_WINDOWS || s.open_bytes + size > s.max_open_bytes {
                s.close_oldest(&mut out);
            }
            let key = Arc::new(key);
            let due = s.clock + REPEAT_WINDOW;
            s.open_bytes += size;
            s.open.insert(key.clone(), first);
            s.due.push_back((due, key));
        }
        event.fields.extend(detail);
        event.fields.set("count", 1u64);
        s.keep(event, true, &mut out);
        Store::tell(s, &out, true);
    }

    /// Moves the log's clock to `at`, recording the counts of repeats due
    /// by then.
    pub(crate) fn advance(&self, at: Instant) {
        let mut out = Vec::new();
        let mut s = self.state.lock();
        let before = s.last;
        s.advance(at, &mut out);
        let changed = s.last != before;
        Store::tell(s, &out, changed);
    }

    /// Calls the subscribers with `events`, once `s` is unlocked.
    fn tell(mut s: MutexGuard<'_, State>, events: &[Arc<Event>], changed: bool) {
        let waiters = if changed {
            std::mem::take(&mut s.waiters)
        } else {
            BTreeMap::new()
        };
        let subscribers = s.subscribers.clone();
        for subscription in subscribers.iter() {
            subscription.enqueue(events);
        }
        drop(s);
        for waker in waiters.into_values() {
            waker.wake();
        }
        for subscription in subscribers.iter() {
            subscription.drain();
        }
    }

    /// The number of the last event recorded.
    pub(crate) fn last(&self) -> u64 {
        self.state.lock().last
    }

    /// Ends the log with the run: records every count of repeats still
    /// open, forgets the subscribers, and waits for the file writers to
    /// write everything.
    pub(crate) fn close(&self) {
        let mut out = Vec::new();
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        let writers;
        let (subscribers, waiters) = {
            let mut s = self.state.lock();
            while !s.due.is_empty() {
                s.close_oldest(&mut out);
            }
            s.closed = true;
            #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
            {
                writers = std::mem::take(&mut s.writers);
            }
            for subscription in s.subscribers.iter() {
                subscription.enqueue(&out);
            }
            (
                std::mem::replace(&mut s.subscribers, Arc::new([])),
                std::mem::take(&mut s.waiters),
            )
        };
        for waker in waiters.into_values() {
            waker.wake();
        }
        for subscription in subscribers.iter() {
            subscription.drain();
        }
        // The writers end once their senders, in the subscribers, are gone.
        drop(subscribers);
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        for writer in writers {
            writer.join(self);
        }
    }

    /// The events after number `after`, at most `max`, oldest first, with
    /// an `events.dropped` event wherever some of them are gone.
    pub(crate) fn after(&self, after: u64, max: usize) -> Vec<Arc<Event>> {
        let s = self.state.lock();
        after_locked(&s, after, max)
    }
}

/// The events held after number `after`, in order: the two parts merged.
pub(super) fn held(s: &State, after: u64) -> impl Iterator<Item = &Arc<Event>> {
    let a = s.events.events.partition_point(|e| e.seq <= after);
    let b = s.repeats.events.partition_point(|e| e.seq <= after);
    let mut a = s.events.events.range(a..).peekable();
    let mut b = s.repeats.events.range(b..).peekable();
    std::iter::from_fn(move || match (a.peek(), b.peek()) {
        (Some(x), Some(y)) if y.seq < x.seq => b.next(),
        (Some(_), _) => a.next(),
        (None, _) => b.next(),
    })
}

fn after_locked(s: &State, after: u64, max: usize) -> Vec<Arc<Event>> {
    let mut out = Vec::new();
    let mut next = after + 1;
    for e in held(s, after) {
        if e.seq > next {
            if out.len() >= max {
                return out;
            }
            out.push(Arc::new(Event::dropped(e.seq - 1, e.at, e.seq - next)));
        }
        if out.len() >= max {
            return out;
        }
        out.push(e.clone());
        next = e.seq + 1;
    }
    if next <= s.last && out.len() < max {
        out.push(Arc::new(Event::dropped(s.last, s.clock, s.last + 1 - next)));
    }
    out
}

impl EventLog {
    pub(super) fn subscribe_arc(&self, f: Subscriber) {
        let subscription = Arc::new(Subscription {
            f,
            delivery: Mutex::default(),
        });
        {
            let mut s = self.store.state.lock();
            subscription.enqueue(&after_locked(&s, 0, usize::MAX));
            if !s.closed {
                let mut all: Vec<_> = s.subscribers.iter().cloned().collect();
                all.push(subscription.clone());
                s.subscribers = all.into();
            }
        }
        subscription.drain();
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::super::model::{ARC_COUNTS, heap};
    use super::super::tests::Sink;
    use super::super::{ConnInfo, Origin, Sandbox};
    use super::*;
    use crate::stdlib::protocols::json::Value;
    use std::borrow::Cow;

    fn numbered(store: &Store, n: u64) {
        for i in 0..n {
            store.push(Event::new("test", "tick").field("i", i));
        }
    }

    /// The log keeps the latest events, and a reader that fell behind gets
    /// one `events.dropped` event counting what it missed.
    #[test]
    fn the_oldest_events_go_first_and_readers_are_told() {
        let store = Store::new(crate::RunMode::Real);
        let total = MAX_EVENTS as u64 + 10;
        numbered(&store, total);
        let log = EventLog::new(store.clone());
        let held = store.state.lock().events.events.len() as u64;
        assert!(held <= MAX_EVENTS as u64 && store.state.lock().events.bytes <= MAX_EVENT_BYTES);
        let gone = total - held;
        assert!(gone >= 10);
        assert_eq!((log.dropped(), log.recorded()), (gone, total));
        let first = log.after(0, 3);
        assert!(first[0].is("events", "dropped"));
        assert_eq!((first[0].seq, first[0].u64("count")), (gone, Some(gone)));
        assert_eq!((first[1].seq, first[2].seq), (gone + 1, gone + 2));
        // A reader that goes on from the last event it saw misses nothing.
        assert_eq!(log.after(gone + 2, 1)[0].seq, gone + 3);
        // One that read up to the 5th is told it missed the rest of those
        // dropped.
        let late = log.after(5, 2);
        assert_eq!(
            (late[0].seq, late[0].u64("count"), late[1].seq),
            (gone, Some(gone - 5), gone + 1)
        );
        assert!(log.after(total, 10).is_empty());
        assert_eq!(log.all().len() as u64, held + 1);
    }

    #[test]
    fn the_byte_limit_holds() {
        let store = Store::new(crate::RunMode::Real);
        let big = "x".repeat(1 << 20);
        for _ in 0..40 {
            store.push(Event::new("test", "big").summary(big.clone()));
        }
        let s = store.state.lock();
        assert!(s.events.bytes <= MAX_EVENT_BYTES, "{}", s.events.bytes);
        assert!(s.events.events.len() < 40 && s.dropped > 0);
    }

    #[test]
    fn small_limits_reject_without_evicting_and_accept_exact_fits() {
        let event = Arc::new(Event::new("test", "small"));
        let size = event.size();
        for (max, bytes) in [(0, size), (1, 0), (1, size - 1)] {
            let mut part = Part::new(max, bytes);
            assert_eq!(part.push(event.clone(), size), 1);
            assert!(part.events.is_empty());
            assert_eq!(part.bytes, 0);
        }
        let mut part = Part::new(2, size);
        assert_eq!(part.push(event.clone(), size), 0);
        let large = Arc::new(Event::new("test", "large").summary("x"));
        assert_eq!(part.push(large.clone(), large.size()), 1);
        assert!(Arc::ptr_eq(&part.events[0], &event));
        assert_eq!(part.bytes, size);
        assert_eq!(part.push(event.clone(), size), 1);
        assert_eq!((part.events.len(), part.bytes), (1, size));
    }

    #[test]
    fn oversized_events_leave_gaps_but_reach_live_subscribers() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let live = seen.clone();
        log.subscribe(move |e| live.lock().push((e.seq, e.kind)));
        for repeat in [false, true] {
            let oversized = Event::new("test", "oversized").summary("x".repeat(if repeat {
                MAX_REPEAT_BYTES
            } else {
                MAX_EVENT_BYTES
            }));
            for event in [
                oversized.clone(),
                Event::new("test", "before"),
                oversized.clone(),
                Event::new("test", "after"),
                oversized,
            ] {
                if repeat {
                    store.push_repeat(event, Fields::new());
                } else {
                    store.push(event);
                }
            }
        }
        assert_eq!((log.recorded(), log.dropped()), (10, 6));
        assert_eq!(
            seen.lock().iter().map(|e| e.0).collect::<Vec<_>>(),
            (1..=10).collect::<Vec<_>>()
        );
        assert_eq!(seen.lock().iter().filter(|e| e.1 == "oversized").count(), 6);
        let all = log.all();
        assert_eq!(
            all.iter()
                .map(|e| (e.seq, e.u64("count")))
                .collect::<Vec<_>>(),
            [
                (1, Some(1)),
                (2, None),
                (3, Some(1)),
                (4, None),
                (6, Some(2)),
                (7, Some(1)),
                (8, Some(1)),
                (9, Some(1)),
                (10, Some(1))
            ]
        );
        let mut after = 0;
        for expected in &all {
            let page = log.after(after, 1);
            assert_eq!(&page[0], expected);
            after = page[0].seq;
        }
        assert!(log.after(after, 1).is_empty());
        store.close();
        let replay = Arc::new(Mutex::new(Vec::new()));
        let late = replay.clone();
        log.subscribe(move |e| late.lock().push(e.clone()));
        assert_eq!(*replay.lock(), all);
        assert_eq!(log.all(), all, "the closed log keeps its gaps");
    }

    #[test]
    fn metadata_is_charged_even_when_shared() {
        let mut event = Event::new("test", "metadata");
        let empty = event.size();
        let name: Arc<str> = "x".repeat(MAX_EVENT_BYTES / 2).into();
        event.conn = ConnInfo {
            sandbox: Some(Sandbox {
                id: 1,
                name: name.clone(),
                addr: None,
                addr_v6: None,
            }),
            sni: Some(name),
            alpn: Some(Arc::from(&b"h2"[..])),
            ..ConnInfo::default()
        };
        assert_eq!(
            event.size() - empty,
            2 * heap(ARC_COUNTS + MAX_EVENT_BYTES / 2) + heap(ARC_COUNTS + 2)
        );
        assert_eq!(event.clone().size(), event.size());
        let metadata = event.size();
        event.origin = Some(Origin {
            task: 1,
            name: Cow::Borrowed("static"),
            file: file!(),
            line: line!(),
            parent: 0,
        });
        assert_eq!(event.size(), metadata);
        let mut name = String::with_capacity(4096);
        name.push('x');
        let charged = heap(name.capacity());
        event.origin.as_mut().unwrap().name = Cow::Owned(name);
        assert_eq!(event.size(), metadata + charged);
        let store = Store::new(crate::RunMode::Lab);
        store.push(event);
        let s = store.state.lock();
        assert_eq!((s.events.bytes, s.dropped), (0, 1));
        assert!(s.events.events.is_empty());
    }

    /// A subscriber set late gets what the log holds, then what follows.
    #[test]
    fn subscribers_replay_then_follow() {
        let store = Store::new(crate::RunMode::Real);
        numbered(&store, 3);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        log.subscribe(move |e| s.lock().push(e.seq));
        numbered(&store, 2);
        assert_eq!(*seen.lock(), [1, 2, 3, 4, 5]);
        store.close();
        numbered(&store, 1);
        assert_eq!(seen.lock().len(), 5, "a closed log calls no one");
    }

    #[test]
    fn reentrant_recording_follows_the_rest_of_replay() {
        let store = Store::new(crate::RunMode::Lab);
        numbered(&store, 2);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = seen.clone();
        let recording = store.clone();
        log.subscribe(move |event| {
            if event.seq == 1 {
                numbered(&recording, 1);
            }
            out.lock().push(event.seq);
        });
        store.close();
        assert_eq!(*seen.lock(), [1, 2, 3]);
    }

    #[test]
    fn reentrant_recording_reaches_each_subscriber_in_order() {
        for mode in [crate::RunMode::Lab, crate::RunMode::Real] {
            let store = Store::new(mode);
            let log = EventLog::new(store.clone());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let first = seen.clone();
            let recording = store.clone();
            log.subscribe(move |event| {
                if event.seq == 3 {
                    numbered(&recording, 1);
                }
                first.lock().push(event.seq);
            });
            numbered(&store, 2);
            let followed = Arc::new(Mutex::new(Vec::new()));
            let second = followed.clone();
            log.subscribe(move |event| second.lock().push(event.seq));
            let sink = Sink::default();
            log.to_writer(Box::new(sink.clone()));
            numbered(&store, 1);
            store.close();
            assert_eq!(*seen.lock(), [1, 2, 3, 4]);
            assert_eq!(*followed.lock(), [1, 2, 3, 4]);
            let expected: String = log
                .all()
                .iter()
                .map(|event| event.to_line().unwrap() + "\n")
                .collect();
            assert_eq!(*sink.bytes.lock(), expected.as_bytes());
            assert_eq!(log.lost(), 0);
        }
    }

    #[test]
    fn reentrant_recording_follows_all_due_repeat_summaries() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = seen.clone();
        let recording = store.clone();
        log.subscribe(move |event| {
            if event.seq == 3 {
                numbered(&recording, 1);
            }
            out.lock().push(event.seq);
        });
        for dst in ["192.0.2.1", "192.0.2.2"] {
            refused(&store, 0, dst, 1);
            refused(&store, 0, dst, 2);
        }
        store.advance(Instant::ZERO + REPEAT_WINDOW);
        store.close();
        assert_eq!(*seen.lock(), [1, 2, 3, 4, 5]);
    }

    #[test]
    fn a_panicking_callback_releases_its_drainer() {
        let store = Store::new(crate::RunMode::Lab);
        numbered(&store, 2);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = seen.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            log.subscribe(move |event| {
                assert_ne!(event.seq, 1, "callback panic");
                out.lock().push(event.seq);
            });
        }));
        assert!(result.is_err());
        numbered(&store, 1);
        store.close();
        assert_eq!(*seen.lock(), [2, 3]);
    }

    #[test]
    fn concurrent_recording_queues_behind_replay_and_live_callbacks() {
        for replay in [false, true] {
            let store = Store::new(crate::RunMode::Lab);
            let log = EventLog::new(store.clone());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let out = seen.clone();
            let (entered, started) = std::sync::mpsc::channel();
            let (release, resume) = std::sync::mpsc::channel();
            let resume = Mutex::new(resume);
            let callback = move |event: &Event| {
                if event.seq == 1 {
                    entered.send(()).unwrap();
                    resume.lock().recv().unwrap();
                }
                out.lock().push((event.seq, std::thread::current().id()));
            };
            let drainer = if replay {
                numbered(&store, 2);
                std::thread::spawn(move || log.subscribe(callback))
            } else {
                log.subscribe(callback);
                let recording = store.clone();
                std::thread::spawn(move || numbered(&recording, 1))
            };
            let thread = drainer.thread().id();
            started.recv().unwrap();
            numbered(&store, 1);
            let waiting = seen.lock().is_empty();
            release.send(()).unwrap();
            drainer.join().unwrap();
            store.close();
            assert!(waiting, "recording returns while its callback is queued");
            let last = if replay { 3 } else { 2 };
            let expected: Vec<_> = (1..=last).map(|seq| (seq, thread)).collect();
            assert_eq!(*seen.lock(), expected);
        }
    }

    #[test]
    fn closing_queues_repeat_summaries_behind_active_callbacks() {
        let store = Store::new(crate::RunMode::Lab);
        refused(&store, 0, "192.0.2.1", 1);
        refused(&store, 0, "192.0.2.1", 2);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = seen.clone();
        let (entered, started) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let resume = Mutex::new(resume);
        let drainer = std::thread::spawn(move || {
            log.subscribe(move |event| {
                if event.seq == 1 {
                    entered.send(()).unwrap();
                    resume.lock().recv().unwrap();
                }
                out.lock().push(event.seq);
            });
        });
        started.recv().unwrap();
        store.close();
        let waiting = seen.lock().is_empty();
        release.send(()).unwrap();
        drainer.join().unwrap();
        assert!(
            waiting,
            "closing queues the summary without overlapping callbacks"
        );
        assert_eq!(*seen.lock(), [1, 2]);
    }

    fn at(ms: u64) -> Instant {
        Instant::ZERO + std::time::Duration::from_millis(ms)
    }

    fn timed(mut event: Event, ms: u64) -> Event {
        event.at = at(ms);
        event
    }

    /// A refused packet, as the network records one: the port is detail.
    fn refused(store: &Store, ms: u64, dst: &str, port: u16) {
        let mut event = Event::new("net", "blocked")
            .summary(format!("to {dst}"))
            .field("why", "ClosedPort")
            .field("dst", dst);
        event.at = at(ms);
        store.push_repeat(event, Fields::new().with("dst_port", u32::from(port)));
    }

    /// The first of a run of alike repeats is recorded at once; the rest
    /// of its window are counted, and the count recorded when the window
    /// has passed.
    #[test]
    fn repeats_are_counted_once_a_window() {
        let store = Store::new(crate::RunMode::Real);
        let log = EventLog::new(store.clone());
        for port in 1..=1000 {
            refused(&store, u64::from(port / 10), "192.0.2.1", port);
        }
        refused(&store, 50, "192.0.2.2", 22);
        assert_eq!(log.recorded(), 2, "one event for each destination");
        // Within the window, nothing more.
        store.push(timed(Event::new("http", "request"), 500));
        assert_eq!(log.recorded(), 3);
        // Past it, the counts come first, then the event that came after.
        store.push(timed(Event::new("http", "request"), 1200));
        let all = log.all();
        let shown: Vec<_> = all
            .iter()
            .map(|e| {
                (
                    e.kind,
                    e.str("dst"),
                    e.u64("count"),
                    e.get("dst_port").cloned(),
                )
            })
            .collect();
        let ports = |lo: u64, hi: u64| Some(Value::Array(vec![lo.into(), hi.into()]));
        assert_eq!(
            shown,
            [
                (
                    "blocked",
                    Some("192.0.2.1"),
                    Some(1),
                    Some(Value::from(1u32))
                ),
                (
                    "blocked",
                    Some("192.0.2.2"),
                    Some(1),
                    Some(Value::from(22u32))
                ),
                ("request", None, None, None),
                ("blocked", Some("192.0.2.1"), Some(999), ports(2, 1000)),
                ("request", None, None, None),
            ]
        );
        assert_eq!(
            (all[3].at, all[3].summary.as_str()),
            (at(100), "999 more: to 192.0.2.1")
        );
        // A new window after the old one closed starts with a recorded one.
        refused(&store, 1300, "192.0.2.1", 7);
        assert_eq!(
            log.of("net", "blocked").last().and_then(|e| e.u64("count")),
            Some(1)
        );
        // The run's end records every count still open.
        refused(&store, 1301, "192.0.2.1", 8);
        store.close();
        assert_eq!(
            log.of("net", "blocked").last().and_then(|e| e.u64("count")),
            Some(1)
        );
        assert_eq!(log.of("net", "blocked").len(), 5);
    }

    fn assert_open_budget(store: &Store) {
        let s = store.state.lock();
        assert_eq!(s.open.len(), s.due.len());
        assert!(s.open.len() <= OPEN_WINDOWS);
        assert!(s.open_bytes <= s.max_open_bytes);
        assert_eq!(
            s.open_bytes,
            s.open
                .iter()
                .map(|(k, w)| k.size() + w.size())
                .sum::<usize>()
        );
    }

    #[test]
    fn large_distinct_repeat_keys_close_oldest_windows_early() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let live = seen.clone();
        log.subscribe(move |e| live.lock().push((e.u64("i"), e.u64("count"))));
        for i in 0..40u64 {
            let event = Event::new("test", "repeat")
                .field("key", "x".repeat(128 << 10))
                .field("i", i);
            store.push_repeat(event.clone(), Fields::new());
            store.push_repeat(event, Fields::new());
            assert_open_budget(&store);
        }
        assert!(store.state.lock().open.len() < 40);
        assert!(
            log.dropped() > 0,
            "history eviction does not free open keys"
        );
        store.close();
        assert_open_budget(&store);
        assert_eq!(store.state.lock().open_bytes, 0);
        let seen = seen.lock();
        for i in 0..40 {
            assert_eq!(
                seen.iter()
                    .filter(|e| e.0 == Some(i))
                    .map(|e| e.1.unwrap())
                    .sum::<u64>(),
                2
            );
        }
        // Every second occurrence is a summary. They close in insertion order.
        let mut first = [false; 40];
        let summaries: Vec<_> = seen
            .iter()
            .filter_map(|e| {
                let i = e.0.unwrap() as usize;
                std::mem::replace(&mut first[i], true).then_some(i)
            })
            .collect();
        assert_eq!(summaries, (0..40).collect::<Vec<_>>());
    }

    #[test]
    fn a_repeat_too_large_for_a_window_is_recorded_individually() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let event =
            Event::new("test", "repeat").field("key", "x".repeat(MAX_OPEN_REPEAT_BYTES / 2));
        assert!(event.size() < MAX_REPEAT_BYTES);
        for _ in 0..3 {
            store.push_repeat(event.clone(), Fields::new());
            assert_open_budget(&store);
            assert_eq!(store.state.lock().open_bytes, 0);
        }
        assert_eq!((log.recorded(), log.dropped()), (3, 2));
        assert_eq!(log.of("test", "repeat")[0].u64("count"), Some(1));
    }

    #[test]
    fn growing_repeat_ranges_close_windows_before_exceeding_the_budget() {
        let store = Store::new(crate::RunMode::Lab);
        let log = EventLog::new(store.clone());
        let event = Event::new("test", "repeat");
        store.push_repeat(event.clone(), Fields::new());
        let base = store.state.lock().open_bytes;
        store.state.lock().max_open_bytes =
            base + heap(4 * std::mem::size_of::<(&str, u64, u64)>());
        for name in ["a", "b", "c", "d", "e"] {
            store.push_repeat(event.clone(), Fields::new().with(name, 7u64));
            assert_open_budget(&store);
        }
        let all = log.all();
        assert_eq!(
            all.iter()
                .map(|e| e.u64("count").unwrap())
                .collect::<Vec<_>>(),
            [1, 4, 1]
        );
        assert_eq!(
            all[1].get("d"),
            Some(&Value::Array(vec![7u64.into(), 7u64.into()]))
        );
        assert_eq!(all[2].u64("e"), Some(7));
        store.advance(at(1000));
        assert_open_budget(&store);
        assert_eq!(store.state.lock().open_bytes, 0);
    }

    /// Repeats have bounds of their own: a flood of them, more than the
    /// log holds, never pushes out another event, and a reader is told
    /// where repeats are gone.
    #[test]
    fn a_flood_of_repeats_never_pushes_out_other_events() {
        let store = Store::new(crate::RunMode::Real);
        let log = EventLog::new(store.clone());
        for i in 0..10u32 {
            store.push(Event::new("http", "request").field("i", i));
        }
        // Every packet to a new address: a new run each time.
        let flood = MAX_EVENTS as u64 + 10;
        for i in 0..flood {
            refused(
                &store,
                i,
                &format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255),
                1,
            );
            if i == flood / 2 {
                store.push(Event::new("dns", "query"));
            }
        }
        assert_eq!(log.of("http", "request").len(), 10);
        assert_eq!(log.of("dns", "query").len(), 1);
        let s = store.state.lock();
        assert!(s.repeats.events.len() <= MAX_REPEATS && s.repeats.bytes <= MAX_REPEAT_BYTES);
        assert!(s.open.len() <= OPEN_WINDOWS && s.due.len() == s.open.len());
        drop(s);
        // Every number is either an event or counted in an
        // `events.dropped` event, in order.
        let mut next = 1;
        for e in log.all() {
            let first = if e.is("events", "dropped") {
                e.seq + 1 - e.u64("count").unwrap()
            } else {
                e.seq
            };
            assert_eq!(first, next, "{e:?}");
            next = e.seq + 1;
        }
        assert_eq!(next, log.recorded() + 1);
        assert_eq!(
            log.dropped()
                + (log
                    .all()
                    .iter()
                    .filter(|e| !e.is("events", "dropped"))
                    .count() as u64),
            log.recorded()
        );
    }
}
