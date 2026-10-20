use std::collections::VecDeque;
use std::sync::{Arc, Weak};
use std::task::{Poll, Waker};

use fictionet::sync::Mutex;

use fictionet::events::{Event, Observation, Observer, Stamp};

/// Independent count and byte bounds for retained or queued events.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum number of events.
    pub events: usize,
    /// Maximum retained event bytes, as counted by [`Event::size`].
    pub bytes: usize,
}

impl Limits {
    /// Sets both bounds. Zero refuses every event.
    pub const fn new(events: usize, bytes: usize) -> Self {
        Self { events, bytes }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(super::MAX_EVENTS, super::MAX_EVENT_BYTES)
    }
}

/// Events were lost; the sample cannot be graded from this observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incomplete {
    /// Number of evicted or rejected events.
    pub dropped: u64,
}

impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "incomplete history: {} events lost", self.dropped)
    }
}

impl std::error::Error for Incomplete {}

/// Bounded synchronous event history, owned by the integrator.
///
/// The default reserves separate budgets for ordinary events and network noise
/// marked with [`Event::repeat`]. Oldest events in each budget are evicted first.
/// Ordinary events get 50,000 records and sixteen MiB; noise gets 5,000 records
/// and two MiB.
/// Loss is persistent, even when later reads
/// select a different kind of event. Graders use [`Self::checked_of`]. Reading
/// does not mutate retention or flush pending work.
pub struct Memory {
    limits: Limits,
    noise_limits: Option<Limits>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    history: [History; 2],
    last: u64,
    dropped: u64,
    waiters: Vec<Weak<Mutex<Option<Waker>>>>,
}

#[derive(Default)]
struct History {
    events: VecDeque<Arc<Event>>,
    bytes: usize,
    evicted: u64,
}

/// A consistent history batch and cursors for displaying loss without counting
/// gaps caused by event filtering. Array entries are ordinary events and noise.
#[derive(Default)]
pub struct DisplayBatch {
    /// Retained events in sequence order.
    pub events: Vec<Event>,
    /// Last delivered event sequence.
    pub last: u64,
    /// Total events lost, including rejected events and evictions.
    pub dropped: u64,
    /// Evictions from each retention budget.
    pub evicted: [u64; 2],
    /// Positions through this batch, including earlier evictions, per budget.
    pub position: [u64; 2],
}

impl State {
    fn after(&self, after: u64) -> impl Iterator<Item = &Arc<Event>> {
        let mut parts = self.history.each_ref().map(|history| {
            let start = history.events.partition_point(|event| event.seq <= after);
            history.events.range(start..).peekable()
        });
        std::iter::from_fn(move || {
            let index = match (
                parts[0].peek().map(|e| e.seq),
                parts[1].peek().map(|e| e.seq),
            ) {
                (Some(a), Some(b)) => usize::from(b < a),
                (Some(_), None) => 0,
                (None, Some(_)) => 1,
                (None, None) => return None,
            };
            parts[index].next()
        })
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::with_noise_limits(Limits::default(), Limits::new(5_000, 2 << 20))
    }
}

impl Memory {
    /// Creates an empty history with one shared budget for all raw facts.
    /// Use [`Self::with_noise_limits`] to keep network floods from evicting
    /// ordinary events, as the default does.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            noise_limits: None,
            state: Mutex::new(State::default()),
        }
    }

    /// Reserves independent count and byte bounds for ordinary events and
    /// facts marked with [`Event::repeat`], including aggregate summaries.
    pub fn with_noise_limits(limits: Limits, noise: Limits) -> Self {
        Self {
            noise_limits: Some(noise),
            ..Self::new(limits)
        }
    }

    /// Reads matching retained events only if no event has been lost.
    pub fn checked_of(&self, source: &str, kind: &str) -> Result<Vec<Event>, Incomplete> {
        self.checked(|event| event.is(source, kind))
    }

    /// Reads all retained events only if no event has been lost.
    pub fn checked_all(&self) -> Result<Vec<Event>, Incomplete> {
        self.checked(|_| true)
    }

    fn checked(&self, pick: impl Fn(&Event) -> bool) -> Result<Vec<Event>, Incomplete> {
        let state = self.state.lock();
        if state.dropped != 0 {
            return Err(Incomplete {
                dropped: state.dropped,
            });
        }
        Ok(state
            .after(0)
            .filter(|e| pick(e))
            .map(|e| (**e).clone())
            .collect())
    }

    /// Waits for matching events in a complete history, bounded by the run's clock.
    /// Inspects only events after `after`, once each, using a pure predicate.
    /// Returns the matches so far at the deadline. Cancellation and retention
    /// loss are errors. At most thirty-two waits may be outstanding.
    pub async fn wait(
        &self,
        cx: &fictionet::Cx,
        mut after: u64,
        count: usize,
        limit: std::time::Duration,
        pick: impl Fn(&Event) -> bool,
    ) -> fictionet::Result<Vec<Event>> {
        if cx.is_cancelled() {
            return Err(fictionet::Cancelled.into());
        }
        // The future owns its registration; dropping it releases the waker.
        let wake = Arc::new(Mutex::new(None));
        {
            let mut state = self.state.lock();
            state.waiters.retain(|wait| wait.strong_count() != 0);
            if state.waiters.len() == 32 {
                return Err(fictionet::Error::msg("too many event waits"));
            }
            state.waiters.push(Arc::downgrade(&wake));
        }
        let deadline = fictionet::time::Instant::from_since_start(
            cx.now().since_start().saturating_add(limit),
        );
        let mut timer = fictionet::Timer::new(cx);
        let mut matches = Vec::new();
        std::future::poll_fn(|task| {
            if cx.is_cancelled() {
                return Poll::Ready(Err(fictionet::Cancelled.into()));
            }
            let previous = wake.lock().replace(task.waker().clone());
            drop(previous);
            let events = {
                let state = self.state.lock();
                if state.dropped != 0 {
                    return Poll::Ready(Err(Incomplete {
                        dropped: state.dropped,
                    }
                    .into()));
                }
                state.after(after).cloned().collect::<Vec<_>>()
            };
            for event in events {
                after = event.seq;
                if pick(&event) {
                    matches.push(event);
                }
            }
            if cx.is_cancelled() {
                return Poll::Ready(Err(fictionet::Cancelled.into()));
            }
            let dropped = self.dropped();
            if dropped != 0 {
                return Poll::Ready(Err(Incomplete { dropped }.into()));
            }
            if matches.len() >= count || cx.now() >= deadline {
                return Poll::Ready(Ok(matches.iter().map(|event| (**event).clone()).collect()));
            }
            match timer.poll_until(task, deadline) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(())) => task.waker().wake_by_ref(),
                Poll::Pending => {}
            }
            Poll::Pending
        })
        .await
    }

    /// Reads a bounded display batch. This does not certify completeness.
    pub fn after(&self, after: u64, max: usize) -> Vec<Event> {
        self.state
            .lock()
            .after(after)
            .take(max)
            .map(|e| (**e).clone())
            .collect()
    }

    /// Reads events and loss cursors together. `None` selects the newest `max`
    /// events; `Some(after)` selects events following that sequence.
    pub fn display_batch(&self, after: Option<u64>, max: usize) -> DisplayBatch {
        let state = self.state.lock();
        let skip = if after.is_none() {
            state
                .history
                .iter()
                .map(|h| h.events.len())
                .sum::<usize>()
                .saturating_sub(max)
        } else {
            0
        };
        let events: Vec<_> = state
            .after(after.unwrap_or(0))
            .skip(skip)
            .take(max)
            .map(|e| (**e).clone())
            .collect();
        let through = events.last().map_or(after.unwrap_or(state.last), |e| e.seq);
        DisplayBatch {
            events,
            last: state.last,
            dropped: state.dropped,
            evicted: state.history.each_ref().map(|h| h.evicted),
            position: state.history.each_ref().map(|h| {
                h.evicted
                    .saturating_add(h.events.partition_point(|e| e.seq <= through) as u64)
            }),
        }
    }

    /// Persistent loss count, independent of sequence gaps from filtering.
    pub fn dropped(&self) -> u64 {
        self.state.lock().dropped
    }

    /// Last delivered sequence number.
    pub fn last(&self) -> u64 {
        self.state.lock().last
    }

    /// Retained count and charged bytes.
    pub fn retained(&self) -> (usize, usize) {
        let state = self.state.lock();
        (
            state.history.iter().map(|h| h.events.len()).sum(),
            state.history.iter().map(|h| h.bytes).sum(),
        )
    }
}

impl Observer for Memory {
    fn lost(&self, loss: fictionet::events::Loss) {
        if loss.stream != fictionet::events::Stream::Events {
            return;
        }
        let count = loss.count;
        let mut state = self.state.lock();
        state.dropped = state.dropped.saturating_add(count);
        let waiters: Vec<_> = state.waiters.iter().filter_map(Weak::upgrade).collect();
        drop(state);
        for wait in waiters {
            let waker = wait.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
        let fictionet::events::Interest::Event(_, _) = interest else {
            return false;
        };
        true
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation else {
            return;
        };
        let size = event.size();
        let mut state = self.state.lock();
        state.last = stamp.seq;
        let (index, limits) = match (event.repeat_fields().is_some(), self.noise_limits) {
            (true, Some(limits)) => (1, limits),
            _ => (0, self.limits),
        };
        if limits.events == 0 || size > limits.bytes {
            state.dropped = state.dropped.saturating_add(1);
        } else {
            let history = &mut state.history[index];
            let before = history.evicted;
            while history.events.len() >= limits.events || history.bytes > limits.bytes - size {
                let oldest = history
                    .events
                    .pop_front()
                    .expect("retained event exceeds bounds");
                history.bytes -= oldest.size();
                history.evicted = history.evicted.saturating_add(1);
            }
            let mut event = event.clone();
            event.seq = stamp.seq;
            event.at = stamp.at;
            // Cloning strings can shrink their capacity; charge the retained copy.
            history.bytes += event.size();
            history.events.push_back(Arc::new(event));
            let evicted = history.evicted - before;
            state.dropped = state.dropped.saturating_add(evicted);
        }
        let waiters: Vec<_> = state.waiters.iter().filter_map(Weak::upgrade).collect();
        drop(state);
        for wait in waiters {
            let waker = wait.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::events::{Loss, LossReason, Stream};
    use fictionet::stdlib::network::bottleneck;
    use fictionet::time::{Instant, ms};
    use fictionet::{Interface, Packet, pair};
    use fictionet::{RunOptions, Seed, block_on, lab};
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Waker};

    #[test]
    fn a_flood_of_distinct_noise_preserves_other_events() {
        let memory = Arc::new(Memory::default());
        let retained = memory.clone();
        let flood = crate::MAX_EVENTS as u64 + 10;
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(Arc::new(crate::Aggregate::new(retained))),
            |cx| async move {
                for i in 0..10u64 {
                    cx.emit("http", "request", |event| event.field("i", i));
                }
                for i in 0..flood {
                    cx.emit("net", "blocked", |event| {
                        event
                            .field("destination", i)
                            .repeat(fictionet::events::Fields::new())
                    });
                    if i == flood / 2 {
                        cx.emit("dns", "query", |event| event);
                    }
                }
                Ok(())
            },
        ))
        .unwrap();
        let events = memory.after(0, usize::MAX);
        assert_eq!(
            events.iter().filter(|e| e.is("http", "request")).count(),
            10
        );
        assert_eq!(events.iter().filter(|e| e.is("dns", "query")).count(), 1);
        assert!(events.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        let noise = events.iter().filter(|e| e.is("net", "blocked")).count();
        assert!(noise > 0 && noise <= 5_000);
        assert!(memory.state.lock().history[1].bytes <= 2 << 20);
        assert_eq!(memory.dropped() + noise as u64, flood);
        assert_eq!(
            memory.checked_of("http", "request").unwrap_err().dropped,
            flood - noise as u64
        );
    }

    #[test]
    fn noise_has_independent_count_and_byte_limits() {
        let event = Event::new("net", "blocked").repeat(fictionet::events::Fields::new());
        for limits in [Limits::new(1, 8192), Limits::new(10, event.size())] {
            let memory = Memory::with_noise_limits(Limits::new(2, 8192), limits);
            for (seq, event) in [
                Event::new("http", "request"),
                event.clone(),
                event.clone(),
                Event::new("dns", "query"),
                event.clone(),
            ]
            .iter()
            .enumerate()
            {
                memory.observe(
                    Stamp {
                        stream: fictionet::events::Stream::Events,
                        seq: seq as u64 + 1,
                        at: fictionet::time::Instant::ZERO,
                    },
                    Observation::Event(event),
                );
            }
            assert_eq!(
                memory
                    .after(0, 10)
                    .iter()
                    .map(|e| e.seq)
                    .collect::<Vec<_>>(),
                [1, 4, 5]
            );
            assert_eq!(memory.dropped(), 2);
            let state = memory.state.lock();
            assert!(state.history[1].bytes <= limits.bytes);
            assert!(state.history[1].events.len() <= limits.events);
        }
    }

    #[test]
    fn waits_are_bounded_and_dropping_them_releases_capacity() {
        let memory = Arc::new(Memory::default());
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(memory.clone()),
            move |cx| async move {
                let mut waits: Vec<_> = (0..32)
                    .map(|_| Box::pin(memory.wait(&cx, 0, 1, ms(100), |_| false)))
                    .collect();
                {
                    let mut task = Context::from_waker(Waker::noop());
                    for wait in &mut waits {
                        assert!(wait.as_mut().poll(&mut task).is_pending());
                    }
                }
                assert_eq!(
                    memory
                        .wait(&cx, 0, 1, ms(100), |_| false)
                        .await
                        .unwrap_err()
                        .to_string(),
                    "too many event waits"
                );
                drop(waits);
                cx.emit("test", "ready", |event| event);
                assert_eq!(
                    memory
                        .wait(&cx, 0, 1, ms(100), |event| event.is("test", "ready"))
                        .await?
                        .len(),
                    1
                );
                assert_eq!(cx.now(), fictionet::time::Instant::ZERO);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn a_wait_inspects_only_new_events_after_its_cursor() {
        let memory = Arc::new(Memory::default());
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(memory.clone()),
            |cx| async move {
                cx.emit("test", "old", |event| event);
                let after = memory.last();
                let seen = std::sync::Mutex::new(Vec::new());
                let mut wait = Box::pin(memory.wait(&cx, after, 2, ms(100), |event| {
                    seen.lock().unwrap().push(event.seq);
                    event.is("test", "new")
                }));
                let mut task = Context::from_waker(Waker::noop());
                assert!(wait.as_mut().poll(&mut task).is_pending());
                cx.emit("test", "new", |event| event);
                assert!(wait.as_mut().poll(&mut task).is_pending());
                assert!(wait.as_mut().poll(&mut task).is_pending());
                cx.emit("test", "new", |event| event);
                let Poll::Ready(Ok(events)) = wait.as_mut().poll(&mut task) else {
                    panic!("matches ready")
                };
                assert_eq!(events.len(), 2);
                assert_eq!(*seen.lock().unwrap(), [after + 1, after + 2]);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn waking_a_reader_can_inspect_memory() {
        struct Reader(Arc<Memory>, Arc<std::sync::atomic::AtomicUsize>);
        impl std::task::Wake for Reader {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                let _ = self.0.after(0, 1);
                self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        block_on(lab(
            fictionet::RunOptions::new(Seed::from_u64(1)),
            |cx| async move {
                let memory = Arc::new(Memory::default());
                let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let waker = Waker::from(Arc::new(Reader(memory.clone(), wakes.clone())));
                let mut wait = Box::pin(memory.wait(&cx, 0, 2, ms(100), |_| true));
                assert!(
                    wait.as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                memory.observe(
                    Stamp {
                        stream: fictionet::events::Stream::Events,
                        seq: 1,
                        at: fictionet::time::Instant::ZERO,
                    },
                    Observation::Event(&Event::new("test", "ready")),
                );
                assert!(
                    wait.as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                memory.lost(fictionet::events::Loss {
                    stream: fictionet::events::Stream::Events,
                    reason: fictionet::events::LossReason::Staging,
                    count: 1,
                    bytes: None,
                    seqs: None,
                });
                assert_eq!(wakes.load(std::sync::atomic::Ordering::Relaxed), 2);
                assert!(
                    wait.as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_ready()
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn a_wait_rejects_loss_even_when_it_has_enough_matches() {
        let memory = Arc::new(Memory::new(Limits::new(1, 4096)));
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(memory.clone()),
            move |cx| async move {
                let error = memory
                    .wait(&cx, 0, 1, ms(100), |_| {
                        cx.emit("test", "overflow", |event| event);
                        true
                    })
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.downcast_ref::<Incomplete>(),
                    Some(&Incomplete { dropped: 1 })
                );
                Ok(())
            },
        ))
        .unwrap();
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
        assert_eq!(memory.checked_all().unwrap_err().dropped, 998);
        assert_eq!(memory.after(0, usize::MAX).len(), 3);
    }

    #[test]
    fn oversized_events_are_rejected_without_evicting_retained_events() {
        let memory = Memory::new(Limits::new(4, 2048));
        memory.observe(
            Stamp {
                stream: fictionet::events::Stream::Events,
                seq: 1,
                at: Instant::ZERO,
            },
            Observation::Event(&Event::new("shop", "order")),
        );
        memory.observe(
            Stamp {
                stream: fictionet::events::Stream::Events,
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

    #[test]
    fn only_event_losses_affect_memory() {
        let memory = Memory::default();
        let mut loss = Loss {
            stream: Stream::Keys,
            reason: LossReason::Staging,
            count: 3,
            bytes: None,
            seqs: None,
        };
        memory.lost(loss.clone());
        assert!(memory.checked_all().is_ok());
        loss.stream = Stream::Events;
        memory.lost(loss);
        assert_eq!(memory.checked_of("shop", "order").unwrap_err().dropped, 3);
    }

    /// A bounded observer reports an incomplete history when a flood exceeds
    /// its retention budget; the bottleneck still reports every raw drop.
    #[test]
    fn a_flooded_bottleneck_reports_raw_drops_and_retention_loss() {
        use crate::{Limits, Memory};
        use std::sync::Arc;
        let flood = crate::MAX_EVENTS + 10_000;
        let bounded = Arc::new(Memory::with_noise_limits(
            Limits::new(3, 4 << 10),
            Limits::new(29, 28 << 10),
        ));
        let aggregated = Arc::new(Memory::new(Limits::new(32, 32 << 10)));
        let options = fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(
            std::sync::Arc::new(fictionet::events::Fanout::new(vec![
                bounded.clone(),
                Arc::new(crate::Aggregate::new(aggregated.clone())),
            ])),
        );
        block_on(fictionet::lab(options, move |fcx| async move {
            let (mut sandbox, inner) = pair();
            let _far = bottleneck(&fcx, 0, 10, inner);
            fcx.emit("http", "request", |event| event);
            for i in 0..flood {
                sandbox.send(Packet(vec![0x45; 20]));
                if i % 32 == 31 {
                    fcx.yield_now().await?;
                }
            }
            fcx.idle().await?;
            fcx.emit("http", "request", |event| event);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
        let raw = bounded.after(0, usize::MAX);
        assert_eq!(
            raw.iter()
                .filter(|event| event.is("http", "request"))
                .count(),
            2
        );
        let raw_drops: Vec<_> = raw
            .iter()
            .filter(|event| event.is("bottleneck", "drop"))
            .collect();
        for event in &raw_drops {
            assert!(event.get("count").is_none());
            assert_eq!(event.str("why"), Some("the queue was full"));
        }
        assert_eq!(
            bounded.dropped() + raw_drops.len() as u64,
            flood as u64 - 10
        );
        assert!(bounded.checked_all().is_err());
        assert!(bounded.dropped() > 0);
        let (count, bytes) = bounded.retained();
        assert!(count <= 32 && bytes <= 32 << 10);
        assert_eq!(aggregated.checked_of("http", "request").unwrap().len(), 2);
        let drops = aggregated.checked_of("bottleneck", "drop").unwrap();
        assert!(!drops.is_empty() && drops.len() <= 4, "{drops:?}");
        assert_eq!(
            drops
                .iter()
                .map(|event| event.u64("count").unwrap_or(1))
                .sum::<u64>(),
            flood as u64 - 10
        );
    }
}
