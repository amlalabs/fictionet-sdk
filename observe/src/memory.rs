use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Poll, Waker};

use fictionet::sync::Mutex;

use crate::{Admit, Class, LossStatus, Policy, When};
use fictionet::events::{Event, Interest, LossReason, Observation, Observer, Stamp, Stream};

use crate::ring::{Kept, Ring};

impl Kept for Arc<Event> {
    fn stamp(&self) -> Stamp {
        Stamp {
            stream: Stream::Events,
            seq: self.seq,
            at: self.at,
        }
    }
    fn size(&self) -> usize {
        Event::size(self)
    }
}

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
    pub lost: u64,
}

impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "incomplete history: {} events lost", self.lost)
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
    policy: Arc<dyn Policy>,
    bytes: usize,
    state: Mutex<State>,
    retained_bytes: AtomicUsize,
    pub(crate) losses: Arc<Mutex<LossStatus>>,
    pub(crate) loss_streams: usize,
}

#[derive(Default)]
struct State {
    history: Vec<(usize, Ring<Arc<Event>>)>,
    last: u64,
    waiters: Vec<Weak<Mutex<Option<Waker>>>>,
}

impl State {
    fn after(&self, after: u64) -> impl Iterator<Item = &Arc<Event>> {
        crate::ring::after(self.history.iter().map(|(_, ring)| ring), after)
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::with_noise_limits(Limits::default(), crate::policy::NOISE)
    }
}

impl Memory {
    /// Creates an empty history with one shared budget for all raw facts.
    /// Use [`Self::with_noise_limits`] to keep network floods from evicting
    /// ordinary events, as the default does.
    pub fn new(limits: Limits) -> Self {
        Self::with_policy(
            Arc::new(crate::policy::Standard {
                classes: vec![
                    Class::new("events")
                        .count(limits.events)
                        .bytes(limits.bytes),
                ],
            }),
            usize::MAX,
        )
    }

    /// Reserves separate budgets for ordinary and repeating events.
    pub fn with_noise_limits(limits: Limits, noise: Limits) -> Self {
        Self::with_policy(
            Arc::new(crate::policy::Standard {
                classes: vec![
                    Class::new("events")
                        .count(limits.events)
                        .bytes(limits.bytes),
                    Class::new("noise").count(noise.events).bytes(noise.bytes),
                ],
            }),
            usize::MAX,
        )
    }

    pub(crate) fn with_policy(policy: Arc<dyn Policy>, bytes: usize) -> Self {
        Self {
            policy,
            bytes,
            losses: Arc::new(Mutex::new(LossStatus::default())),
            loss_streams: 1,
            state: Mutex::new(State::default()),
            retained_bytes: AtomicUsize::new(0),
        }
    }

    /// Reads matching retained events unless that kind or an unknown kind was lost.
    pub fn checked_of(&self, source: &str, kind: &str) -> Result<Vec<Event>, Incomplete> {
        self.checked(Some((source, kind)), |event| event.is(source, kind))
    }

    /// Reads all retained events only if no event has been lost.
    pub fn checked_all(&self) -> Result<Vec<Event>, Incomplete> {
        self.checked(None, |_| true)
    }

    fn checked(
        &self,
        kind: Option<(&str, &str)>,
        pick: impl Fn(&Event) -> bool,
    ) -> Result<Vec<Event>, Incomplete> {
        let state = self.state.lock();
        let losses = self.losses.lock();
        if kind.map_or(losses.missing_events() != 0, |(source, kind)| {
            losses.incomplete(source, kind)
        }) {
            return Err(Incomplete {
                lost: losses.missing_events(),
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
                let lost = self.losses.lock().events();
                if lost != 0 {
                    return Poll::Ready(Err(Incomplete { lost }.into()));
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
            let lost = self.losses.lock().events();
            if lost != 0 {
                return Poll::Ready(Err(Incomplete { lost }.into()));
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
    pub(crate) fn batch(&self, after: Option<u64>, max: usize) -> crate::ring::Batch<Event> {
        let state = self.state.lock();
        let batch = crate::ring::batch(state.history.iter().map(|(_, ring)| ring), after, max);
        crate::ring::Batch {
            events: batch
                .events
                .into_iter()
                .map(|event| (*event).clone())
                .collect(),
            last: state.last,
            evicted: batch.evicted,
            position: batch.position,
        }
    }

    /// Persistent loss totals for this observer.
    pub fn losses(&self) -> LossStatus {
        self.losses.lock().clone()
    }

    /// Last delivered sequence number.
    pub fn last(&self) -> u64 {
        self.state.lock().last
    }

    /// Retained count and charged bytes.
    pub fn retained(&self) -> (usize, usize) {
        let state = self.state.lock();
        (
            state.history.iter().map(|(_, h)| h.items.len()).sum(),
            state.history.iter().map(|(_, h)| h.bytes).sum(),
        )
    }
}

impl Observer for Memory {
    fn lost(&self, loss: fictionet::events::Loss) {
        if loss.stream != fictionet::events::Stream::Events {
            return;
        }
        self.losses.lock().add(self.loss_streams, loss);
        let state = self.state.lock();
        let waiters: Vec<_> = state.waiters.iter().filter_map(Weak::upgrade).collect();
        drop(state);
        for wait in waiters {
            let waker = wait.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    fn enabled(&self, interest: Interest<'_>) -> bool {
        if !matches!(interest, Interest::Event(..)) {
            return false;
        }
        match self.policy.admit(interest) {
            Admit::Skip => false,
            Admit::Build => true,
            Admit::Class(index) => self
                .policy
                .classes()
                .get(index)
                .is_some_and(|class| class.when == When::Always),
        }
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = &observation else {
            return;
        };
        let index = match self.policy.admit(observation.interest()) {
            Admit::Skip => return,
            Admit::Class(index) => Some(index),
            Admit::Build => self.policy.sort(&observation),
        };
        if let Some(index) = index {
            self.push(stamp, event, index);
            self.wake();
        }
    }
}

impl Memory {
    pub(crate) fn push(&self, stamp: Stamp, event: &Event, index: usize) {
        let Some(class) = self
            .policy
            .classes()
            .get(index)
            .filter(|class| class.when == When::Always)
        else {
            return;
        };
        let size = event.size();
        let mut state = self.state.lock();
        state.last = stamp.seq;
        let mut losses = self.losses.lock();
        let slot = state
            .history
            .iter()
            .position(|(class, _)| *class == index)
            .unwrap_or_else(|| {
                state.history.push((index, Ring::default()));
                state.history.len() - 1
            });
        let history = &mut state.history[slot].1;
        let before = history.bytes;
        if !history.admit(stamp, class.burst) {
            losses.record_event(self.loss_streams, stamp, index, LossReason::Sampling, event);
        } else if class.count == 0 || size > class.bytes.min(self.bytes) {
            losses.record_event(self.loss_streams, stamp, index, LossReason::Overflow, event);
        } else {
            history.make_room(size, class.count, class.bytes, |old| {
                losses.record_event(
                    self.loss_streams,
                    old.stamp(),
                    index,
                    LossReason::Eviction,
                    &old,
                );
            });
            let mut event = event.clone();
            event.seq = stamp.seq;
            event.at = stamp.at;
            history.push(Arc::new(event));
        }
        if history.bytes >= before {
            self.retained_bytes
                .fetch_add(history.bytes - before, Ordering::Relaxed);
        } else {
            self.retained_bytes
                .fetch_sub(before - history.bytes, Ordering::Relaxed);
        }
        if event.is_truncated() {
            losses.record_event(
                self.loss_streams,
                stamp,
                index,
                LossReason::Truncation,
                event,
            );
        }
    }

    pub(crate) fn selected(
        &self,
        selection: &crate::export::Selection,
    ) -> Vec<(usize, Arc<Event>)> {
        let state = self.state.lock();
        let mut events: Vec<_> = state
            .history
            .iter()
            .filter(|(class, _)| selection.class(*class))
            .flat_map(|(class, ring)| {
                ring.items
                    .iter()
                    .filter(|event| {
                        selection.sequence(event.seq)
                            && selection
                                .host(event.conn.sandbox.as_ref().map(|sandbox| &*sandbox.name))
                    })
                    .map(move |event| (*class, event.clone()))
            })
            .collect();
        events.sort_by_key(|(_, event)| event.seq);
        events
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes.load(Ordering::Relaxed)
    }

    pub(crate) fn largest(&self) -> Option<(usize, usize)> {
        self.state
            .lock()
            .history
            .iter()
            .filter(|(_, ring)| !ring.items.is_empty())
            .max_by_key(|(index, ring)| {
                (
                    std::cmp::Reverse(self.policy.classes()[*index].rank),
                    ring.bytes,
                )
            })
            .map(|(index, ring)| (*index, ring.bytes))
    }

    pub(crate) fn evict(&self, index: usize) -> Option<Arc<Event>> {
        let mut state = self.state.lock();
        let event = state
            .history
            .iter_mut()
            .find(|(class, _)| *class == index)?
            .1
            .evict()?;
        self.retained_bytes
            .fetch_sub(event.size(), Ordering::Relaxed);
        self.losses.lock().record_event(
            self.loss_streams,
            event.stamp(),
            index,
            LossReason::Eviction,
            &event,
        );
        Some(event)
    }

    pub(crate) fn wake(&self) {
        let waiters: Vec<_> = self
            .state
            .lock()
            .waiters
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
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
    use fictionet::events::{Loss, Stream};
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
        assert!(memory.state.lock().history[1].1.bytes <= 2 << 20);
        assert_eq!(memory.losses().events() + noise as u64, flood);
        assert_eq!(memory.checked_of("http", "request").unwrap().len(), 10);
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
            assert_eq!(memory.losses().events(), 2);
            let state = memory.state.lock();
            assert!(state.history[1].1.bytes <= limits.bytes);
            assert!(state.history[1].1.items.len() <= limits.events);
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
                memory.lost(fictionet::events::Loss::staged(
                    fictionet::events::Stream::Events,
                    1,
                ));
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
                    Some(&Incomplete { lost: 1 })
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
        assert_eq!(memory.losses().events(), 998);
        assert_eq!(memory.checked_of("shop", "order").unwrap_err().lost, 998);
        assert!(memory.checked_of("unrelated", "kind").unwrap().is_empty());
        assert_eq!(memory.checked_all().unwrap_err().lost, 998);
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
        assert_eq!(memory.losses().events(), 1);
        assert_eq!(memory.last(), 2);
        assert_eq!(memory.after(0, 4)[0].seq, 1);
    }

    #[test]
    fn only_event_losses_affect_memory() {
        let memory = Memory::default();
        let mut loss = Loss::staged(Stream::Keys, 3);
        memory.lost(loss.clone());
        assert!(memory.checked_all().is_ok());
        loss.stream = Stream::Events;
        memory.lost(loss);
        assert_eq!(memory.checked_of("shop", "order").unwrap_err().lost, 3);
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
            bounded.losses().events() + raw_drops.len() as u64,
            flood as u64 - 10
        );
        assert!(bounded.checked_all().is_err());
        assert!(bounded.losses().events() > 0);
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
