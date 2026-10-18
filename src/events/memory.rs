use std::collections::VecDeque;

use crate::sync::Mutex;

use super::{ConnInfo, Event, Metadata, Observation, Observer, Stamp};

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

/// Evidence was lost; the sample cannot be graded from this observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incomplete {
    /// Number of evicted or rejected events.
    pub dropped: u64,
}

impl std::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "incomplete evidence: {} events lost", self.dropped)
    }
}

impl std::error::Error for Incomplete {}

/// Bounded synchronous evidence, owned by the integrator.
///
/// Oldest events are evicted first. Loss is persistent, even when later reads
/// select a different kind of event. Graders use [`Self::checked_of`]. Reading
/// does not mutate retention or flush pending work.
pub struct Memory {
    limits: Limits,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    events: VecDeque<Event>,
    bytes: usize,
    last: u64,
    dropped: u64,
    waiters: [Option<std::task::Waker>; 32],
}

impl Default for Memory {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Memory {
    /// Creates empty evidence with fixed bounds.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
        }
    }

    /// Reads matching evidence only if no event has been lost.
    pub fn checked_of(&self, source: &str, kind: &str) -> Result<Vec<Event>, Incomplete> {
        self.checked(|event| event.is(source, kind))
    }

    /// Reads all retained evidence only if no event has been lost.
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
        Ok(state.events.iter().filter(|e| pick(e)).cloned().collect())
    }

    /// Waits for matching complete evidence, bounded by the run's clock.
    /// Returns the matches so far at the deadline. Cancellation and retention
    /// loss are errors. At most thirty-two waits may be outstanding.
    pub async fn wait(
        &self,
        cx: &crate::Cx,
        count: usize,
        limit: std::time::Duration,
        mut pick: impl FnMut(&Event) -> bool,
    ) -> crate::Result<Vec<Event>> {
        use std::task::{Poll, Waker};
        struct Wait<'a>(&'a Memory, usize);
        impl Drop for Wait<'_> {
            fn drop(&mut self) {
                self.0.state.lock().waiters[self.1] = None;
            }
        }
        if cx.is_cancelled() {
            return Err(crate::Cancelled.into());
        }
        let slot = {
            let mut state = self.state.lock();
            let slot = state
                .waiters
                .iter()
                .position(Option::is_none)
                .ok_or_else(|| crate::Error::msg("too many evidence waits"))?;
            state.waiters[slot] = Some(Waker::noop().clone());
            slot
        };
        let _wait = Wait(self, slot);
        let deadline =
            crate::time::Instant::from_since_start(cx.now().since_start().saturating_add(limit));
        let mut timer = crate::Timer::new(cx);
        std::future::poll_fn(|task| {
            if cx.is_cancelled() {
                return Poll::Ready(Err(crate::Cancelled.into()));
            }
            let (events, last) = {
                let mut state = self.state.lock();
                state.waiters[slot] = Some(task.waker().clone());
                if state.dropped != 0 {
                    return Poll::Ready(Err(Incomplete {
                        dropped: state.dropped,
                    }
                    .into()));
                }
                (state.events.iter().cloned().collect::<Vec<_>>(), state.last)
            };
            let matches: Vec<_> = events.into_iter().filter(|event| pick(event)).collect();
            if cx.is_cancelled() {
                return Poll::Ready(Err(crate::Cancelled.into()));
            }
            let dropped = self.dropped();
            if dropped != 0 {
                return Poll::Ready(Err(Incomplete { dropped }.into()));
            }
            if matches.len() >= count || cx.now() >= deadline {
                return Poll::Ready(Ok(matches));
            }
            if self.last() != last {
                task.waker().wake_by_ref();
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
            .events
            .iter()
            .filter(|e| e.seq > after)
            .take(max.min(self.limits.events))
            .cloned()
            .collect()
    }

    #[cfg(feature = "observe")]
    pub(crate) fn display_batch(&self, after: u64, max: usize) -> (Vec<Event>, u64, u64) {
        let state = self.state.lock();
        (
            state
                .events
                .iter()
                .filter(|e| e.seq > after)
                .take(max.min(self.limits.events))
                .cloned()
                .collect(),
            state.last,
            state.dropped,
        )
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
        (state.events.len(), state.bytes)
    }
}

impl Observer for Memory {
    fn lost(&self, count: u64) {
        let mut state = self.state.lock();
        state.dropped = state.dropped.saturating_add(count);
        for waker in state.waiters.iter().flatten() {
            waker.wake_by_ref();
        }
    }

    fn enabled(&self, _: Metadata, _: &ConnInfo) -> bool {
        true
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation;
        let size = event.size();
        let mut state = self.state.lock();
        state.last = stamp.seq;
        for waker in state.waiters.iter().flatten() {
            waker.wake_by_ref();
        }
        if self.limits.events == 0 || size > self.limits.bytes {
            state.dropped += 1;
            return;
        }
        while state.events.len() >= self.limits.events || state.bytes > self.limits.bytes - size {
            let oldest = state
                .events
                .pop_front()
                .expect("retained event exceeds bounds");
            state.bytes -= oldest.size();
            state.dropped += 1;
        }
        let mut event = event.clone();
        event.seq = stamp.seq;
        event.at = stamp.at;
        // Cloning strings can shrink their capacity; charge the retained copy.
        state.bytes += event.size();
        state.events.push_back(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::ms;
    use crate::{RunOptions, Seed, block_on, lab};
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Waker};

    #[test]
    fn waits_are_bounded_and_dropping_them_releases_capacity() {
        let memory = Arc::new(Memory::default());
        block_on(lab(
            RunOptions::new(Seed::from_u64(1)).observer(memory.clone()),
            move |cx| async move {
                let mut waits: Vec<_> = (0..32)
                    .map(|_| Box::pin(memory.wait(&cx, 1, ms(100), |_| false)))
                    .collect();
                {
                    let mut task = Context::from_waker(Waker::noop());
                    for wait in &mut waits {
                        assert!(wait.as_mut().poll(&mut task).is_pending());
                    }
                }
                assert_eq!(
                    memory
                        .wait(&cx, 1, ms(100), |_| false)
                        .await
                        .unwrap_err()
                        .to_string(),
                    "too many evidence waits"
                );
                drop(waits);
                cx.emit("test", "ready", |event| event);
                assert_eq!(
                    memory
                        .wait(&cx, 1, ms(100), |event| event.is("test", "ready"))
                        .await?
                        .len(),
                    1
                );
                assert_eq!(cx.now(), crate::time::Instant::ZERO);
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
                    .wait(&cx, 1, ms(100), |_| {
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
}
