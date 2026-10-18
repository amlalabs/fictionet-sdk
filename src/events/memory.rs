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
        let state = self.state.lock();
        if state.dropped != 0 {
            return Err(Incomplete {
                dropped: state.dropped,
            });
        }
        Ok(state
            .events
            .iter()
            .filter(|e| e.is(source, kind))
            .cloned()
            .collect())
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
    fn enabled(&self, _: Metadata, _: &ConnInfo) -> bool {
        true
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation;
        let size = event.size();
        let mut state = self.state.lock();
        state.last = stamp.seq;
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
