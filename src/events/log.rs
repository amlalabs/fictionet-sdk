use std::sync::Arc;

use crate::Cx;
use crate::stdlib::json::Value;
use crate::time::Instant;

use super::store::held;
use super::{Event, Fields, Store, float};

/// A run's events. Cheap to clone, and still readable after the run is
/// over. Get one with [`Cx::events`](crate::Cx::events). See the
/// [module docs](crate::events).
#[derive(Clone)]
pub struct EventLog {
    pub(super) store: Arc<Store>,
}

impl std::fmt::Debug for EventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.store.state.lock();
        let held = s.events.events.len() + s.repeats.events.len();
        f.debug_struct("EventLog")
            .field("recorded", &s.last)
            .field("held", &held)
            .field("dropped", &s.dropped)
            .finish()
    }
}

impl EventLog {
    pub(crate) fn new(store: Arc<Store>) -> EventLog {
        EventLog { store }
    }

    /// The events recorded after number `after`, at most `max`, oldest
    /// first. Where the log no longer holds some of them, an
    /// `events.dropped` event stands in their place and counts them (field
    /// `count`), numbered as the last one missed, so the next call can go
    /// on from the last event returned.
    pub fn after(&self, after: u64, max: usize) -> Vec<Event> {
        self.store
            .after(after, max)
            .into_iter()
            .map(|e| (*e).clone())
            .collect()
    }

    /// Every event the log holds, oldest first, with an `events.dropped`
    /// event wherever some were dropped.
    pub fn all(&self) -> Vec<Event> {
        self.after(0, usize::MAX)
    }

    /// The events of `source`'s `kind` the log holds.
    pub fn of(&self, source: &str, kind: &str) -> Vec<Event> {
        let s = self.store.state.lock();
        held(&s, 0)
            .filter(|e| e.is(source, kind))
            .map(|e| (**e).clone())
            .collect()
    }

    /// The number of the last event recorded: how many there have been.
    pub fn recorded(&self) -> u64 {
        self.store.last()
    }

    /// How many events the log has evicted or rejected for its limits.
    pub fn dropped(&self) -> u64 {
        self.store.state.lock().dropped
    }

    /// Records the `run.start` event that anchors the run's clock. It is
    /// dated at the start of the run (`at` 0), and its `wall` field is the
    /// wall-clock time then, in seconds since the Unix epoch, as the run
    /// noted it when it began, so a reader can put every event's `at` on a
    /// calendar. Real runs record it on every target, including browsers.
    /// A lab records `null` because its clock has no wall date. A real run
    /// also records `null` if its wall clock is before the Unix epoch.
    /// The `seed` field is the run's 32-byte seed as 64 lowercase hexadecimal
    /// digits. The `rng` field is `chacha20-v1`, identifying the algorithm and
    /// contiguous-byte consumption convention. `fields` add the world's own
    /// facts, such as the date the world says it is (`world_date`): the world owns its dates, and services take
    /// them from it, never from the host's clock.
    /// [`Net::start`](crate::stdlib::net::Net::start) calls this when it
    /// starts serving. Neither [`run`](crate::run) nor [`lab`](crate::lab)
    /// calls it. Worlds without `Net` call it explicitly, usually before
    /// recording other events. Each call records another event; it is not
    /// deduplicated. Its `at` is zero even if recorded later, while its
    /// sequence number follows the events already recorded.
    pub fn start(&self, fcx: &Cx, fields: Fields) {
        let wall = if fcx.mode() == crate::RunMode::Lab {
            Value::Null
        } else {
            fcx.run
                .start_wall
                .duration_since(crate::sys::UNIX_EPOCH)
                .map_or(Value::Null, |d| float(d.as_secs_f64()))
        };
        let event = Event::new("run", "start")
            .summary("the run started")
            .fields(fields)
            .field("wall", wall)
            .field("seed", fcx.run.environment.seed.to_string())
            .field("rng", "chacha20-v1");
        fcx.record_at(Instant::ZERO, event);
    }

    /// Waits until `n` held events match `pick`, checking every 10 ms on
    /// the run's clock, for at most `limit`. Returns those events, or every
    /// match so far if the time ran out. Each check first records the
    /// counts of [repeats](crate::events#repeats) that are due. Returns early with
    /// [`Cancelled`](crate::Cancelled) if `fcx`'s [region](Cx#regions) is
    /// cancelled. Cancellation is checked before inspecting events and
    /// before returning matches, even if `n` is zero or the deadline has
    /// arrived. The last sleep is shortened to the remaining time. A limit
    /// that overflows the clock's range has no deadline.
    ///
    /// Each check takes a snapshot of the held events, oldest first, then
    /// calls `pick` without holding the log's lock. The predicate may read
    /// or record events in the same log. Events recorded during a check
    /// are considered on the next check.
    pub async fn wait(
        &self,
        fcx: &Cx,
        n: usize,
        limit: std::time::Duration,
        mut pick: impl FnMut(&Event) -> bool,
    ) -> Result<Vec<Event>, crate::Cancelled> {
        let deadline = fcx.now().since_start().saturating_add(limit);
        loop {
            if fcx.is_cancelled() {
                return Err(crate::Cancelled);
            }
            self.store.advance(fcx.now());
            let events: Vec<Arc<Event>> = {
                let s = self.store.state.lock();
                held(&s, 0).cloned().collect()
            };
            let got: Vec<Event> = events
                .into_iter()
                .filter(|e| pick(e))
                .map(|e| (*e).clone())
                .collect();
            if fcx.is_cancelled() {
                return Err(crate::Cancelled);
            }
            let now = fcx.now().since_start();
            if got.len() >= n || now >= deadline {
                return Ok(got);
            }
            let next = now
                .saturating_add(std::time::Duration::from_millis(10))
                .min(deadline);
            fcx.sleep_until(Instant::from_since_start(next)).await?;
        }
    }
}
