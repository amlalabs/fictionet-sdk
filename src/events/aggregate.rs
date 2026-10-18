use std::sync::Arc;
use std::time::Duration;

use crate::stdlib::protocols::json::Value;
use crate::sync::Mutex;
use crate::time::Instant;

use super::{ConnInfo, Event, Limits, Metadata, Observation, Observer, Stamp};

/// Optional, bounded aggregation of facts marked with [`Event::repeat`].
///
/// Matching source, kind, level, connection, task, summary and identifying fields
/// share a window. Numeric detail becomes a `[low, high]` range; other detail
/// must match. Summaries carry `count`, `first_seq` and `last_seq`, using the last
/// occurrence's stamp. Single occurrences keep their original fields.
///
/// Windows use run time. The next event after the window expires, an ordinary
/// event, capacity pressure, or [`Observer::end`] delivers pending facts in
/// sequence order. Reads of the destination never flush windows. With fixed
/// limits and inputs this is deterministic, including in labs. Early delivery
/// under pressure loses no facts, but the destination can still overflow.
pub struct Aggregate {
    next: Arc<dyn Observer>,
    window: Duration,
    limits: Limits,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    pending: Vec<Pending>,
    bytes: usize,
    start: Option<Instant>,
    ended: bool,
}

struct Pending {
    event: Event,
    first: u64,
    count: u64,
}

impl Aggregate {
    /// Wraps a destination with one-second windows, at most 1,024 distinct
    /// facts and two MiB of pending event storage.
    pub fn new(next: Arc<dyn Observer>) -> Self {
        Self::with_limits(next, Duration::from_secs(1), Limits::new(1024, 2 << 20))
    }

    /// Sets run-time windows and count and byte bounds. Zero disables batching.
    pub fn with_limits(next: Arc<dyn Observer>, window: Duration, limits: Limits) -> Self {
        Self {
            next,
            window,
            limits,
            state: Mutex::new(State::default()),
        }
    }

    fn flush(&self, state: &mut State) {
        state.pending.sort_unstable_by_key(|p| p.event.seq);
        for mut pending in state.pending.drain(..) {
            if pending.count > 1 {
                pending.event.fields.set("count", pending.count);
                pending.event.fields.set("first_seq", pending.first);
                pending.event.fields.set("last_seq", pending.event.seq);
            }
            self.deliver(&pending.event);
        }
        state.bytes = 0;
        state.start = None;
    }

    fn deliver(&self, event: &Event) {
        self.next.observe(
            Stamp {
                seq: event.seq,
                at: event.at,
            },
            Observation::Event(event),
        );
    }
}

impl Observer for Aggregate {
    fn enabled(&self, metadata: Metadata, connection: &ConnInfo) -> bool {
        self.next.enabled(metadata, connection)
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation;
        let mut state = self.state.lock();
        if state.ended {
            return;
        }
        if event.repeat.is_none()
            || state
                .start
                .is_some_and(|start| stamp.at >= start + self.window)
        {
            self.flush(&mut state);
        }
        if event.repeat.is_none() || self.window.is_zero() {
            self.next.observe(stamp, observation);
            return;
        }
        if let Some(pending) = state.pending.iter_mut().find(|p| matches(&p.event, event)) {
            for name in event.repeat.as_ref().unwrap() {
                if let Some(n) = event.u64(name) {
                    let old = pending.event.get(name).unwrap();
                    let (low, high) = range(old).unwrap();
                    pending.event.fields.set(
                        name,
                        Value::Array(vec![low.min(n).into(), high.max(n).into()]),
                    );
                }
            }
            pending.count += 1;
            pending.event.seq = stamp.seq;
            pending.event.at = stamp.at;
            return;
        }
        // Reserve space for numeric ranges and summary fields before copying.
        let size = event
            .size()
            .saturating_add(event.repeat.as_ref().unwrap().len().saturating_mul(256) + 1024);
        if state.pending.len() >= self.limits.events
            || size > self.limits.bytes.saturating_sub(state.bytes)
        {
            self.flush(&mut state);
        }
        if self.limits.events == 0 || size > self.limits.bytes {
            self.next.observe(stamp, observation);
            return;
        }
        state.start.get_or_insert(stamp.at);
        let mut event = event.clone();
        event.seq = stamp.seq;
        event.at = stamp.at;
        state.pending.push(Pending {
            event,
            first: stamp.seq,
            count: 1,
        });
        state.bytes += size;
    }

    fn lost(&self, count: u64) {
        self.next.lost(count);
    }

    fn end(&self, at: Instant) {
        let mut state = self.state.lock();
        if !state.ended {
            state.ended = true;
            self.flush(&mut state);
            self.next.end(at);
        }
    }
}

fn range(value: &Value) -> Option<(u64, u64)> {
    if let Some(n) = value.as_u64() {
        Some((n, n))
    } else if let Value::Array(values) = value {
        Some((values.first()?.as_u64()?, values.get(1)?.as_u64()?))
    } else {
        None
    }
}

fn matches(a: &Event, b: &Event) -> bool {
    a.source == b.source
        && a.kind == b.kind
        && a.level == b.level
        && a.conn == b.conn
        && a.origin == b.origin
        && a.summary == b.summary
        && a.repeat == b.repeat
        && a.fields.len() == b.fields.len()
        && a.fields
            .iter()
            .zip(b.fields.iter())
            .all(|((name, av), (other, bv))| {
                name == other
                    && (av == bv
                        || (a.repeat.as_ref().unwrap().contains(&name)
                            && range(av).is_some()
                            && bv.as_u64().is_some()))
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Fields, Memory};
    use crate::{RunOptions, Seed, block_on, lab};

    fn flood(read: bool) -> Vec<Event> {
        let memory = Arc::new(Memory::new(Limits::new(8, 32 << 10)));
        let aggregate = Arc::new(Aggregate::new(memory.clone()));
        let inspect = aggregate.clone();
        let evidence = memory.clone();
        block_on(lab(
            RunOptions::new(Seed::from_u64(7)).observer(aggregate),
            |cx| async move {
                for port in 0..65536u32 {
                    cx.emit("net", "blocked", |e| {
                        e.field("why", "refused")
                            .repeat(Fields::new().with("dst_port", port))
                    });
                    if read {
                        assert_eq!(evidence.checked_all()?.len(), 1);
                    }
                }
                {
                    let state = inspect.state.lock();
                    assert_eq!(state.pending.len(), 1);
                    assert!(state.bytes <= 2 << 20);
                }
                cx.sleep(Duration::from_secs(1)).await?;
                cx.emit("shop", "order", |e| e.field("item", "pump"));
                Ok(())
            },
        ))
        .unwrap();
        memory.checked_all().unwrap()
    }

    #[test]
    fn scan_stays_complete_bounded_and_independent_of_reads() {
        let events = flood(false);
        assert_eq!(events, flood(true));
        assert_eq!(events.len(), 3);
        let summary = &events[1];
        assert_eq!(summary.u64("count"), Some(65536));
        assert_eq!(summary.u64("first_seq"), Some(2));
        assert_eq!(summary.u64("last_seq"), Some(65537));
        assert_eq!(summary.seq, 65537);
        assert_eq!(range(summary.get("dst_port").unwrap()), Some((0, 65535)));
        assert!(events[2].is("shop", "order"));
    }

    fn send(observer: &dyn Observer, seq: u64, seconds: u64, key: u32) {
        let event = Event::new("lan", "drop")
            .field("key", key)
            .repeat(Fields::new());
        observer.observe(
            Stamp {
                seq,
                at: Instant::ZERO + Duration::from_secs(seconds),
            },
            Observation::Event(&event),
        );
    }

    #[test]
    fn windows_end_in_sequence_order_and_forward_loss() {
        let memory = Arc::new(Memory::default());
        let aggregate = Aggregate::new(memory.clone());
        send(&aggregate, 1, 0, 1);
        send(&aggregate, 2, 0, 2);
        send(&aggregate, 3, 0, 1);
        assert!(memory.checked_all().unwrap().is_empty());
        send(&aggregate, 4, 1, 1);
        assert_eq!(
            memory
                .after(0, 10)
                .iter()
                .map(|e| e.seq)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        aggregate.end(Instant::ZERO + Duration::from_secs(1));
        assert_eq!(memory.after(3, 10)[0].seq, 4);
        aggregate.end(Instant::ZERO);
        assert_eq!(memory.checked_all().unwrap().len(), 3);
        aggregate.lost(7);
        assert_eq!(memory.checked_all().unwrap_err().dropped, 7);
    }

    #[test]
    fn run_options_aggregate_before_retention_and_fanout() {
        let history = Arc::new(Memory::new(Limits::new(4, 8192)));
        let evidence = Arc::new(Memory::new(Limits::new(4, 8192)));
        block_on(lab(
            RunOptions::new(Seed::from_u64(7))
                .aggregate_events()
                .event_history(history.clone())
                .observer(evidence.clone()),
            |cx| async move {
                for _ in 0..1000 {
                    cx.emit("lan", "drop", |e| e.repeat(Fields::new()));
                }
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(
            history.checked_all().unwrap(),
            evidence.checked_all().unwrap()
        );
        assert_eq!(
            history.checked_of("lan", "drop").unwrap()[0].u64("count"),
            Some(1000)
        );
    }

    #[test]
    fn different_detail_types_and_connections_remain_distinct() {
        let memory = Arc::new(Memory::default());
        let aggregate = Aggregate::new(memory.clone());
        for (seq, value, id) in [
            (1, Value::Array(vec![1u64.into(), 2u64.into()]), None),
            (2, 1u64.into(), None),
            (3, 1u64.into(), Some(1)),
        ] {
            let event = Event::new("net", "blocked")
                .conn(&ConnInfo {
                    id,
                    ..ConnInfo::default()
                })
                .repeat(Fields::new().with("detail", value));
            aggregate.observe(
                Stamp {
                    seq,
                    at: Instant::ZERO,
                },
                Observation::Event(&event),
            );
        }
        aggregate.end(Instant::ZERO);
        let events = memory.checked_all().unwrap();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| e.u64("count") == Some(1)));
    }

    #[test]
    fn pressure_delivers_early_without_losing_facts() {
        for limits in [
            Limits::new(1, 8192),
            Limits::new(100, 1),
            Limits::new(0, 8192),
        ] {
            let memory = Arc::new(Memory::default());
            let aggregate = Aggregate::with_limits(memory.clone(), Duration::from_secs(1), limits);
            for seq in 1..=10 {
                send(&aggregate, seq, 0, seq as u32);
                let state = aggregate.state.lock();
                assert!(state.pending.len() <= limits.events);
                assert!(state.bytes <= limits.bytes);
            }
            aggregate.end(Instant::ZERO);
            assert_eq!(memory.checked_all().unwrap().len(), 10);
        }
    }
}
