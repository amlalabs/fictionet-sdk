use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::protocols::json::Value;
use fictionet::sync::Mutex;
use fictionet::time::Instant;

use crate::Limits;
use fictionet::events::{Event, Observation, Observer, Stamp};

/// Optional, bounded aggregation of facts marked with [`Event::repeat`].
/// Other streams and their losses pass through unchanged.
///
/// Matching source, kind, level, connection, task, summary and identifying fields
/// share a window. Numeric detail becomes a `[low, high]` range; other detail
/// must match. Summaries carry `count`, `first_seq` and `last_seq`, using the last
/// occurrence's stamp. The first occurrence is delivered immediately; only
/// subsequent occurrences are counted in summaries.
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

    fn deliver(&self, event: &Event) {
        self.next.observe(
            Stamp {
                stream: fictionet::events::Stream::Events,
                seq: event.seq,
                at: event.at,
            },
            Observation::Event(event),
        );
    }
}

impl Observer for Aggregate {
    fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
        self.next.enabled(interest)
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation else {
            self.next.observe(stamp, observation);
            return;
        };
        let mut state = self.state.lock();
        if state.ended {
            return;
        }
        let mut ready = Vec::new();
        let forward = state.stage(stamp, event, self.window, self.limits, &mut ready);
        drop(state);
        for event in ready {
            self.deliver(&event);
        }
        if forward {
            self.next.observe(stamp, observation);
        }
    }

    fn lost(&self, loss: fictionet::events::Loss) {
        self.next.lost(loss);
    }

    fn end(&self, at: Instant) {
        let mut state = self.state.lock();
        if !state.ended {
            state.ended = true;
            let mut ready = Vec::new();
            state.flush(&mut ready);
            drop(state);
            for event in ready {
                self.deliver(&event);
            }
            self.next.end(at);
        }
    }
}

impl State {
    fn flush(&mut self, ready: &mut Vec<Event>) {
        self.deliver_repeats(ready);
        self.pending.clear();
        self.bytes = 0;
        self.start = None;
    }

    fn deliver_repeats(&mut self, ready: &mut Vec<Event>) {
        self.pending.sort_unstable_by_key(|p| p.event.seq);
        for pending in &mut self.pending {
            if pending.count == 0 {
                continue;
            }
            let mut event = pending.event.clone();
            if pending.count > 1 {
                event.fields.set("count", pending.count);
                event.fields.set("first_seq", pending.first);
                event.fields.set("last_seq", event.seq);
            }
            ready.push(event);
            pending.count = 0;
        }
    }

    fn stage(
        &mut self,
        stamp: Stamp,
        event: &Event,
        window: Duration,
        limits: Limits,
        ready: &mut Vec<Event>,
    ) -> bool {
        if event.repeat_fields().is_none()
            || self.start.is_some_and(|start| {
                stamp.at.since_start().saturating_sub(start.since_start()) >= window
            })
        {
            self.flush(ready);
        }
        if event.repeat_fields().is_none() || window.is_zero() {
            return true;
        }
        if let Some(pending) = self.pending.iter_mut().find(|p| matches(&p.event, event)) {
            if pending.count == 0 {
                pending.event = event.clone();
                pending.first = stamp.seq;
            }
            for name in event.repeat_fields().unwrap() {
                if pending.count != 0
                    && let Some(n) = event.u64(name)
                    && let Some((low, high)) = pending.event.get(name).and_then(range)
                {
                    pending.event.fields.set(
                        name,
                        Value::Array(vec![low.min(n).into(), high.max(n).into()]),
                    );
                }
            }
            pending.count += 1;
            pending.event.seq = stamp.seq;
            pending.event.at = stamp.at;
            return false;
        }
        // Reserve space for numeric ranges and summary fields before copying.
        let size = event
            .size()
            .saturating_add(event.repeat_fields().unwrap().len().saturating_mul(256))
            .saturating_add((event.fields.len() + 3) * std::mem::size_of::<(&str, Value)>())
            .saturating_add(1024);
        if self.pending.len() >= limits.events || size > limits.bytes.saturating_sub(self.bytes) {
            self.flush(ready);
        }
        if limits.events == 0 || size > limits.bytes {
            return true;
        }
        // A new first occurrence must not overtake buffered repeats.
        self.deliver_repeats(ready);
        self.start.get_or_insert(stamp.at);
        let mut event = event.clone();
        event.seq = stamp.seq;
        event.at = stamp.at;
        self.pending.push(Pending {
            event,
            first: stamp.seq,
            count: 0,
        });
        self.bytes += size;
        true
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
        && a.same_origin(b)
        && a.summary == b.summary
        && a.repeat_fields() == b.repeat_fields()
        && a.fields.len() == b.fields.len()
        && a.fields
            .iter()
            .zip(b.fields.iter())
            .all(|((name, av), (other, bv))| {
                name == other
                    && (av == bv
                        || (a.repeat_fields().unwrap().contains(&name)
                            && range(av).is_some()
                            && bv.as_u64().is_some()))
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Memory;
    use fictionet::events::ConnInfo;
    use fictionet::events::Fields;
    use fictionet::{RunOptions, Seed, block_on, lab};

    fn flood(read: bool) -> Vec<Event> {
        let memory = Arc::new(Memory::new(Limits::new(8, 32 << 10)));
        let aggregate = Arc::new(Aggregate::new(memory.clone()));
        let inspect = aggregate.clone();
        let grader = memory.clone();
        block_on(lab(
            RunOptions::new(Seed::from_u64(7)).observer(aggregate),
            |cx| async move {
                for port in 0..65536u32 {
                    cx.emit("net", "blocked", |e| {
                        e.field("why", "refused")
                            .repeat(Fields::new().with("dst_port", port))
                    });
                    if read {
                        assert_eq!(grader.checked_all()?.len(), 2);
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
        assert_eq!(events.len(), 4);
        assert!(events[1].get("count").is_none());
        let summary = &events[2];
        assert_eq!(summary.u64("count"), Some(65535));
        assert_eq!(summary.u64("first_seq"), Some(3));
        assert_eq!(summary.u64("last_seq"), Some(65537));
        assert_eq!(summary.seq, 65537);
        assert_eq!(range(summary.get("dst_port").unwrap()), Some((1, 65535)));
        assert!(events[3].is("shop", "order"));
    }

    fn send(observer: &dyn Observer, seq: u64, seconds: u64, key: u32) {
        let event = Event::new("lan", "drop")
            .field("key", key)
            .repeat(Fields::new());
        observer.observe(
            Stamp {
                stream: fictionet::events::Stream::Events,
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
        assert_eq!(memory.checked_all().unwrap().len(), 2);
        send(&aggregate, 4, 1, 1);
        assert_eq!(
            memory
                .after(0, 10)
                .iter()
                .map(|e| e.seq)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        aggregate.end(Instant::ZERO + Duration::from_secs(1));
        assert_eq!(memory.after(3, 10)[0].seq, 4);
        aggregate.end(Instant::ZERO);
        assert_eq!(memory.checked_all().unwrap().len(), 4);
        aggregate.lost(fictionet::events::Loss::staged(
            fictionet::events::Stream::Events,
            7,
        ));
        assert_eq!(memory.checked_all().unwrap_err().dropped, 7);
    }

    #[test]
    fn aggregation_precedes_retention_and_fanout() {
        let history = Arc::new(Memory::new(Limits::new(4, 8192)));
        let grader = Arc::new(Memory::new(Limits::new(4, 8192)));
        block_on(lab(
            RunOptions::new(Seed::from_u64(7)).observer(Arc::new(Aggregate::new(Arc::new(
                fictionet::events::Fanout::new(vec![history.clone(), grader.clone()]),
            )))),
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
            grader.checked_all().unwrap()
        );
        assert_eq!(
            history.checked_of("lan", "drop").unwrap()[1].u64("count"),
            Some(999)
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
                    stream: fictionet::events::Stream::Events,
                    seq,
                    at: Instant::ZERO,
                },
                Observation::Event(&event),
            );
        }
        aggregate.end(Instant::ZERO);
        let events = memory.checked_all().unwrap();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|e| e.get("count").is_none()));
    }

    #[test]
    fn summary_fields_fit_the_byte_budget() {
        let mut event = Event::new("test", "repeat");
        for name in "a b c d e f g h i j k l m n o p q r s t u v w x y z aa bb cc dd ee ff"
            .split_whitespace()
        {
            event = event.field(name, true);
        }
        let event = event.repeat(Fields::new());
        let bytes = event.size() + 1024;
        let memory = Arc::new(Memory::default());
        let aggregate = Aggregate::with_limits(
            memory.clone(),
            Duration::from_secs(1),
            Limits::new(10, bytes),
        );
        for seq in 1..=2 {
            aggregate.observe(
                Stamp {
                    stream: fictionet::events::Stream::Events,
                    seq,
                    at: Instant::ZERO,
                },
                Observation::Event(&event),
            );
        }
        aggregate.end(Instant::ZERO);
        let events = memory.checked_all().unwrap();
        assert!(events.iter().all(|event| event.size() <= bytes));
        assert_eq!(
            events
                .iter()
                .map(|event| event.u64("count").unwrap_or(1))
                .sum::<u64>(),
            2
        );
    }

    #[test]
    fn an_unbounded_window_does_not_overflow_run_time() {
        let memory = Arc::new(Memory::default());
        let aggregate = Aggregate::with_limits(memory.clone(), Duration::MAX, Limits::default());
        send(&aggregate, 1, 1, 7);
        send(&aggregate, 2, 2, 7);
        assert_eq!(memory.checked_all().unwrap().len(), 1);
        aggregate.end(Instant::ZERO + Duration::from_secs(2));
        let events = memory.checked_all().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.get("count").is_none()));
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
