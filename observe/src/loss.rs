use std::collections::{BTreeSet, HashMap};

use fictionet::events::{Event, Loss, LossReason, Stamp, Stream};

const EVENT_KINDS: usize = 256;

/// Persistent loss totals. Sequence ranges may be disjoint.
#[derive(Clone, Debug, Default)]
pub struct LossStatus {
    /// Totals by stream, class, cause and known event kind.
    pub streams: Vec<LossEntry>,
    /// Totals whose stream could not fit in the detail budget.
    pub untracked: Vec<LossTotal>,
    by_stream: HashMap<Stream, Vec<usize>>,
    omissions: HashMap<(Option<Stream>, Option<usize>), u64>,
    kinds: BTreeSet<(&'static str, &'static str)>,
    unknown_events: bool,
    missing_kinds: BTreeSet<(&'static str, &'static str)>,
    missing_events: u64,
    events: u64,
}

/// Loss in one stream and policy class.
#[derive(Clone, Debug)]
pub struct LossEntry {
    /// Affected stream.
    pub stream: Stream,
    /// Policy class, or unknown for losses before classification.
    pub class: Option<usize>,
    /// Cause of loss.
    pub reason: LossReason,
    /// Number of affected observations.
    pub count: u64,
    /// Known affected bytes.
    pub bytes: Option<u64>,
    /// Event source and kind, when known.
    pub event: Option<(&'static str, &'static str)>,
}

/// Loss whose stream detail exceeded the configured bound.
#[derive(Clone, Debug)]
pub struct LossTotal {
    /// Policy class, when known.
    pub class: Option<usize>,
    /// Cause of loss.
    pub reason: LossReason,
    /// Number of affected observations.
    pub count: u64,
    /// Known affected bytes.
    pub bytes: u64,
}

impl LossStatus {
    /// Total affected events, including losses without stream detail.
    pub fn events(&self) -> u64 {
        self.events
    }

    pub(crate) fn missing_events(&self) -> u64 {
        self.missing_events
    }

    pub(crate) fn incomplete(&self, source: &str, kind: &str) -> bool {
        self.unknown_events || self.missing_kinds.contains(&(source, kind))
    }

    pub(crate) fn omissions(&self, stream: Stream, class: usize) -> u64 {
        [Some(stream), None]
            .into_iter()
            .flat_map(|stream| {
                [Some(class), None]
                    .into_iter()
                    .map(move |class| (stream, class))
            })
            .map(|key| self.omissions.get(&key).copied().unwrap_or(0))
            .fold(0, u64::saturating_add)
    }

    pub(crate) fn add(&mut self, limit: usize, loss: Loss) {
        self.insert(
            limit,
            LossEntry {
                stream: loss.stream,
                class: None,
                reason: loss.reason,
                count: loss.count,
                bytes: loss.bytes,
                event: None,
            },
        );
    }

    fn insert(&mut self, limit: usize, mut loss: LossEntry) {
        if loss.count == 0 {
            return;
        }
        if loss.stream == Stream::Events {
            self.events = self.events.saturating_add(loss.count);
            if let Some(pair) = loss.event {
                if self.kinds.contains(&pair) || self.kinds.len() < EVENT_KINDS {
                    self.kinds.insert(pair);
                } else {
                    loss.event = None;
                }
            }
            if loss.reason != LossReason::Truncation {
                self.missing_events = self.missing_events.saturating_add(loss.count);
                if let Some(pair) = loss.event {
                    self.missing_kinds.insert(pair);
                } else {
                    self.unknown_events = true;
                }
            }
        }
        let tracked = self.by_stream.contains_key(&loss.stream) || self.by_stream.len() < limit;
        if loss.reason != LossReason::Truncation {
            let total = self
                .omissions
                .entry((tracked.then_some(loss.stream), loss.class))
                .or_default();
            *total = total.saturating_add(loss.count);
        }
        if tracked {
            let entries = self.by_stream.entry(loss.stream).or_default();
            if let Some(index) = entries.iter().copied().find(|index| {
                let total = &self.streams[*index];
                total.class == loss.class
                    && total.reason == loss.reason
                    && total.event == loss.event
            }) {
                let total = &mut self.streams[index];
                total.count = total.count.saturating_add(loss.count);
                total.bytes = total
                    .bytes
                    .zip(loss.bytes)
                    .map(|(a, b)| a.saturating_add(b));
            } else {
                entries.push(self.streams.len());
                self.streams.push(loss);
            }
        } else if let Some(total) = self
            .untracked
            .iter_mut()
            .find(|total| total.reason == loss.reason && total.class == loss.class)
        {
            total.count = total.count.saturating_add(loss.count);
            total.bytes = total.bytes.saturating_add(loss.bytes.unwrap_or(0));
        } else {
            self.untracked.push(LossTotal {
                class: loss.class,
                reason: loss.reason,
                count: loss.count,
                bytes: loss.bytes.unwrap_or(0),
            });
        }
    }

    pub(crate) fn record(
        &mut self,
        limit: usize,
        stamp: Stamp,
        class: Option<usize>,
        reason: LossReason,
        bytes: usize,
    ) {
        self.insert(
            limit,
            LossEntry {
                stream: stamp.stream,
                class,
                reason,
                count: 1,
                bytes: Some(bytes as u64),
                event: None,
            },
        );
    }

    pub(crate) fn record_event(
        &mut self,
        limit: usize,
        stamp: Stamp,
        class: usize,
        reason: LossReason,
        event: &Event,
    ) {
        self.insert(
            limit,
            LossEntry {
                stream: stamp.stream,
                class: Some(class),
                reason,
                count: 1,
                bytes: Some(if reason == LossReason::Truncation {
                    0
                } else {
                    event.size() as u64
                }),
                event: Some((event.source, event.kind)),
            },
        );
    }
}

pub(crate) fn stream_name(stream: Stream) -> String {
    match stream {
        Stream::Events => "events".into(),
        Stream::Keys => "keys".into(),
        Stream::Topology => "topology".into(),
        Stream::Packets(link) => format!("packets:{}", link.get()),
    }
}

#[cfg(feature = "decode")]
pub(crate) fn gap(
    stream: Stream,
    class: Option<usize>,
    after: u64,
    next: u64,
    missed: u64,
) -> String {
    crate::json::Object::new()
        .str("stream", &stream_name(stream))
        .raw(
            "class",
            &class.map_or_else(|| "null".into(), |n| n.to_string()),
        )
        .num("after", after)
        .num("next", next)
        .num("missed", missed)
        .done()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::time::Instant;

    #[test]
    fn a_full_kind_budget_refuses_every_kind() {
        let mut losses = LossStatus::default();
        for seq in 0..=EVENT_KINDS {
            let kind = Box::leak(format!("kind{seq}").into_boxed_str());
            losses.record_event(
                1,
                Stamp {
                    stream: Stream::Events,
                    seq: seq as u64,
                    at: Instant::ZERO,
                },
                0,
                LossReason::Sampling,
                &Event::new("test", kind),
            );
        }
        assert_eq!(losses.kinds.len(), EVENT_KINDS);
        assert!(losses.incomplete("http", "request"));
        assert_eq!(losses.streams.last().unwrap().event, None);
        assert_eq!(losses.events(), EVENT_KINDS as u64 + 1);
    }
}
