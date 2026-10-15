use std::sync::Arc;

use crate::stdlib::json::Value;
use crate::time::Instant;

use super::model::{ARC_COUNTS, conn_size, fields_size, heap};
use super::{ConnInfo, Event, Fields};

/// What makes repeats alike.
#[derive(PartialEq, Eq, Hash)]
pub(super) struct RepeatKey {
    pub(super) source: &'static str,
    pub(super) kind: &'static str,
    pub(super) conn: ConnInfo,
    pub(super) fields: Fields,
}

impl RepeatKey {
    pub(super) fn size(&self) -> usize {
        heap(std::mem::size_of::<RepeatKey>() + ARC_COUNTS)
            + conn_size(&self.conn)
            + fields_size(&self.fields)
    }
}

/// A run of alike repeats, counted after the first.
pub(super) struct Window {
    /// The first of them, without its detail.
    pub(super) first: Event,
    pub(super) count: u64,
    /// When the latest was recorded.
    pub(super) last: Instant,
    /// Each detail field that is a number, with its lowest and highest.
    pub(super) ranges: Vec<(&'static str, u64, u64)>,
}

impl Window {
    pub(super) fn size(&self) -> usize {
        self.first.size() + std::mem::size_of::<Window>() - std::mem::size_of::<Event>()
            + self.ranges_size()
            + std::mem::size_of::<Arc<RepeatKey>>()
            + std::mem::size_of::<(Instant, Arc<RepeatKey>)>()
    }

    pub(super) fn ranges_size(&self) -> usize {
        heap(self.ranges.capacity() * std::mem::size_of::<(&str, u64, u64)>())
    }

    /// Counts this repeat only if its new ranges fit in `available` bytes.
    pub(super) fn add(&mut self, at: Instant, detail: &Fields, available: usize) -> bool {
        let new = detail
            .iter()
            .filter(|(name, value)| {
                value.as_u64().is_some() && !self.ranges.iter().any(|r| r.0 == *name)
            })
            .count();
        if self.ranges.len() + new > self.ranges.capacity() {
            let capacity = (self.ranges.len() + new)
                .max(self.ranges.capacity() * 2)
                .max(4);
            let growth =
                heap(capacity * std::mem::size_of::<(&str, u64, u64)>()) - self.ranges_size();
            if growth > available {
                return false;
            }
            self.ranges.reserve_exact(capacity - self.ranges.len());
        }
        self.count += 1;
        self.last = self.last.max(at);
        for (name, value) in detail.iter() {
            let Some(n) = value.as_u64() else { continue };
            match self.ranges.iter_mut().find(|r| r.0 == name) {
                Some(r) => (r.1, r.2) = (r.1.min(n), r.2.max(n)),
                None => self.ranges.push((name, n, n)),
            }
        }
        true
    }

    /// The event that counts the repeats after the first, if there were
    /// any.
    pub(super) fn summary(self) -> Option<Event> {
        if self.count == 0 {
            return None;
        }
        let mut event = self.first;
        event.summary = format!("{} more: {}", self.count, event.summary);
        event.at = self.last;
        event.fields.set("count", self.count);
        for (name, low, high) in self.ranges {
            event
                .fields
                .set(name, Value::Array(vec![low.into(), high.into()]));
        }
        Some(event)
    }
}
