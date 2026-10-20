use std::collections::VecDeque;

use fictionet::events::Stamp;
use fictionet::time::{Duration, Instant};

pub(crate) trait Kept {
    fn stamp(&self) -> Stamp;
    fn size(&self) -> usize;
}

pub(crate) struct Ring<T> {
    pub(crate) events: VecDeque<T>,
    pub(crate) bytes: usize,
    pub(crate) evicted: u64,
    pub(crate) last: u64,
    window: Instant,
    in_window: u64,
    pub(crate) skipped: u64,
}

impl<T> Default for Ring<T> {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            bytes: 0,
            evicted: 0,
            last: 0,
            window: Instant::ZERO,
            in_window: 0,
            skipped: 0,
        }
    }
}

impl<T: Kept> Ring<T> {
    pub(crate) fn admit(&mut self, stamp: Stamp, burst: Option<u64>) -> bool {
        self.last = self.last.max(stamp.seq);
        let Some(burst) = burst else {
            return true;
        };
        if stamp
            .at
            .since_start()
            .saturating_sub(self.window.since_start())
            >= Duration::from_millis(100)
        {
            self.window = stamp.at;
            self.in_window = 0;
        }
        let index = self.in_window;
        self.in_window = self.in_window.saturating_add(1);
        let keep =
            burst != 0 && (index < burst || index.is_multiple_of(1u64 << (index / burst).min(30)));
        if !keep {
            self.skipped = self.skipped.saturating_add(1);
        }
        keep
    }

    pub(crate) fn evict(&mut self) -> Option<T> {
        let item = self.events.pop_front()?;
        self.bytes -= item.size();
        self.evicted = self.evicted.saturating_add(1);
        Some(item)
    }

    pub(crate) fn make_room(
        &mut self,
        size: usize,
        count: usize,
        bytes: usize,
        mut lost: impl FnMut(T),
    ) {
        while !self.events.is_empty()
            && (self.events.len() >= count || size > bytes || self.bytes > bytes - size)
        {
            lost(self.evict().expect("ring budget"));
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        self.last = item.stamp().seq;
        self.bytes += item.size();
        self.events.push_back(item);
    }
}

pub(crate) fn after<'a, T: Kept + 'a>(
    rings: impl IntoIterator<Item = &'a Ring<T>>,
    seq: u64,
) -> impl Iterator<Item = &'a T> {
    let mut parts: Vec<_> = rings
        .into_iter()
        .map(|ring| {
            let start = ring.events.partition_point(|item| item.stamp().seq <= seq);
            ring.events.range(start..).peekable()
        })
        .collect();
    std::iter::from_fn(move || {
        let index = parts
            .iter_mut()
            .enumerate()
            .filter_map(|(index, part)| part.peek().map(|item| (index, item.stamp().seq)))
            .min_by_key(|(_, seq)| *seq)?
            .0;
        parts[index].next()
    })
}
