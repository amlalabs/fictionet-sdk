use std::collections::VecDeque;

use fictionet::events::Stamp;
use fictionet::time::{Duration, Instant};

pub(crate) trait Kept {
    fn stamp(&self) -> Stamp;
    fn size(&self) -> usize;
}

pub(crate) struct Ring<T> {
    pub(crate) items: VecDeque<T>,
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
            items: VecDeque::new(),
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
        self.evict_at(0)
    }

    pub(crate) fn evict_at(&mut self, index: usize) -> Option<T> {
        let item = self.items.remove(index)?;
        self.bytes -= item.size();
        self.evicted = self.evicted.saturating_add(1);
        Some(item)
    }

    pub(crate) fn make_room(
        &mut self,
        size: usize,
        count: usize,
        bytes: usize,
        victim: impl Fn(&VecDeque<T>) -> usize,
        mut lost: impl FnMut(T),
    ) {
        while !self.items.is_empty()
            && (self.items.len() >= count || size > bytes || self.bytes > bytes - size)
        {
            lost(self.evict_at(victim(&self.items)).expect("ring budget"));
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        self.last = item.stamp().seq;
        self.bytes += item.size();
        self.items.push_back(item);
    }
}

pub(crate) fn after<'a, T: Kept + 'a>(
    rings: impl IntoIterator<Item = &'a Ring<T>>,
    seq: u64,
) -> impl Iterator<Item = &'a T> {
    let mut parts: Vec<_> = rings
        .into_iter()
        .map(|ring| {
            let start = ring.items.partition_point(|item| item.stamp().seq <= seq);
            ring.items.range(start..).peekable()
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

/// Items and positions through the rings of one stream.
#[derive(Default)]
pub(crate) struct Batch<T> {
    pub(crate) events: Vec<T>,
    pub(crate) last: u64,
    pub(crate) evicted: Vec<u64>,
    #[cfg(any(feature = "decode", test))]
    pub(crate) position: Vec<u64>,
}

pub(crate) fn batch<'a, T: Kept + Clone + 'a>(
    rings: impl IntoIterator<Item = &'a Ring<T>>,
    cursor: Option<u64>,
    max: usize,
) -> Batch<T> {
    let rings: Vec<_> = rings.into_iter().collect();
    let last = rings.iter().map(|ring| ring.last).max().unwrap_or(0);
    let skip = if cursor.is_none() {
        rings
            .iter()
            .map(|ring| ring.items.len())
            .sum::<usize>()
            .saturating_sub(max)
    } else {
        0
    };
    let events: Vec<_> = after(rings.iter().copied(), cursor.unwrap_or(0))
        .skip(skip)
        .take(max)
        .cloned()
        .collect();
    #[cfg(any(feature = "decode", test))]
    let through = events
        .last()
        .map_or(cursor.unwrap_or(last), |item| item.stamp().seq);
    Batch {
        events,
        last,
        evicted: rings.iter().map(|ring| ring.evicted).collect(),
        #[cfg(any(feature = "decode", test))]
        position: rings
            .iter()
            .map(|ring| {
                ring.evicted.saturating_add(
                    ring.items
                        .partition_point(|item| item.stamp().seq <= through)
                        as u64,
                )
            })
            .collect(),
    }
}
