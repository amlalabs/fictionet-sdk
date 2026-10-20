use std::collections::VecDeque;

use fictionet::events::Stamp;

pub(crate) trait Kept {
    fn stamp(&self) -> Stamp;
    fn size(&self) -> usize;
}

pub(crate) struct Ring<T> {
    pub(crate) events: VecDeque<T>,
    pub(crate) bytes: usize,
    pub(crate) evicted: u64,
    pub(crate) last: u64,
}

impl<T> Default for Ring<T> {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            bytes: 0,
            evicted: 0,
            last: 0,
        }
    }
}

impl<T: Kept> Ring<T> {
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
