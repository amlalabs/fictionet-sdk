extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use fictionet::stdlib::codec::{
    Decode, Fail, Stream,
};
use core::{
    cell::Cell,
    ops::Bound::{Excluded, Unbounded},
};

struct Entry<D: Decode> {
    stream: Option<Stream<D>>,
    error: Option<Fail<D::Error>>,
}

/// Keyed streams under a shared unread-byte and held-state budget.
/// Stream count is bounded by `max_streams`. The total is bounded by
/// `max_bytes` through this owner's operations. Decoder growth is checked
/// after each drain. An over-budget stream is released and its key stays
/// closed until removed. Its last item or protocol error is delivered.
/// A successful item is followed by [`Fail::Refused`] on the next visit.
/// Allocator overhead and provenance have separate component limits.
pub struct Demux<K: Ord, D: Decode, F = fn(&K) -> D> {
    streams: BTreeMap<K, Entry<D>>,
    ready: BTreeSet<K>,
    cursor: Option<K>,
    total: Cell<usize>,
    // Only one stream can escape through get_mut before the next owner call.
    dirty: Cell<Option<(K, usize)>>,
    excess: Cell<Option<K>>,
    make: F,
    max_streams: usize,
    max_bytes: usize,
}
impl<K: Ord + Clone, D: Decode, F: FnMut(&K) -> D> Demux<K, D, F> {
    /// Sets the stream count and shared byte limits. The factory is called
    /// only when an absent key has a free stream slot. The factory's type
    /// determines whether this owner can move between threads.
    pub fn new(max_streams: usize, max_bytes: usize, make: F) -> Self {
        Self {
            streams: BTreeMap::new(),
            ready: BTreeSet::new(),
            cursor: None,
            total: Cell::new(0),
            dirty: Cell::new(None),
            excess: Cell::new(None),
            make,
            max_streams,
            max_bytes,
        }
    }
    fn bytes(stream: &Stream<D>) -> usize {
        stream.buffered().saturating_add(stream.held())
    }
    /// Opens a stream on first use and accepts what fits under both limits.
    /// Zero with nonempty input means the caller must drain, remove, or refuse.
    /// Initial decoder state also counts against the shared budget.
    /// After EOF or completion, takes and drops all new bytes like [`Stream::push`].
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push(&mut self, key: &K, bytes: &[u8]) -> usize {
        let mut total = self.total();
        if !self.streams.contains_key(key) {
            if self.streams.len() >= self.max_streams {
                return 0;
            }
            let dec = (self.make)(key);
            let held = dec.held();
            if held > self.max_bytes.saturating_sub(total) {
                return 0;
            }
            total = total.saturating_add(held);
            self.total.set(total);
            self.streams.insert(
                key.clone(),
                Entry {
                    stream: Some(Stream::new(dec)),
                    error: None,
                },
            );
            self.ready.insert(key.clone());
        }
        let room = self.max_bytes.saturating_sub(total);
        let Some(stream) = self
            .streams
            .get_mut(key)
            .and_then(|entry| entry.stream.as_mut())
        else {
            // Budget failures retain a closed key, like other terminal streams.
            return bytes.len();
        };
        let before = Self::bytes(stream);
        let n = if stream.is_done() || stream.is_eof() {
            stream.push(bytes)
        } else {
            stream.push(bytes.get(..room).unwrap_or(bytes))
        };
        self.total.set(
            total
                .saturating_sub(before)
                .saturating_add(Self::bytes(stream)),
        );
        if n != 0 && !stream.is_done() {
            self.ready.insert(key.clone());
        }
        n
    }
    /// Marks an existing stream's EOF. An absent key is unchanged.
    pub fn end(&mut self, key: &K) {
        self.total();
        if let Some(stream) = self
            .streams
            .get_mut(key)
            .and_then(|entry| entry.stream.as_mut())
        {
            stream.end();
            if !stream.is_done() {
                self.ready.insert(key.clone());
            }
        }
    }
    /// Removes an entry. Returns its stream if the budget has not released it.
    /// Removing a closed key allows the next push to open it again.
    pub fn remove(&mut self, key: &K) -> Option<Stream<D>> {
        let total = self.total();
        self.ready.remove(key);
        if self.excess.get_mut().as_ref() == Some(key) {
            *self.excess.get_mut() = None;
        }
        let entry = self.streams.remove(key)?;
        if let Some(stream) = &entry.stream {
            self.total.set(total.saturating_sub(Self::bytes(stream)));
        }
        entry.stream
    }
    /// Access to a stream for mode changes. The next owner operation accounts
    /// for its changed bytes and schedules it for decoding. Direct changes
    /// must preserve the shared budget. An excess is charged to this key.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut Stream<D>> {
        self.total();
        let stream = self.streams.get_mut(key)?.stream.as_mut()?;
        *self.dirty.get_mut() = Some((key.clone(), Self::bytes(stream)));
        self.ready.insert(key.clone());
        Some(stream)
    }
    /// The cached sum of unread bytes and decoder-held state.
    /// After `get_mut`, only that stream's delta is checked. Saturates on overflow.
    pub fn total(&self) -> usize {
        if let Some((key, before)) = self.dirty.take()
            && let Some(stream) = self
                .streams
                .get(&key)
                .and_then(|entry| entry.stream.as_ref())
        {
            let total = self
                .total
                .get()
                .saturating_sub(before)
                .saturating_add(Self::bytes(stream));
            self.total.set(total);
            if total > self.max_bytes {
                self.excess.set(Some(key));
            }
        }
        self.total.get()
    }
    /// The number of entries, including closed keys.
    pub fn len(&self) -> usize {
        self.streams.len()
    }
    /// Whether there are no stream entries.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }
    fn next_key(&mut self) -> Option<K> {
        if let Some(key) = self.excess.get_mut().take()
            && self.total.get() > self.max_bytes
        {
            return Some(key);
        }
        self.cursor
            .as_ref()
            .and_then(|key| self.ready.range((Excluded(key), Unbounded)).next().cloned())
            .or_else(|| self.ready.first().cloned())
    }
}
impl<K: Ord + Clone, D: Decode, F: FnMut(&K) -> D> Demux<K, D, F>
where
    D::Error: Clone,
{
    /// Takes an item from a ready stream. Keys rotate in sorted order.
    /// A stream leaves the ready set when it needs input or completes.
    /// Push, EOF, and mutable access make a stream ready again.
    #[allow(clippy::should_implement_trait, clippy::type_complexity)]
    pub fn next(&mut self) -> Option<(K, Result<D::Item, Fail<D::Error>>)> {
        self.total();
        while let Some(key) = self.next_key() {
            self.cursor = Some(key.clone());
            let entry = self.streams.get_mut(&key)?;
            let Some(stream) = entry.stream.as_mut() else {
                self.ready.remove(&key);
                if let Some(error) = entry.error.take() {
                    return Some((key, Err(error)));
                }
                continue;
            };
            let before = Self::bytes(stream);
            let over_budget = self.total.get() > self.max_bytes;
            let item = if over_budget { None } else { stream.next() };
            let after = Self::bytes(stream);
            let total = self
                .total
                .get()
                .saturating_sub(before)
                .saturating_add(after);
            self.total.set(total);
            if total > self.max_bytes {
                let failure = Fail::Refused {
                    unread: stream.buffered(),
                    limit: self.max_bytes,
                };
                self.total.set(total.saturating_sub(after));
                entry.stream = None;
                return Some((
                    key.clone(),
                    match item {
                        Some(Ok(item)) => {
                            entry.error = Some(failure);
                            Ok(item)
                        }
                        Some(Err(error)) => {
                            self.ready.remove(&key);
                            Err(error)
                        }
                        None => {
                            self.ready.remove(&key);
                            Err(failure)
                        }
                    },
                ));
            }
            if item.is_none() || stream.is_done() {
                self.ready.remove(&key);
            }
            if let Some(item) = item {
                return Some((key, item));
            }
        }
        None
    }
}
