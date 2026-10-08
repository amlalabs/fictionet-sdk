extern crate alloc;

use alloc::vec::Vec;

/// A bounded unread suffix and its stream offset.
///
/// New input is bounded by `limit`. A handoff can retain a larger suffix.
/// Storage is at most twice the largest limit used:
/// a consumed prefix is kept until it is at least as large as the suffix.
/// This makes compaction amortized linear even when a full buffer is
/// consumed and refilled one byte at a time. Allocation grows on demand.
#[derive(Clone, Debug)]
pub struct Buffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
    offered: usize,
    limit: usize,
    offset: u64,
    #[cfg(test)]
    pub(super) moved: usize,
    #[cfg(test)]
    pub(super) initialized: usize,
}

impl Buffer {
    const MAX_SPARE: usize = 64 * 1024;

    /// Largest supported unread limit. Twice this fits in a vector.
    pub const MAX_LIMIT: usize = (isize::MAX as usize) / 2;

    /// Creates an empty buffer. Limits above [`MAX_LIMIT`](Self::MAX_LIMIT)
    /// are clamped. A zero limit accepts no bytes.
    pub fn new(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            end: 0,
            offered: 0,
            limit: limit.min(Self::MAX_LIMIT),
            offset: 0,
            #[cfg(test)]
            moved: 0,
            #[cfg(test)]
            initialized: 0,
        }
    }
    /// The unread limit for new input. A handoff may retain a larger suffix.
    pub fn limit(&self) -> usize {
        self.limit
    }
    /// All committed, unread bytes.
    pub fn unread(&self) -> &[u8] {
        self.buf.get(self.start..self.end).unwrap_or_default()
    }
    /// The unread length.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
    /// Whether there are no unread bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// How many more bytes fit.
    pub fn room(&self) -> usize {
        self.limit.saturating_sub(self.len())
    }
    /// The offset of the first unread byte. Saturates at `u64::MAX`.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// The allocated vector capacity, including any consumed prefix.
    pub fn allocated(&self) -> usize {
        self.buf.capacity()
    }

    fn compact(&mut self) {
        self.offered = 0;
        if self.start >= self.len() && self.start != 0 {
            let n = self.len();
            // Both ends are maintained within buf.len().
            self.buf.copy_within(self.start..self.end, 0);
            self.start = 0;
            self.end = n;
            #[cfg(test)]
            {
                self.moved = self.moved.saturating_add(n);
            }
        }
    }

    fn size(&mut self, size: usize) -> bool {
        if size > self.buf.capacity() {
            let target = size
                .max(self.buf.capacity().saturating_mul(2))
                .min(self.limit.saturating_mul(2));
            if self
                .buf
                .try_reserve_exact(target.saturating_sub(self.buf.len()))
                .is_err()
            {
                return false;
            }
        }
        if size > self.buf.len() {
            #[cfg(test)]
            {
                self.initialized = self
                    .initialized
                    .saturating_add(size.saturating_sub(self.buf.len()));
            }
            self.buf.resize(size, 0);
        }
        true
    }

    /// Appends what fits and returns the accepted count. Compacts only
    /// when the consumed prefix is at least half of committed storage.
    /// Returns zero if allocation fails. Invalidates any prior spare offer.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        self.compact();
        let n = bytes.len().min(self.room());
        let end = self.end.saturating_add(n);
        if !self.size(end) {
            return 0;
        }
        if let (Some(dst), Some(src)) = (self.buf.get_mut(self.end..end), bytes.get(..n)) {
            dst.copy_from_slice(src);
            self.end = end;
            n
        } else {
            0
        }
    }

    /// Offers initialized space for direct reads. Call [`commit`](Self::commit)
    /// afterward. Uncommitted bytes are never unread input. An allocation
    /// failure gives an empty slice. Space can contain bytes from earlier
    /// offers. Initialized storage is reused across short reads. Each offer
    /// is at most 64 KiB.
    pub fn spare(&mut self) -> &mut [u8] {
        self.compact();
        let offered = self.room().min(Self::MAX_SPARE);
        let end = self.end.saturating_add(offered);
        if !self.size(end) {
            return &mut [];
        }
        self.offered = offered;
        self.buf.get_mut(self.end..end).unwrap_or_default()
    }
    /// Commits at most the last offered spare length. Without a spare
    /// offer this does nothing. Discards the rest of that offer.
    pub fn commit(&mut self, n: usize) {
        let n = n
            .min(self.offered)
            .min(self.buf.len().saturating_sub(self.end))
            .min(self.room());
        self.end = self.end.saturating_add(n);
        self.offered = 0;
    }
    /// Consumes at most the unread length and advances the offset.
    /// Invalidates any spare offer.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len());
        self.start = self.start.saturating_add(n);
        self.offset = self
            .offset
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        self.offered = 0;
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }
    /// Sets the limit for new input, clamped to [`MAX_LIMIT`](Self::MAX_LIMIT).
    /// Keeps unread bytes and invalidates any spare offer.
    #[inline]
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(Self::MAX_LIMIT);
        self.offered = 0;
    }
}
