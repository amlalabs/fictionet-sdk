extern crate alloc;

use alloc::vec::Vec;
use core::ops::RangeInclusive;

/// Where a [`Buffer`] keeps its bytes: a plain vector, or a container whose
/// growth is paid for before it allocates, such as a layer's
/// [`ChargedBytes`](fictionet::stdlib::layer::ChargedBytes).
///
/// The buffer keeps its own read and write positions inside
/// [`bytes`](Self::bytes); the storage only holds them.
pub trait Storage {
    /// The bytes that are initialized, written or not.
    fn bytes(&self) -> &[u8];
    /// The same bytes, to write.
    fn bytes_mut(&mut self) -> &mut [u8];
    /// How many bytes the allocation holds, initialized or not.
    fn capacity(&self) -> usize;
    /// Grows the allocation to hold as much of `capacity` as it may: at
    /// least its start, at most its end. Returns `false`, changing
    /// nothing, if not even the start can be had.
    fn grow_within(&mut self, capacity: RangeInclusive<usize>) -> bool;
    /// Initializes up to `len` bytes, zeroing the new ones, if `len` fits
    /// in the capacity. Returns `false`, changing nothing, if it does not.
    /// Never reallocates.
    fn resize_within(&mut self, len: usize) -> bool;
    /// Keeps the first `len` initialized bytes and gives back the capacity
    /// past them.
    fn shrink_to(&mut self, len: usize);
    /// Forgets every byte and gives back the capacity past `keep`, keeping
    /// as much of it as the storage holds up to `keep` for the next bytes.
    fn clear_to(&mut self, keep: usize);
}

/// Storage that asks only the allocator.
impl Storage for Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        self
    }
    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }
    fn grow_within(&mut self, capacity: RangeInclusive<usize>) -> bool {
        let (least, most) = (*capacity.start(), *capacity.end());
        least <= Vec::capacity(self)
            || self
                .try_reserve_exact(most.saturating_sub(self.len()))
                .is_ok()
            || self.try_reserve_exact(least - self.len()).is_ok()
    }
    fn resize_within(&mut self, len: usize) -> bool {
        if len > Vec::capacity(self) {
            return false;
        }
        self.resize(len, 0);
        true
    }
    fn shrink_to(&mut self, len: usize) {
        self.truncate(len);
        self.shrink_to_fit();
    }
    fn clear_to(&mut self, keep: usize) {
        self.clear();
        Vec::shrink_to(self, keep);
    }
}

/// A bounded unread suffix and its stream offset, kept in storage `S`.
///
/// New input is bounded by `limit`. A handoff can retain a larger suffix.
/// Storage is at most twice the largest limit used:
/// a consumed prefix is kept until it is at least as large as the suffix.
/// This makes compaction amortized linear even when a full buffer is
/// consumed and refilled one byte at a time. Allocation grows on demand,
/// and only as far as the storage allows.
#[derive(Clone, Debug)]
pub struct Buffer<S = Vec<u8>> {
    buf: S,
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
    /// Largest supported unread limit. Twice this fits in a vector.
    pub const MAX_LIMIT: usize = (isize::MAX as usize) / 2;

    /// Creates an empty buffer in a vector. Limits above
    /// [`MAX_LIMIT`](Self::MAX_LIMIT) are clamped. A zero limit accepts no
    /// bytes.
    pub fn new(limit: usize) -> Self {
        Self::in_storage(limit, Vec::new())
    }
}

impl<S: Storage> Buffer<S> {
    const MAX_SPARE: usize = 64 * 1024;

    /// Creates an empty buffer in `storage`, whose initialized bytes it
    /// reuses as room. Limits above [`MAX_LIMIT`](Buffer::MAX_LIMIT) are
    /// clamped. A zero limit accepts no bytes.
    pub fn in_storage(limit: usize, storage: S) -> Self {
        Self {
            buf: storage,
            start: 0,
            end: 0,
            offered: 0,
            limit: limit.min(Buffer::MAX_LIMIT),
            offset: 0,
            #[cfg(test)]
            moved: 0,
            #[cfg(test)]
            initialized: 0,
        }
    }
    /// The storage, to see what pays for it.
    pub fn storage(&self) -> &S {
        &self.buf
    }
    /// The storage, to move what pays for it. Its bytes are the buffer's:
    /// changing them changes what the buffer holds.
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.buf
    }
    /// The unread limit for new input. A handoff may retain a larger suffix.
    pub fn limit(&self) -> usize {
        self.limit
    }
    /// All committed, unread bytes.
    pub fn unread(&self) -> &[u8] {
        self.buf
            .bytes()
            .get(self.start..self.end)
            .unwrap_or_default()
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
    /// The allocated capacity, including any consumed prefix.
    pub fn allocated(&self) -> usize {
        self.buf.capacity()
    }
    /// The most [`allocated`](Self::allocated) reaches while the limit
    /// stays at most what it is now: twice the limit, since storage grows
    /// to at most that.
    pub fn most_allocated(&self) -> usize {
        self.limit.saturating_mul(2)
    }

    /// Compacts unread bytes and releases spare input capacity.
    /// Preserves the offset and invalidates any outstanding spare offer.
    pub fn shrink(&mut self) {
        let n = self.len();
        self.buf.bytes_mut().copy_within(self.start..self.end, 0);
        self.buf.shrink_to(n);
        self.start = 0;
        self.end = n;
        self.offered = 0;
        #[cfg(test)]
        {
            self.moved = self.moved.saturating_add(n);
        }
    }

    /// Gives back capacity past `keep` bytes, or past the unread bytes if
    /// they are more, preserving the unread bytes and offset. Capacity at
    /// or under `keep` stays, so storage kept for reuse is not given back.
    pub fn shrink_to(&mut self, keep: usize) {
        if self.allocated() <= keep {
            return;
        }
        let n = self.len();
        self.buf.bytes_mut().copy_within(self.start..self.end, 0);
        // The storage keeps only initialized bytes, so the room kept is
        // initialized first. The capacity is more than `keep`: it fits.
        let kept = n.max(keep);
        if self.buf.bytes().len() < kept {
            let resized = self.buf.resize_within(kept);
            debug_assert!(resized, "the capacity holds what is kept");
        }
        self.buf.shrink_to(kept);
        self.start = 0;
        self.end = n;
        self.offered = 0;
        #[cfg(test)]
        {
            self.moved = self.moved.saturating_add(n);
        }
    }

    fn compact(&mut self) {
        self.offered = 0;
        if self.start >= self.len() && self.start != 0 {
            let n = self.len();
            // Both ends are maintained within the initialized bytes.
            self.buf.bytes_mut().copy_within(self.start..self.end, 0);
            self.start = 0;
            self.end = n;
            #[cfg(test)]
            {
                self.moved = self.moved.saturating_add(n);
            }
        }
    }

    fn size(&mut self, size: usize, capacity: usize) -> bool {
        if size > self.buf.capacity() {
            let target = size
                .max(self.buf.capacity().saturating_mul(2))
                .min(self.limit.saturating_mul(2))
                .min(capacity);
            if target < size || !self.buf.grow_within(size..=target) {
                return false;
            }
        }
        let initialized = self.buf.bytes().len();
        if size > initialized {
            if !self.buf.resize_within(size) {
                return false;
            }
            #[cfg(test)]
            {
                self.initialized = self.initialized.saturating_add(size - initialized);
            }
        }
        true
    }

    /// Capacity needed to append this many bytes, after the same compaction
    /// and bounded growth used by `push`. Existing capacity is retained.
    pub fn capacity_for(&self, additional: usize) -> usize {
        let end = if self.start >= self.len() {
            self.len()
        } else {
            self.end
        };
        let needed = end.saturating_add(additional.min(self.room()));
        if needed <= self.allocated() {
            self.allocated()
        } else {
            needed
                .max(self.allocated().saturating_mul(2))
                .min(self.most_allocated())
        }
    }

    /// Appends what fits and returns the accepted count. Compacts only
    /// when the consumed prefix is at least half of committed storage.
    /// Returns zero if the storage cannot grow. Invalidates any prior
    /// spare offer.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        self.push_with_budget(bytes, usize::MAX)
    }

    /// Appends bytes while growing allocated storage by at most `growth`.
    /// Existing spare capacity can be reused without growth.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push_with_budget(&mut self, bytes: &[u8], growth: usize) -> usize {
        self.compact();
        let capacity = self.allocated().saturating_add(growth);
        let n = bytes
            .len()
            .min(self.room())
            .min(capacity.saturating_sub(self.end));
        let end = self.end.saturating_add(n);
        if !self.size(end, capacity) {
            return 0;
        }
        if let (Some(dst), Some(src)) =
            (self.buf.bytes_mut().get_mut(self.end..end), bytes.get(..n))
        {
            dst.copy_from_slice(src);
            self.end = end;
            n
        } else {
            0
        }
    }

    /// Offers initialized space for direct reads. Call [`commit`](Self::commit)
    /// afterward. Uncommitted bytes are never unread input. A storage that
    /// cannot grow gives an empty slice. Space can contain bytes from
    /// earlier offers. Initialized storage is reused across short reads.
    /// Each offer is at most 64 KiB.
    pub fn spare(&mut self) -> &mut [u8] {
        self.compact();
        let offered = self.room().min(Self::MAX_SPARE);
        let end = self.end.saturating_add(offered);
        if !self.size(end, usize::MAX) {
            return &mut [];
        }
        self.offered = offered;
        self.buf
            .bytes_mut()
            .get_mut(self.end..end)
            .unwrap_or_default()
    }
    /// Commits at most the last offered spare length. Without a spare
    /// offer this does nothing. Discards the rest of that offer.
    pub fn commit(&mut self, n: usize) {
        let n = n
            .min(self.offered)
            .min(self.buf.bytes().len().saturating_sub(self.end))
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
    /// Sets the limit for new input, clamped to [`MAX_LIMIT`](Buffer::MAX_LIMIT).
    /// Keeps unread bytes and invalidates any spare offer.
    #[inline]
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(Buffer::MAX_LIMIT);
        self.offered = 0;
    }
}
