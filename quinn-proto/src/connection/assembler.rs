use std::{
    cmp::{max, Ordering},
    collections::{binary_heap::PeekMut, BinaryHeap},
    mem,
};

use bytes::{Buf, Bytes};
use fictionet_buf::{Budget, Charge};

use crate::range_set::RangeSet;

/// Helper to assemble unordered stream frames into an ordered stream
#[derive(Debug, Default)]
pub(super) struct Assembler {
    state: State,
    data: BinaryHeap<Buffer>,
    // Drop descriptors before releasing their reservation.
    charge: Option<Charge>,
    /// Total number of buffered bytes, including duplicates in ordered mode.
    buffered: usize,
    /// Estimated number of allocated bytes, will never be less than `buffered`.
    allocated: usize,
    /// Number of bytes read by the application. When only ordered reads have been used, this is the
    /// length of the contiguous prefix of the stream which has been consumed by the application,
    /// aka the stream offset.
    bytes_read: u64,
    end: u64,
}

impl Assembler {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Reset to the initial state
    pub(super) fn reinit(&mut self) {
        let old_data = mem::take(&mut self.data);
        let charge = self.charge.take();
        *self = Self::default();
        self.charge = charge;
        self.data = old_data;
        self.data.clear();
    }

    /// Install before the first insertion; reinitialization retains this budget.
    pub(super) fn set_budget(&mut self, budget: Option<&Budget>) {
        if self.charge.is_none() {
            if let Some(budget) = budget {
                assert_eq!(self.data.capacity(), 0);
                self.charge = Some(Charge::nothing(budget));
            }
        }
    }

    pub(super) fn ensure_ordering(&mut self, ordered: bool) -> Result<(), IllegalOrderedRead> {
        if ordered && !self.state.is_ordered() {
            return Err(IllegalOrderedRead);
        } else if !ordered && self.state.is_ordered() {
            // Enter unordered mode
            if !self.data.is_empty() {
                // Get rid of possible duplicates
                self.defragment();
            }
            let mut recvd = RangeSet::new();
            recvd.insert(0..self.bytes_read);
            for chunk in &self.data {
                recvd.insert(chunk.offset..chunk.offset + chunk.bytes.len() as u64);
            }
            self.state = State::Unordered { recvd };
        }
        Ok(())
    }

    /// Get the the next chunk
    pub(super) fn read(&mut self, max_length: usize, ordered: bool) -> Option<Chunk> {
        loop {
            let mut chunk = self.data.peek_mut()?;

            if ordered {
                if chunk.offset > self.bytes_read {
                    // Next chunk is after current read index
                    return None;
                } else if (chunk.offset + chunk.bytes.len() as u64) <= self.bytes_read {
                    // Next chunk is useless as the read index is beyond its end
                    self.buffered -= chunk.bytes.len();
                    self.allocated -= chunk.allocation_size;
                    PeekMut::pop(chunk);
                    continue;
                }

                // Determine `start` and `len` of the slice of useful data in chunk
                let start = (self.bytes_read - chunk.offset) as usize;
                if start > 0 {
                    chunk.bytes.advance(start);
                    chunk.offset += start as u64;
                    self.buffered -= start;
                }
            }

            return Some(if max_length < chunk.bytes.len() {
                self.bytes_read += max_length as u64;
                let offset = chunk.offset;
                chunk.offset += max_length as u64;
                self.buffered -= max_length;
                Chunk::new(offset, chunk.bytes.split_to(max_length))
            } else {
                self.bytes_read += chunk.bytes.len() as u64;
                self.buffered -= chunk.bytes.len();
                self.allocated -= chunk.allocation_size;
                let chunk = PeekMut::pop(chunk);
                Chunk::new(chunk.offset, chunk.bytes)
            });
        }
    }

    /// Copy fragmented chunk data to new chunks backed by a single buffer
    ///
    /// This makes sure we're not unnecessarily holding on to many larger allocations.
    /// We merge contiguous chunks in the process of doing so.
    fn defragment(&mut self) {
        // Chunks smaller than min_chunk_size are merged regardless of fragmentation
        let min_chunk_size = max(self.buffered.div_ceil(MAX_CHUNKS), MIN_RETAINED_CHUNK_SIZE);
        // Sorting, deduplicating and rebuilding reuse the descriptor allocation.
        let mut buffers = mem::take(&mut self.data).into_sorted_vec();
        buffers.reverse();
        self.buffered = 0;
        let mut fragmented_buffered = 0;
        let mut offset = 0;
        for chunk in &mut buffers {
            chunk.try_mark_defragment(offset);
            let size = chunk.bytes.len();
            offset = chunk.offset + size as u64;
            self.buffered += size;
            if !chunk.defragmented || size < min_chunk_size {
                fragmented_buffered += size;
            }
        }
        buffers.retain(|chunk| !chunk.bytes.is_empty());
        if fragmented_buffered != 0 {
            if let Some(mut compacted) = Compacted::new(
                fragmented_buffered,
                self.charge.as_ref().map(Charge::budget),
            ) {
                for chunk in &buffers {
                    if !chunk.defragmented || chunk.bytes.len() < min_chunk_size {
                        compacted.bytes.extend_from_slice(&chunk.bytes);
                    }
                }
                let compacted = Bytes::from_owner(compacted);
                let mut cursor = 0;
                let mut kept = 0;
                let mut run: Option<(usize, usize)> = None;
                // Replace and merge only copied spans. Uncopied spans retain their owners.
                for i in 0..buffers.len() {
                    let len = buffers[i].bytes.len();
                    if buffers[i].defragmented && len >= min_chunk_size {
                        buffers.swap(kept, i);
                        kept += 1;
                        run = None;
                        continue;
                    }
                    let end = cursor + len;
                    if let Some((previous, start)) = run.filter(|(previous, _)| {
                        buffers[*previous].offset + buffers[*previous].bytes.len() as u64
                            == buffers[i].offset
                    }) {
                        buffers[previous].bytes = compacted.slice(start..end);
                        buffers[previous].allocation_size += len;
                    } else {
                        buffers[kept] = Buffer::new_defragmented(
                            buffers[i].offset,
                            compacted.slice(cursor..end),
                        );
                        run = Some((kept, cursor));
                        kept += 1;
                    }
                    cursor = end;
                }
                buffers.truncate(kept);
            }
        }
        // A refused copy still deduplicates, without losing any useful bytes.
        self.allocated = buffers.iter().map(|chunk| chunk.allocation_size).sum();
        self.data = BinaryHeap::from(buffers);
    }

    // Note: If a packet contains many frames from the same stream, the estimated over-allocation
    // will be much higher because we are counting the same allocation multiple times.
    pub(super) fn insert(
        &mut self,
        mut offset: u64,
        mut bytes: Bytes,
        allocation_size: usize,
    ) -> Result<(), TooManyChunks> {
        debug_assert!(
            bytes.len() <= allocation_size,
            "allocation_size less than bytes.len(): {:?} < {:?}",
            allocation_size,
            bytes.len()
        );
        self.end = self.end.max(offset + bytes.len() as u64);
        if let State::Unordered { ref mut recvd } = self.state {
            // Discard duplicate data
            for duplicate in recvd.replace(offset..offset + bytes.len() as u64) {
                if duplicate.start > offset {
                    let buffer = Buffer::new(
                        offset,
                        bytes.split_to((duplicate.start - offset) as usize),
                        allocation_size,
                    );
                    let len = buffer.bytes.len();
                    push(&mut self.data, &mut self.charge, buffer)?;
                    self.buffered += len;
                    self.allocated += allocation_size;
                    offset = duplicate.start;
                }
                bytes.advance((duplicate.end - offset) as usize);
                offset = duplicate.end;
            }
        } else if offset < self.bytes_read {
            if (offset + bytes.len() as u64) <= self.bytes_read {
                return Ok(());
            } else {
                let diff = self.bytes_read - offset;
                offset += diff;
                bytes.advance(diff as usize);
            }
        }

        // No early return when empty: the dedup loop above may already have pushed chunks.
        if !bytes.is_empty() {
            let buffer = Buffer::new(offset, bytes, allocation_size);
            let len = buffer.bytes.len();
            push(&mut self.data, &mut self.charge, buffer)?;
            self.buffered += len;
            self.allocated += allocation_size;
        }
        // `self.buffered` also counts duplicate bytes, therefore we use
        // `self.end - self.bytes_read` as an upper bound of buffered unique
        // bytes. This will cause a defragmentation if the amount of duplicate
        // bytes exceedes a proportion of the receive window size.
        let buffered = self.buffered.min((self.end - self.bytes_read) as usize);
        let over_allocation = self.allocated - buffered;
        // Rationale: on the one hand, we want to defragment rarely, ideally never
        // in non-pathological scenarios. However, a pathological or malicious
        // peer could send us one-byte frames, and since we use reference-counted
        // buffers in order to prevent copying, this could result in keeping a lot
        // of memory allocated. This limits over-allocation in proportion to the
        // buffered data. The constants are chosen somewhat arbitrarily and try to
        // balance between defragmentation overhead and over-allocation.
        let threshold = 32768.max(buffered * 3 / 2);
        // Small gapped frames hold over-allocation below the threshold, so bound the count too.
        if over_allocation > threshold || self.data.len() > COMPACT_THRESHOLD {
            self.defragment();
            // ngtcp2 uses a threshold of 4000 -- try to be a little more conservative?
            if self.data.len() > MAX_CHUNKS {
                return Err(TooManyChunks);
            }
        }

        Ok(())
    }

    /// Number of bytes consumed by the application
    pub(super) fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Discard all buffered data
    pub(super) fn clear(&mut self) {
        self.data.clear();
        self.buffered = 0;
        self.allocated = 0;
    }

    /// How many separately received pieces are buffered
    pub(super) fn pieces(&self) -> usize {
        self.data.len()
    }
}

/// The buffered, unread part of the stream. Reading each byte looks at
/// every piece, so callers bound `pieces`.
impl crate::version::Received for Assembler {
    fn byte(&self, position: u64) -> Option<u8> {
        self.data.iter().find_map(|buffer| {
            let index = usize::try_from(position.checked_sub(buffer.offset)?).ok()?;
            buffer.bytes.get(index).copied()
        })
    }

    fn prefix(&self) -> u64 {
        let mut end = self.bytes_read;
        while let Some(next) = self
            .data
            .iter()
            .filter(|buffer| buffer.offset <= end)
            .map(|buffer| buffer.offset + buffer.bytes.len() as u64)
            .find(|&next| next > end)
        {
            end = next;
        }
        end
    }
}

/// Grow the heap only after reserving both old and new descriptor allocations.
fn push(
    data: &mut BinaryHeap<Buffer>,
    charge: &mut Option<Charge>,
    buffer: Buffer,
) -> Result<(), TooManyChunks> {
    if data.len() == data.capacity() {
        grow(data, charge)?;
    }
    data.push(buffer);
    Ok(())
}

fn grow(data: &mut BinaryHeap<Buffer>, charge: &mut Option<Charge>) -> Result<(), TooManyChunks> {
    let capacity = data.capacity().saturating_mul(2).max(4);
    if let Some(charge) = charge {
        let peak = capacity
            .checked_mul(size_of::<Buffer>())
            .and_then(|n| charge.bytes().checked_add(n))
            .ok_or(TooManyChunks)?;
        if !charge.grow_to(peak) {
            return Err(TooManyChunks);
        }
    }
    data.reserve_exact(capacity - data.len());
    // Keep the growth history reserved. Geometric capacity bounds its sum
    // below twice the current allocation, including each replacement copy.
    Ok(())
}

/// One copied backing, shared by every contiguous run and application slice.
struct Compacted {
    bytes: Vec<u8>,
    // The owner wrapper and payload are freed before the reservation is released.
    _charge: Option<Charge>,
}

impl Compacted {
    const OVERHEAD: usize = size_of::<Self>() + size_of::<usize>();

    fn new(capacity: usize, budget: Option<&Budget>) -> Option<Self> {
        let charge = match budget {
            Some(budget) => Some(budget.charge(capacity.checked_add(Self::OVERHEAD)?)?),
            None => None,
        };
        Some(Self {
            bytes: Vec::with_capacity(capacity),
            _charge: charge,
        })
    }
}

impl AsRef<[u8]> for Compacted {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// A chunk of data from the receive stream
#[derive(Debug, PartialEq, Eq)]
pub struct Chunk {
    /// The offset in the stream
    pub offset: u64,
    /// The contents of the chunk
    pub bytes: Bytes,
}

impl Chunk {
    fn new(offset: u64, bytes: Bytes) -> Self {
        Self { offset, bytes }
    }
}

#[derive(Debug, Eq)]
struct Buffer {
    offset: u64,
    bytes: Bytes,
    /// Size of the allocation behind `bytes`, if `defragmented == false`.
    /// Otherwise this will be set to `bytes.len()` by `try_mark_defragment`.
    /// Will never be less than `bytes.len()`.
    allocation_size: usize,
    defragmented: bool,
}

impl Buffer {
    /// Constructs a new fragmented Buffer
    fn new(offset: u64, bytes: Bytes, allocation_size: usize) -> Self {
        Self {
            offset,
            bytes,
            allocation_size,
            defragmented: false,
        }
    }

    /// Constructs a new defragmented Buffer
    fn new_defragmented(offset: u64, bytes: Bytes) -> Self {
        let allocation_size = bytes.len();
        Self {
            offset,
            bytes,
            allocation_size,
            defragmented: true,
        }
    }

    /// Discards data before `offset` and flags `self` as defragmented if it has good utilization
    fn try_mark_defragment(&mut self, offset: u64) {
        let duplicate = offset.saturating_sub(self.offset) as usize;
        self.offset = self.offset.max(offset);
        if duplicate >= self.bytes.len() {
            // All bytes are duplicate
            self.bytes = Bytes::new();
            self.defragmented = true;
            self.allocation_size = 0;
            return;
        }
        self.bytes.advance(duplicate);
        // Make sure that fragmented buffers with high utilization become defragmented and
        // defragmented buffers remain defragmented
        self.defragmented = self.defragmented || self.bytes.len() * 6 / 5 >= self.allocation_size;
        if self.defragmented {
            // Make sure that defragmented buffers do not contribute to over-allocation
            self.allocation_size = self.bytes.len();
        }
    }
}

impl Ord for Buffer {
    // Invert ordering based on offset (max-heap, min offset first),
    // prioritize longer chunks at the same offset.
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset
            .cmp(&other.offset)
            .reverse()
            .then(self.bytes.len().cmp(&other.bytes.len()))
    }
}

impl PartialOrd for Buffer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Buffer {
    fn eq(&self, other: &Self) -> bool {
        (self.offset, self.bytes.len()) == (other.offset, other.bytes.len())
    }
}

#[derive(Debug, Default)]
enum State {
    #[default]
    Ordered,
    Unordered {
        /// The set of offsets that have been received from the peer, including portions not yet
        /// read by the application.
        recvd: RangeSet,
    },
}

impl State {
    fn is_ordered(&self) -> bool {
        matches!(self, Self::Ordered)
    }
}

/// Error indicating that an ordered read was performed on a stream after an unordered read
#[derive(Debug)]
pub struct IllegalOrderedRead;

/// Receive storage is exhausted or too many distinct chunks remain after compaction
#[derive(Debug)]
pub(crate) struct TooManyChunks;

/// Bound on the number of distinct spans kept for a stream
///
/// Independent of how much memory those spans over-allocate. A frame is rejected only
/// if compaction cannot get the count back down to this.
const MAX_CHUNKS: usize = 1024;

/// Minimum size of a defragmented chunk that is retained without coalescing.
///
/// Chunks below this size will be copied on every compaction. 128 bytes balances
/// being cheap to copy while reducing the overhead of many small buffer nodes.
const MIN_RETAINED_CHUNK_SIZE: usize = 128;

/// Chunk count past which `insert` compacts before deciding whether to reject
///
/// Above `MAX_CHUNKS` so a flood of mergeable frames cannot force a defragmentation
/// per frame.
const COMPACT_THRESHOLD: usize = 2 * MAX_CHUNKS;

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn assemble_ordered() {
        let mut x = Assembler::new();
        assert_matches!(next(&mut x, 32), None);
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        assert_matches!(next(&mut x, 1), Some(ref y) if &y[..] == b"1");
        assert_matches!(next(&mut x, 3), Some(ref y) if &y[..] == b"23");
        x.insert(3, Bytes::from_static(b"456"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"456");
        x.insert(6, Bytes::from_static(b"789"), 3).unwrap();
        x.insert(9, Bytes::from_static(b"10"), 2).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"789");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"10");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_unordered() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(3, Bytes::from_static(b"456"), 3).unwrap();
        assert_matches!(next(&mut x, 32), None);
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_duplicate() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_duplicate_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contained() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contained_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contains() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_contains_compact() {
        let mut x = Assembler::new();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"12345"), 5).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"12345");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_overlapping() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 3).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 3).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123");
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"4");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_overlapping_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"123"), 4).unwrap();
        x.insert(1, Bytes::from_static(b"234"), 4).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"1234");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_complex() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"), 1).unwrap();
        x.insert(2, Bytes::from_static(b"3"), 1).unwrap();
        x.insert(4, Bytes::from_static(b"5"), 1).unwrap();
        x.insert(0, Bytes::from_static(b"123456"), 6).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_complex_compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1"), 1).unwrap();
        x.insert(2, Bytes::from_static(b"3"), 1).unwrap();
        x.insert(4, Bytes::from_static(b"5"), 1).unwrap();
        x.insert(0, Bytes::from_static(b"123456"), 6).unwrap();
        x.defragment();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"123456");
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn assemble_old() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"1234"), 4).unwrap();
        assert_matches!(next(&mut x, 32), Some(ref y) if &y[..] == b"1234");
        x.insert(0, Bytes::from_static(b"1234"), 4).unwrap();
        assert_matches!(next(&mut x, 32), None);
    }

    #[test]
    fn compact() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 4).unwrap();
        x.insert(3, Bytes::from_static(b"def"), 4).unwrap();
        x.insert(9, Bytes::from_static(b"jkl"), 4).unwrap();
        x.insert(12, Bytes::from_static(b"mno"), 4).unwrap();
        x.defragment();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"abcdef"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(9, Bytes::from_static(b"jklmno"))
        );
    }

    #[test]
    fn defrag_with_missing_prefix() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 3).unwrap();
        x.defragment();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
    }

    #[test]
    fn defrag_read_chunk() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 4).unwrap();
        x.insert(0, Bytes::from_static(b"abc"), 4).unwrap();
        x.insert(7, Bytes::from_static(b"hij"), 4).unwrap();
        x.insert(11, Bytes::from_static(b"lmn"), 4).unwrap();
        x.defragment();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"abcdef");
        x.insert(5, Bytes::from_static(b"fghijklmn"), 9).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"ghijklmn");
        x.insert(13, Bytes::from_static(b"nopq"), 4).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"opq");
        x.insert(15, Bytes::from_static(b"pqrs"), 4).unwrap();
        assert_matches!(x.read(usize::MAX, true), Some(ref y) if &y.bytes[..] == b"rs");
        assert_matches!(x.read(usize::MAX, true), None);
    }

    #[test]
    fn unordered_happy_path() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"abc"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(3, Bytes::from_static(b"def"), 3).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
    }

    #[test]
    fn unordered_dedup() {
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        x.insert(3, Bytes::from_static(b"def"), 3).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(3, Bytes::from_static(b"def"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(0, Bytes::from_static(b"a"), 1).unwrap();
        x.insert(0, Bytes::from_static(b"abcdefghi"), 9).unwrap();
        x.insert(0, Bytes::from_static(b"abcd"), 4).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(0, Bytes::from_static(b"a"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(1, Bytes::from_static(b"bc"))
        );
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(6, Bytes::from_static(b"ghi"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(8, Bytes::from_static(b"ijkl"), 4).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(9, Bytes::from_static(b"jkl"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(12, Bytes::from_static(b"mno"), 3).unwrap();
        assert_eq!(
            next_unordered(&mut x),
            Chunk::new(12, Bytes::from_static(b"mno"))
        );
        assert_eq!(x.read(usize::MAX, false), None);
        x.insert(2, Bytes::from_static(b"cde"), 3).unwrap();
        assert_eq!(x.read(usize::MAX, false), None);
    }

    #[test]
    fn chunks_dedup() {
        let mut x = Assembler::new();
        x.insert(3, Bytes::from_static(b"def"), 3).unwrap();
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(0, Bytes::from_static(b"a"), 1).unwrap();
        x.insert(1, Bytes::from_static(b"bcdefghi"), 9).unwrap();
        x.insert(0, Bytes::from_static(b"abcd"), 4).unwrap();
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(0, Bytes::from_static(b"abcd")))
        );
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(4, Bytes::from_static(b"efghi")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(8, Bytes::from_static(b"ijkl"), 4).unwrap();
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(9, Bytes::from_static(b"jkl")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(12, Bytes::from_static(b"mno"), 3).unwrap();
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(12, Bytes::from_static(b"mno")))
        );
        assert_eq!(x.read(usize::MAX, true), None);
        x.insert(2, Bytes::from_static(b"cde"), 3).unwrap();
        assert_eq!(x.read(usize::MAX, true), None);
    }

    #[test]
    fn ordered_eager_discard() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        assert_eq!(x.data.len(), 1);
        assert_eq!(
            x.read(usize::MAX, true),
            Some(Chunk::new(0, Bytes::from_static(b"abc")))
        );
        x.insert(0, Bytes::from_static(b"ab"), 2).unwrap();
        assert_eq!(x.data.len(), 0);
        x.insert(2, Bytes::from_static(b"cd"), 2).unwrap();
        assert_eq!(
            x.data.peek(),
            Some(&Buffer::new(3, Bytes::from_static(b"d"), 2))
        );
    }

    #[test]
    fn ordered_insert_unordered_read() {
        let mut x = Assembler::new();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        x.insert(0, Bytes::from_static(b"abc"), 3).unwrap();
        x.ensure_ordering(false).unwrap();
        assert_eq!(
            x.read(3, false),
            Some(Chunk::new(0, Bytes::from_static(b"abc")))
        );
        assert_eq!(x.read(3, false), None);
    }

    #[test]
    fn ordered_lossless_stream_is_not_rejected() {
        const FRAME_LEN: usize = 32;

        let mut x = Assembler::new();
        let data = Bytes::from(vec![0; FRAME_LEN]);
        let mut offset = 0u64;
        while offset < (2 * COMPACT_THRESHOLD * FRAME_LEN) as u64 {
            x.insert(offset, data.clone(), FRAME_LEN)
                .expect("contiguous lossless data must not be rejected");
            offset += FRAME_LEN as u64;
        }
    }

    #[test]
    fn defrag_respects_max_chunks_at_rounding_boundary() {
        let mut x = Assembler::new();
        let data = Bytes::from(vec![0; MIN_RETAINED_CHUNK_SIZE]);
        let mut offset = 0;
        // Fill with minimium sized chunks.
        for _ in 0..MAX_CHUNKS {
            x.insert(offset, data.clone(), data.len()).unwrap();
            offset += data.len() as u64;
        }
        // Add 1 extra chunk, defragment must coalesce the previous
        // chunks to stay within MAX_CHUNKS
        x.insert(offset, Bytes::from_static(b"x"), 1).unwrap();
        x.defragment();
        assert!(x.data.len() <= MAX_CHUNKS);
    }

    #[test]
    fn bounded_chunks_under_low_over_allocation() {
        // Gapped frames whose `allocation_size` equals their length hold
        // `over_allocation` at zero, so that trigger never fires.
        let mut x = Assembler::new();
        // Withhold offset 0 so an ordered reader can never drain anything.
        let mut offset = 1u64;
        let mut result = Ok(());
        for _ in 0..(MAX_CHUNKS * 8) {
            result = x.insert(offset, Bytes::from_static(b"gap"), 3);
            if result.is_err() {
                break;
            }
            offset += 3 + 1; // 3 data bytes, 1 byte gap
        }
        assert_matches!(result, Err(TooManyChunks));
        assert!(
            x.data.len() <= COMPACT_THRESHOLD + 1,
            "chunk count {} exceeded the bound",
            x.data.len()
        );
    }

    #[test]
    fn bounded_chunks_unordered_overlap_flood() {
        // Overlapping frames whose tail is already received: the dedup loop pushes
        // the fresh head byte and leaves `bytes` empty, and `end` never rises, so
        // the flood costs the peer no flow control.
        let mut x = Assembler::new();
        x.ensure_ordering(false).unwrap();
        let top = 1_000_000u64;
        x.insert(top, Bytes::from_static(b"ab"), 2).unwrap();
        for k in 0..(4 * MAX_CHUNKS as u64) {
            x.insert(top - k - 1, Bytes::from_static(b"ab"), 2).unwrap();
            assert!(
                x.data.len() <= COMPACT_THRESHOLD + 1,
                "chunk count {} exceeded the bound at k={k}",
                x.data.len()
            );
        }
    }

    #[test]
    fn bounded_chunks_duplicate_flood() {
        // Duplicates against a stream already at the cap. Ordered mode does not dedup,
        // so each one pushes a chunk; they must not be rejected, or compact every frame.
        let mut x = Assembler::new();
        // Withhold offset 0 so nothing can be drained.
        for i in 0..MAX_CHUNKS as u64 {
            x.insert(1 + i * 4, Bytes::from_static(b"abc"), 3).unwrap();
        }
        let mut max_len = x.data.len();
        for _ in 0..(3 * MAX_CHUNKS) {
            x.insert(1, Bytes::from_static(b"abc"), 3)
                .expect("duplicate flood must not be rejected");
            max_len = max_len.max(x.data.len());
            assert!(
                x.data.len() <= COMPACT_THRESHOLD + 1,
                "chunk count {} exceeded the bound",
                x.data.len()
            );
        }
        // Compacting on every frame would pin the count at `MAX_CHUNKS`.
        assert!(
            max_len > MAX_CHUNKS,
            "buffer compacted on every frame (max observed len {max_len})"
        );
    }

    #[test]
    fn reassembly_refuses_descriptor_growth_before_allocating() {
        use crate::cost::{Charged, Costs, Linear};
        let budget = Budget::new(0);
        let mut assembler = Assembler::new();
        assembler.set_budget(Some(&budget));
        let mut costs = Costs::new("QUIC reassembly refusal");
        let result = costs.step(
            4,
            0,
            Linear {
                num: 0,
                den: 1,
                fixed: 0,
            },
            || Charged {
                value: assembler.insert(0, Bytes::from_static(b"data"), 4),
                charged: budget.used(),
            },
        );
        assert!(result.is_err());
        assert!(assembler.data.is_empty());
        assert_eq!(assembler.buffered, 0);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reassembly_descriptor_growth_and_reuse_are_reserved() {
        use crate::cost::{Charged, Costs, Linear};
        let budget = Budget::unlimited();
        let mut assembler = Assembler::new();
        assembler.set_budget(Some(&budget));
        let mut costs = Costs::new("QUIC reassembly descriptors");
        for round in 0..2 {
            for offset in 0..64 {
                let before = budget.used();
                costs.step(
                    1,
                    before,
                    Linear {
                        num: 0,
                        den: 1,
                        fixed: 0,
                    },
                    || {
                        assembler
                            .insert(offset, Bytes::from_static(b"x"), 1)
                            .unwrap();
                        Charged {
                            value: (),
                            charged: budget.used() - before,
                        }
                    },
                );
            }
            let before = budget.used();
            costs.step(
                0,
                before,
                Linear {
                    num: 0,
                    den: 1,
                    fixed: 0,
                },
                || {
                    assembler.reinit();
                    Charged {
                        value: (),
                        charged: 0,
                    }
                },
            );
            assert_eq!(
                budget.used(),
                before,
                "retained capacity stays paid in round {round}"
            );
        }
        drop(assembler);
        assert_eq!(budget.used(), 0);
        println!("cost: {}", costs.summary());
    }

    #[test]
    fn reassembly_compaction_retains_payment_through_application_slices() {
        use crate::cost::{Charged, Costs, Linear};
        for size in [1, 64, 1200, 16384] {
            let budget = Budget::unlimited();
            let mut costs = Costs::new("QUIC reassembly compaction");
            let input = vec![7; size];
            // The caller pays for source wire backings before this session.
            let first = crate::PacketBuffer::copy_from(&budget, &input)
                .unwrap()
                .freeze();
            let second = crate::PacketBuffer::copy_from(&budget, &input)
                .unwrap()
                .freeze();
            let mut assembler = Assembler::new();
            assembler.set_budget(Some(&budget));
            for (offset, data) in [(0, first), (size as u64 + 1, second)] {
                let before = budget.used();
                costs.step(
                    size,
                    before,
                    Linear {
                        num: 0,
                        den: 1,
                        fixed: 0,
                    },
                    || {
                        assembler.insert(offset, data, size * 2).unwrap();
                        Charged {
                            value: (),
                            charged: budget.used() - before,
                        }
                    },
                );
            }
            let before = budget.used();
            // One copy of retained useful bytes and one shared owner, with no
            // new descriptors. The old wire owners coexist until replacement.
            costs.step(
                2 * size,
                before,
                Linear {
                    num: 1,
                    den: 1,
                    fixed: Compacted::OVERHEAD,
                },
                || {
                    assembler.defragment();
                    Charged {
                        value: (),
                        charged: 2 * size + Compacted::OVERHEAD,
                    }
                },
            );
            let first = assembler.read(usize::MAX, true).unwrap();
            let second = assembler.read(usize::MAX, false).unwrap();
            assert_eq!(first.bytes.as_ref(), input);
            assert_eq!(second.offset, size as u64 + 1);
            assert_eq!(second.bytes.as_ref(), input);
            let retained = second.bytes.slice(size / 2..);
            drop((assembler, first, second));
            assert_eq!(budget.used(), 2 * size + Compacted::OVERHEAD);
            assert_eq!(retained.as_ref(), &input[size / 2..]);
            drop(retained);
            assert_eq!(budget.used(), 0);
            println!("cost: {}", costs.summary());
        }
    }

    #[test]
    fn reassembly_refused_compaction_deduplicates_without_copying() {
        use crate::cost::{Charged, Costs, Linear};
        let budget = Budget::new(4 * size_of::<Buffer>());
        let mut assembler = Assembler::new();
        assembler.set_budget(Some(&budget));
        assembler.insert(0, Bytes::from_static(b"abcd"), 8).unwrap();
        assembler.insert(1, Bytes::from_static(b"bcde"), 8).unwrap();
        assembler.insert(0, Bytes::from_static(b"abcd"), 8).unwrap();
        assert_eq!(budget.used(), budget.limit());
        let mut costs = Costs::new("QUIC compaction refusal");
        costs.step(
            12,
            0,
            Linear {
                num: 0,
                den: 1,
                fixed: 0,
            },
            || {
                assembler.defragment();
                Charged {
                    value: (),
                    charged: 0,
                }
            },
        );
        assert_eq!(assembler.buffered, 5);
        assert_eq!(assembler.data.len(), 2);
        assert_eq!(assembler.read(8, true).unwrap().bytes, b"abcd"[..]);
        assert_eq!(assembler.read(8, true).unwrap().bytes, b"e"[..]);
        assert!(assembler.read(8, true).is_none());
        drop(assembler);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reassembly_compaction_preserves_overlapping_and_retained_spans() {
        // Repeated shuffles mix retained large spans with copied tiny spans,
        // duplicates and overlaps. The byte at each offset is independent of
        // which packet supplies it.
        let input: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        for seed in 1..17u64 {
            let budget = Budget::unlimited();
            let mut assembler = Assembler::new();
            assembler.set_budget(Some(&budget));
            let mut rng = seed;
            for _ in 0..128 {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                let start = (rng >> 32) as usize % input.len();
                let length = [1, 3, 127, 128, 511][rng as usize % 5].min(input.len() - start);
                let bytes = crate::PacketBuffer::copy_from(&budget, &input[start..start + length])
                    .unwrap()
                    .freeze();
                assembler.insert(start as u64, bytes, length).unwrap();
                if rng & 7 == 0 {
                    assembler.defragment();
                }
            }
            // Fill every hole, then compact once more before ordered delivery.
            for start in (0..input.len()).step_by(64) {
                let bytes = crate::PacketBuffer::copy_from(&budget, &input[start..start + 64])
                    .unwrap()
                    .freeze();
                assembler.insert(start as u64, bytes, 64).unwrap();
            }
            assembler.defragment();
            let mut read = 0;
            while let Some(chunk) = assembler.read(73, true) {
                assert_eq!(chunk.offset, read as u64);
                assert_eq!(chunk.bytes.as_ref(), &input[read..read + chunk.bytes.len()]);
                read += chunk.bytes.len();
            }
            assert_eq!(read, input.len());
            drop(assembler);
            assert_eq!(budget.used(), 0);
        }
    }

    fn next_unordered(x: &mut Assembler) -> Chunk {
        x.read(usize::MAX, false).unwrap()
    }

    fn next(x: &mut Assembler, size: usize) -> Option<Bytes> {
        x.read(size, true).map(|chunk| chunk.bytes)
    }
}

#[cfg(kani)]
#[path = "../../../verification/quic/kani/reassembly.rs"]
mod resource_proofs;
