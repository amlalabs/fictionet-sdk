use alloc::vec::Vec;
use core::mem;
use core::ops::Range;
#[cfg(feature = "std")]
use std::io;

#[cfg(feature = "std")]
use super::record_end;
use crate::budget::{Paid, PaidBytes};
#[cfg(feature = "std")]
use crate::msgs::message::MAX_WIRE_SIZE;

/// Conversion from a slice within a larger buffer into
/// a `Range` offset within.
#[derive(Debug)]
pub(crate) struct Locator {
    bounds: Range<*const u8>,
}

impl Locator {
    #[inline]
    pub(crate) fn new(slice: &[u8]) -> Self {
        Self {
            bounds: slice.as_ptr_range(),
        }
    }

    #[inline]
    pub(crate) fn locate(&self, slice: &[u8]) -> Range<usize> {
        let bounds = slice.as_ptr_range();
        debug_assert!(self.fully_contains(slice));
        let start = bounds.start as usize - self.bounds.start as usize;
        let len = bounds.end as usize - bounds.start as usize;
        Range {
            start,
            end: start + len,
        }
    }

    #[inline]
    pub(crate) fn fully_contains(&self, slice: &[u8]) -> bool {
        let bounds = slice.as_ptr_range();
        bounds.start >= self.bounds.start && bounds.end <= self.bounds.end
    }
}

/// Conversion from a `Range` offset to the original slice.
pub(crate) struct Delocator<'b> {
    slice: &'b [u8],
}

impl<'b> Delocator<'b> {
    /// The buffer the ranges are in.
    #[inline]
    pub(crate) fn slice(&self) -> &'b [u8] {
        self.slice
    }

    #[inline]
    pub(crate) fn new(slice: &'b [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn slice_from_range(&'_ self, range: &Range<usize>) -> &'b [u8] {
        // safety: this unwrap is safe so long as `range` came from `locate()`
        // for the same buffer
        self.slice.get(range.clone()).unwrap()
    }

    #[inline]
    pub(crate) fn locator(self) -> Locator {
        Locator::new(self.slice)
    }
}

/// Reordering the underlying buffer based on ranges.
pub(crate) struct Coalescer<'b> {
    slice: &'b mut [u8],
}

impl<'b> Coalescer<'b> {
    #[inline]
    pub(crate) fn new(slice: &'b mut [u8]) -> Self {
        Self { slice }
    }

    #[inline]
    pub(crate) fn copy_within(&mut self, from: Range<usize>, to: Range<usize>) {
        debug_assert!(from.len() == to.len());
        debug_assert!(self.slice.get(from.clone()).is_some());
        debug_assert!(self.slice.get(to.clone()).is_some());
        self.slice.copy_within(from, to.start);
    }

    #[inline]
    pub(crate) fn delocator(self) -> Delocator<'b> {
        Delocator::new(self.slice)
    }
}

/// Accounting structure tracking progress in parsing a single buffer.
#[derive(Clone, Debug)]
pub(crate) struct BufferProgress {
    /// Prefix of the buffer that has been processed so far.
    ///
    /// `processed` may exceed `discard`, that means we have parsed
    /// some buffer, but are still using it.  This happens due to
    /// in-place decryption of incoming records, and in-place
    /// reassembly of handshake messages.
    ///
    /// 0 <= processed <= len
    processed: usize,

    /// Prefix of the buffer that can be removed.
    ///
    /// If `discard` exceeds `processed`, that means we are ignoring
    /// data without processing it.
    ///
    /// 0 <= discard <= len
    discard: usize,
}

impl BufferProgress {
    pub(super) fn new(processed: usize) -> Self {
        Self {
            processed,
            discard: 0,
        }
    }

    #[inline]
    pub(crate) fn add_discard(&mut self, discard: usize) {
        self.discard += discard;
    }

    #[inline]
    pub(crate) fn add_processed(&mut self, processed: usize) {
        self.processed += processed;
    }

    /// Passes over `skipped` bytes of records that failed trial decryption:
    /// processed, and to be removed. Nothing before them may still be in
    /// use, as a handshake message being joined would be: trial decryption
    /// ends at the first handshake message, and fails if one is being
    /// joined.
    #[inline]
    pub(crate) fn skip(&mut self, skipped: usize) {
        if skipped == 0 {
            return;
        }
        debug_assert_eq!(
            self.discard, self.processed,
            "records skipped behind bytes still in use"
        );
        self.add_processed(skipped);
        self.add_discard(skipped);
    }

    #[inline]
    pub(crate) fn take_discard(&mut self) -> usize {
        // the caller is about to discard `discard` bytes
        // from the front of the buffer.  adjust `processed`
        // down by the same amount.
        self.processed = self.processed.saturating_sub(self.discard);
        mem::take(&mut self.discard)
    }

    #[inline]
    pub(crate) fn processed(&self) -> usize {
        self.processed
    }
}

/// TLS allows for handshake messages of up to 16MB.  We
/// restrict that to 64KB to limit potential for denial-of-
/// service.
#[cfg(feature = "std")]
const MAX_HANDSHAKE_SIZE: usize = 0xffff;

#[derive(Default, Debug)]
pub(crate) struct DeframerVecBuffer {
    /// Buffer of data read from the socket, in the process of being parsed into messages.
    ///
    /// For buffer size management, checkout out the [`DeframerVecBuffer::prepare_read()`] method.
    buf: Vec<u8>,

    /// What size prefix of `buf` is used.
    used: usize,

    /// Pays for `buf`'s capacity, charged before it grows.
    paid: Paid,
}

impl DeframerVecBuffer {
    /// An empty buffer that pays for itself with `paid`.
    pub(crate) fn paid_with(paid: Paid) -> Self {
        Self {
            paid,
            ..Self::default()
        }
    }

    /// Makes `buf` `len` bytes long, paying for the capacity first. Refuses,
    /// changing nothing, if the budget has no room.
    ///
    /// A buffer that must grow grows to at least twice its capacity, up to
    /// `most`, so that a message joined from many records is moved to a
    /// larger allocation a few times, not once a record. Growing moves the
    /// bytes to a new allocation while the old one is still held, so both
    /// are paid for until the old one is freed. The capacity stays until
    /// the buffer empties ([`Self::release_if_empty`]): giving part of it
    /// back would move the bytes again.
    #[must_use = "a refused growth must not be followed by a write past the length"]
    fn resize(&mut self, len: usize, most: usize) -> bool {
        let capacity = self.buf.capacity();
        if len > capacity {
            let grown = len.max(Ord::min(capacity * 2, most));
            if !self.paid.grow_by(grown) {
                return false;
            }
            self.buf.reserve_exact(grown - self.buf.len());
            // The old allocation is freed: its charge goes back, and so
            // does any the new one does not hold.
            self.paid.shrink_by(capacity + grown - self.buf.capacity());
        }
        self.buf.resize(len, 0);
        true
    }

    /// What the buffer's allocation takes.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.buf.capacity()
    }

    /// Whether what is paid for is the capacity, as the invariant says.
    #[cfg(test)]
    pub(crate) fn accounted(&self) -> bool {
        !self.paid.is_budgeted() || self.paid.bytes() == self.buf.capacity()
    }

    /// Discard `taken` bytes from the start of our buffer.
    pub(crate) fn discard(&mut self, taken: usize) {
        #[allow(clippy::comparison_chain)]
        if taken < self.used {
            /* Before:
             * +----------+----------+----------+
             * | taken    | pending  |xxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ taken    ^ self.used
             *
             * After:
             * +----------+----------+----------+
             * | pending  |xxxxxxxxxxxxxxxxxxxxx|
             * +----------+----------+----------+
             * 0          ^ self.used
             */

            self.buf.copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken >= self.used {
            self.used = 0;
        }
        self.release_if_empty();
    }

    /// Frees the allocation once nothing is buffered, giving back its
    /// charge: an idle connection holds no receive buffer.
    fn release_if_empty(&mut self) {
        if self.used == 0 && self.buf.capacity() != 0 {
            let capacity = self.buf.capacity();
            self.buf = Vec::new();
            self.paid.shrink_by(capacity);
        }
    }

    /// Takes everything buffered out, with the charge that pays for it,
    /// leaving the buffer empty and unallocated. Everything buffered is one
    /// record (after any records skipped before it), whose plaintext was
    /// decrypted in place at `plaintext`: the plaintext leaves in the buffer
    /// it arrived in, moved to its front, and nothing is copied out.
    pub(crate) fn take_plaintext(&mut self, plaintext: Range<usize>) -> PaidBytes {
        debug_assert!(plaintext.end <= self.used);
        let mut bytes = mem::take(&mut self.buf);
        self.used = 0;
        bytes.truncate(plaintext.end);
        bytes.drain(..plaintext.start);
        let charge = self.paid.split(bytes.capacity());
        PaidBytes::new(bytes, charge)
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.used]
    }

    pub(crate) fn filled(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

#[cfg(feature = "std")]
impl DeframerVecBuffer {
    /// Reads bytes from `rd` up to the end of the record arriving, and no
    /// further. The buffer holds the parts of a handshake message being
    /// joined, which end at `joined`, and after them at most one record:
    /// the one arriving. It grows to hold that record, paid for before it
    /// grows: its header first, then the rest once the header says how
    /// long the record is and is checked to be a record's header.
    ///
    /// Fails, having read nothing, with [`io::ErrorKind::OutOfMemory`] if
    /// the buffer must grow and the budget has no room,
    /// [`io::ErrorKind::InvalidData`] if it holds the most it may or the
    /// record arriving has a header no record may have, and
    /// [`io::ErrorKind::Other`] if a whole record is buffered: it must be
    /// processed first.
    pub(crate) fn read(
        &mut self,
        rd: &mut dyn io::Read,
        joined: usize,
        joining: bool,
    ) -> io::Result<usize> {
        let mut read = 0;
        let result = loop {
            if let Err(no_room) = self.prepare_read(joined, joining) {
                break match read {
                    0 => Err(no_room.into()),
                    _ => Ok(read),
                };
            }
            let n = match rd.read(&mut self.buf[self.used..]) {
                Ok(n) => n,
                Err(_) if read > 0 => break Ok(read),
                Err(error) => break Err(error),
            };
            self.used += n;
            read += n;
            // A short read has taken what `rd` had; a full one has
            // completed the header, which says how much more to read, or
            // the record.
            if n == 0 || self.used < self.buf.len() {
                break Ok(read);
            }
        };
        self.release_if_empty();
        result
    }

    /// Sizes `buf` to what the record arriving takes, or its header while
    /// that is incomplete: its length exactly, its capacity perhaps more.
    fn prepare_read(&mut self, joined: usize, joining: bool) -> Result<(), NoRoom> {
        // We allow a maximum of 64k of buffered data for handshake messages
        // only: the parts of the message joined so far stay in the buffer
        // ahead of the record arriving.
        let allow_max = match joining {
            true => MAX_HANDSHAKE_SIZE,
            false => MAX_WIRE_SIZE,
        };

        let end = self.arriving_end(joined)?;
        if self.used >= allow_max {
            return Err(NoRoom::Full);
        }

        // A record that would take a message being joined past the most it
        // may hold is read up to the limit; processing it fails then.
        let need = Ord::min(end, allow_max);
        if need != self.buf.len() && !self.resize(need, allow_max) {
            return Err(NoRoom::Unpaid);
        }

        Ok(())
    }

    /// Where the record arriving after `from` ends, or where its header
    /// does while that is incomplete. The header is checked as soon as it
    /// is whole, so a header no record may have grows nothing past itself.
    fn arriving_end(&self, from: usize) -> Result<usize, NoRoom> {
        let end = record_end(self.filled(), from).map_err(|_| NoRoom::Invalid)?;
        match end > self.used {
            true => Ok(end),
            false => Err(NoRoom::Waiting),
        }
    }

    /// Append `bytes` to the end of this buffer.
    ///
    /// Return a `Range` saying where it went, or `None`, changing nothing, if
    /// the buffer must grow and the budget has no room.
    pub(crate) fn extend(&mut self, bytes: &[u8]) -> Option<Range<usize>> {
        let len = bytes.len();
        let start = self.used;
        let end = start + len;
        if self.buf.len() < end && !self.resize(end, end.max(MAX_HANDSHAKE_SIZE)) {
            return None;
        }
        self.buf[start..end].copy_from_slice(bytes);
        self.used += len;
        Some(Range { start, end })
    }
}

/// Why a read found no room.
#[cfg(feature = "std")]
enum NoRoom {
    /// The buffer holds the most it may.
    Full,
    /// The buffer must grow, and the budget has no room.
    Unpaid,
    /// A whole record is buffered, waiting to be processed.
    Waiting,
    /// The record arriving has a header no record may have: processing
    /// fails on it.
    Invalid,
}

#[cfg(feature = "std")]
impl From<NoRoom> for io::Error {
    fn from(no_room: NoRoom) -> Self {
        match no_room {
            NoRoom::Full => Self::new(io::ErrorKind::InvalidData, "message buffer full"),
            NoRoom::Unpaid => Self::new(
                io::ErrorKind::OutOfMemory,
                "no budget for the received records",
            ),
            NoRoom::Waiting => Self::new(
                io::ErrorKind::Other,
                "a received record waits for process_new_packets",
            ),
            NoRoom::Invalid => Self::new(io::ErrorKind::InvalidData, "invalid record header"),
        }
    }
}

/// A borrowed version of [`DeframerVecBuffer`] that tracks discard operations
#[derive(Debug)]
pub(crate) struct DeframerSliceBuffer<'a> {
    // a fully initialized buffer that will be deframed
    buf: &'a mut [u8],
    // number of bytes to discard from the front of `buf` at a later time
    discard: usize,
}

impl<'a> DeframerSliceBuffer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, discard: 0 }
    }

    /// Tracks a pending discard operation of `num_bytes`
    pub(crate) fn queue_discard(&mut self, num_bytes: usize) {
        self.discard += num_bytes;
    }

    pub(crate) fn pending_discard(&self) -> usize {
        self.discard
    }

    pub(crate) fn filled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.discard..]
    }
}
