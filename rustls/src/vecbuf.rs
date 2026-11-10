use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::{cmp, mem};
#[cfg(feature = "std")]
use std::io;
#[cfg(feature = "std")]
use std::io::Read;

use crate::budget::{Paid, PaidBytes};
#[cfg(feature = "std")]
use crate::msgs::message::OutboundChunks;

/// What one place in the queue of chunks takes.
pub(crate) const PLACE: usize = size_of::<Vec<u8>>();

/// The places a queue takes when it first needs any beyond its first chunk.
pub(crate) const FIRST_PLACES: usize = 4;

/// The chunks of a queue, in order. The first is held in place, so a queue
/// of one chunk allocates no places, and one that empties and fills again
/// with a chunk at a time allocates nothing for them. The places of the
/// chunks after it are allocated as they are needed. The last chunk a
/// queue ever takes, its connection's final alert, is held in place too,
/// so it never needs a place.
#[derive(Default)]
struct Chunks {
    /// Invariant: `None` only if `rest` is empty and `last` is `None`.
    first: Option<Vec<u8>>,
    rest: VecDeque<Vec<u8>>,
    /// The final alert, behind every other chunk.
    last: Option<Vec<u8>>,
}

impl Chunks {
    fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    /// The chunks that take a place or the first: all but the final alert
    /// waiting behind them.
    fn len(&self) -> usize {
        usize::from(self.first.is_some()) + self.rest.len()
    }

    /// How many chunks fit without allocating more places.
    fn fit(&self) -> usize {
        1 + self.rest.capacity()
    }

    /// The places allocated, each [`PLACE`] bytes.
    fn places(&self) -> usize {
        self.rest.capacity()
    }

    /// Allocates `places` places in all for the chunks after the first.
    fn allocate_places(&mut self, places: usize) {
        self.rest.reserve_exact(places - self.rest.len());
    }

    /// Frees the places, returning how many there were.
    fn free_places(&mut self) -> usize {
        debug_assert!(self.rest.is_empty());
        mem::take(&mut self.rest).capacity()
    }

    fn push_back(&mut self, chunk: Vec<u8>) {
        debug_assert!(self.last.is_none(), "a chunk after the final alert");
        match self.first {
            None => self.first = Some(chunk),
            Some(_) => self.rest.push_back(chunk),
        }
    }

    /// Puts the final alert behind every chunk, without a place.
    fn push_last(&mut self, chunk: Vec<u8>) {
        debug_assert!(self.last.is_none(), "a second final alert");
        match self.first {
            None => self.first = Some(chunk),
            Some(_) => self.last = Some(chunk),
        }
    }

    fn pop_front(&mut self) -> Option<Vec<u8>> {
        let first = self.first.take()?;
        self.first = self.rest.pop_front().or_else(|| self.last.take());
        Some(first)
    }

    fn front(&self) -> Option<&Vec<u8>> {
        self.first.as_ref()
    }

    fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.first.iter().chain(&self.rest).chain(&self.last)
    }
}

/// This is a byte buffer that is built from a deque of byte vectors.
///
/// This avoids extra copies when appending a new byte vector,
/// at the expense of more complexity when reading out.
///
/// With a budget, it pays for its allocations before it makes them: each
/// chunk is paid for before it exists ([`Self::pay`]) and appended against
/// that payment ([`Self::push_paid`]); the places of the queue are paid for
/// as they grow; and room may be paid ahead for output a caller is about to
/// make ([`Self::reserve`]). Chunks leaving give their bytes back, or take
/// their charge with them ([`Self::pop_paid`]).
pub(crate) struct ChunkVecBuffer {
    /// How many bytes have been consumed in the first chunk.
    ///
    /// Invariant: zero if `chunks.is_empty()`
    /// Invariant: 0 <= `prefix_used` < `chunks[0].len()`
    prefix_used: usize,

    chunks: Chunks,

    /// The total upper limit (in bytes) of this object.
    limit: Option<usize>,

    /// Invariant, with a budget: the chunks' capacities, the places, the
    /// promised chunks, the reserve and the room kept for the final alert,
    /// in bytes.
    paid: Paid,

    /// Bytes paid for chunks not yet appended, and how many chunks.
    promised: usize,
    promised_chunks: usize,

    /// Room paid ahead, which the next payments take first.
    reserve: usize,

    /// Room kept for the one final alert a connection sends.
    alert_room: AlertRoom,

    /// The final alert is queued: chunks appended after it are dropped.
    ended: bool,
}

/// The room a queue keeps paid for its connection's final alert: a fatal
/// alert or a `close_notify`, after which nothing more goes out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlertRoom {
    /// Not paid for yet.
    Unpaid,
    /// Paid for and waiting: [`ALERT_ROOM`] bytes.
    Kept,
    /// Taken by the final alert, or given back.
    Spent,
}

/// The most one alert record takes: a 5-byte header, the 2-byte alert,
/// and the most a cipher adds (TLS 1.2 GCM's 8-byte explicit nonce and
/// 16-byte tag; TLS 1.3 adds a type byte and a tag, 17 bytes). The final
/// alert takes no place in the queue.
pub(crate) const ALERT_ROOM: usize = 5 + 2 + 8 + 16;

impl ChunkVecBuffer {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            prefix_used: 0,
            chunks: Chunks::default(),
            limit,
            paid: Paid::default(),
            promised: 0,
            promised_chunks: 0,
            reserve: 0,
            alert_room: AlertRoom::Unpaid,
            ended: false,
        }
    }

    /// An empty buffer that pays for itself with `paid`.
    pub(crate) fn paid_with(limit: Option<usize>, paid: Paid) -> Self {
        Self {
            paid,
            ..Self::new(limit)
        }
    }

    /// Sets the upper limit on how many bytes this
    /// object can store.
    ///
    /// Setting a lower limit than the currently stored
    /// data is not an error.
    ///
    /// A [`None`] limit is interpreted as no limit.
    pub(crate) fn set_limit(&mut self, new_limit: Option<usize>) {
        self.limit = new_limit;
    }

    /// If we're empty
    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// How many bytes we're storing
    pub(crate) fn len(&self) -> usize {
        self.chunks
            .iter()
            .fold(0usize, |acc, chunk| acc + chunk.len())
            - self.prefix_used
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?
    pub(crate) fn apply_limit(&self, len: usize) -> usize {
        if let Some(limit) = self.limit {
            let space = limit.saturating_sub(self.len());
            cmp::min(len, space)
        } else {
            len
        }
    }

    /// The places the queue grows to so that `chunks` more fit with those
    /// already promised, or `None` if they fit already.
    fn places_for(&self, chunks: usize) -> Option<usize> {
        let wanted = self.chunks.len() + self.promised_chunks + chunks;
        let now = self.chunks.places();
        (wanted > self.chunks.fit()).then(|| (wanted - 1).max(now * 2).max(FIRST_PLACES))
    }

    /// The bytes `chunks` more chunks of `bytes` in all would take, places
    /// included.
    fn room_for(&self, bytes: usize, chunks: usize) -> usize {
        let places = self
            .places_for(chunks)
            .map_or(0, |places| (places - self.chunks.places()) * PLACE);
        bytes + places
    }

    /// Pays for `chunks` more chunks holding `bytes` in all, from the reserve
    /// first, before any of them exists, and makes their places. Refuses,
    /// changing nothing, if they do not fit.
    #[must_use = "a refused payment must not be followed by the chunk"]
    pub(crate) fn pay(&mut self, bytes: usize, chunks: usize) -> bool {
        let places = self.places_for(chunks);
        let total = self.room_for(bytes, chunks);
        let from_reserve = cmp::min(self.reserve, total);
        if !self.paid.grow_by(total - from_reserve) {
            return false;
        }
        self.reserve -= from_reserve;
        if let Some(places) = places {
            self.chunks.allocate_places(places);
        }
        self.promised += bytes;
        self.promised_chunks += chunks;
        true
    }

    /// Pays for the room the connection's final alert takes, once, so that
    /// the alert goes out whatever the budget says when it is sent. `true`
    /// once it is paid or was spent; `false`, changing nothing, if the
    /// budget has no room.
    #[must_use = "without the room an alert may go unsent"]
    pub(crate) fn keep_alert_room(&mut self) -> bool {
        if self.alert_room != AlertRoom::Unpaid {
            return true;
        }
        if !self.paid.grow_by(ALERT_ROOM) {
            return false;
        }
        self.alert_room = AlertRoom::Kept;
        true
    }

    /// Whether the room for the final alert is kept and waiting.
    pub(crate) fn keeps_alert_room(&self) -> bool {
        self.alert_room == AlertRoom::Kept
    }

    /// Pays for the connection's final alert, a record of `len` bytes: a
    /// fatal alert or a `close_notify`, after which nothing more goes out.
    /// It takes no place in the queue, and is paid from the reserve and the
    /// budget, or, if they have no room, from the room kept for it
    /// ([`Self::keep_alert_room`]), which always holds an alert record.
    /// Append it with [`Self::push_final_alert`].
    #[must_use = "a refused payment must not be followed by the chunk"]
    pub(crate) fn pay_final_alert(&mut self, len: usize) -> bool {
        let from_reserve = cmp::min(self.reserve, len);
        let need = len - from_reserve;
        let kept = self.alert_room == AlertRoom::Kept;
        // What of the room kept goes back: all of it if the budget paid,
        // and what the alert did not take if the room paid.
        let give_back = if self.paid.grow_by(need) {
            if kept {
                ALERT_ROOM
            } else {
                0
            }
        } else if kept && need <= ALERT_ROOM {
            ALERT_ROOM - need
        } else {
            return false;
        };
        self.reserve -= from_reserve;
        self.paid.shrink_by(give_back);
        self.alert_room = AlertRoom::Spent;
        self.promised += len;
        true
    }

    /// Appends the final alert, paid for by [`Self::pay_final_alert`] as
    /// `paid` bytes, behind every chunk queued. Chunks appended after it
    /// are never sent ([`Self::push_paid`]).
    #[must_use = "a dropped chunk was never queued"]
    pub(crate) fn push_final_alert(&mut self, chunk: Vec<u8>, paid: usize) -> bool {
        self.promised -= paid;
        let capacity = chunk.capacity();
        if capacity < paid {
            self.paid.shrink_by(paid - capacity);
        } else if capacity > paid && !self.paid.grow_by(capacity - paid) {
            self.paid.shrink_by(paid);
            return false;
        }
        self.chunks.push_last(chunk);
        self.ended = true;
        true
    }

    /// Appends `chunk`, paid for by [`Self::pay`] as one chunk of `paid`
    /// bytes. A chunk whose allocation is smaller gives back the rest; one
    /// whose allocation is larger, which its maker said it would not be, is
    /// charged the difference, or dropped, returning `false`, if that does
    /// not fit.
    #[must_use = "a dropped chunk was never queued"]
    pub(crate) fn push_paid(&mut self, chunk: Vec<u8>, paid: usize) -> bool {
        if self.ended {
            // Nothing goes out after the final alert.
            self.promised -= paid;
            self.promised_chunks -= 1;
            self.paid.shrink_by(paid);
            self.release_idle_places();
            return true;
        }
        self.promised -= paid;
        self.promised_chunks -= 1;
        let capacity = chunk.capacity();
        if capacity < paid {
            self.paid.shrink_by(paid - capacity);
        } else if capacity > paid && !self.paid.grow_by(capacity - paid) {
            self.paid.shrink_by(paid);
            return false;
        }
        if chunk.is_empty() {
            self.paid.shrink_by(capacity);
            self.release_idle_places();
            return true;
        }
        if self.chunks.is_empty() {
            debug_assert_eq!(self.prefix_used, 0);
        }
        self.chunks.push_back(chunk);
        true
    }

    /// Appends `chunk`, which comes with the charge that pays for its
    /// allocation, without copying it: a record decrypted where it was
    /// read. Its place is paid for first, from the reserve if there is one.
    /// `false`, with the chunk dropped and its charge given back, if the
    /// place does not fit or the charge is not on this queue's budget.
    #[must_use = "a refused chunk was never queued"]
    pub(crate) fn push_charged(&mut self, chunk: PaidBytes) -> bool {
        let (bytes, charge) = chunk.into_parts();
        if bytes.is_empty() {
            return true;
        }
        if !self.pay(0, 1) {
            return false;
        }
        self.promised_chunks -= 1;
        if !self.paid.absorb(charge) {
            self.release_idle_places();
            return false;
        }
        self.chunks.push_back(bytes);
        true
    }

    /// Pays for a chunk of `len` bytes and appends it, made by `make` once
    /// paid for. `false`, with nothing made, if it does not fit.
    #[must_use = "a refused chunk was never queued"]
    pub(crate) fn append_with(&mut self, len: usize, make: impl FnOnce() -> Vec<u8>) -> bool {
        self.pay(len, 1) && self.push_paid(make(), len)
    }

    /// Pays ahead for room for `chunks` more chunks of `bytes` in all, so
    /// that paying for them later takes nothing more from the budget. Room
    /// already reserved counts. Refuses, changing nothing, if it does not
    /// fit.
    #[must_use = "a refused reservation leaves no room"]
    pub(crate) fn reserve(&mut self, bytes: usize, chunks: usize) -> bool {
        let wanted = self.room_for(bytes, chunks);
        if wanted <= self.reserve {
            return true;
        }
        if !self.paid.grow_by(wanted - self.reserve) {
            return false;
        }
        self.reserve = wanted;
        true
    }

    /// Gives back the room reserved and not used.
    pub(crate) fn release_reserve(&mut self) {
        self.paid.shrink_by(mem::take(&mut self.reserve));
        self.release_idle_places();
    }

    /// Gives the places back once nothing is queued, promised or reserved,
    /// so that an idle queue holds no allocation at all.
    fn release_idle_places(&mut self) {
        if self.chunks.is_empty()
            && self.promised_chunks == 0
            && self.reserve == 0
            && self.chunks.places() != 0
        {
            let places = self.chunks.free_places();
            self.paid.shrink_by(places * PLACE);
        }
    }

    /// Take one of the chunks from this object. Its bytes are given back.
    ///
    /// This function returns `None` if the object `is_empty`.
    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        let mut first = self.chunks.pop_front();

        if let Some(first) = &mut first {
            // slice off `prefix_used` if needed (uncommon)
            let prefix = mem::take(&mut self.prefix_used);
            first.drain(0..prefix);
            self.paid.shrink_by(first.capacity());
        }
        self.release_idle_places();

        first
    }

    /// Take one of the chunks from this object, with the charge that pays
    /// for it.
    pub(crate) fn pop_paid(&mut self) -> Option<PaidBytes> {
        let mut first = self.chunks.pop_front()?;
        let prefix = mem::take(&mut self.prefix_used);
        first.drain(0..prefix);
        let charge = self.paid.split(first.capacity());
        self.release_idle_places();
        Some(PaidBytes::new(first, charge))
    }

    pub(crate) fn take_sole_whole_chunk(&mut self, max_capacity: usize) -> Option<PaidBytes> {
        if self.prefix_used != 0
            || self.chunks.len() != 1
            || self.chunks.front()?.capacity() > max_capacity
        {
            return None;
        }
        self.pop_paid()
    }

    #[cfg(read_buf)]
    /// Read data out of this object, writing it into `cursor`.
    pub(crate) fn read_buf(
        &mut self,
        mut cursor: core::io::BorrowedCursor<'_, u8>,
    ) -> io::Result<()> {
        while cursor.capacity() > 0 {
            let Some(chunk) = self.chunk() else {
                break;
            };
            let used = cmp::min(chunk.len(), cursor.capacity());
            cursor.append(&chunk[..used]);
            self.consume(used);
        }

        Ok(())
    }

    /// Inspect the first chunk from this object.
    pub(crate) fn peek(&self) -> Option<&[u8]> {
        self.chunks.front().map(|ch| ch.as_slice())
    }

    /// Returns the first contiguous chunk of data, or None if empty.
    pub(crate) fn chunk(&self) -> Option<&[u8]> {
        self.chunks.front().map(|chunk| &chunk[self.prefix_used..])
    }

    pub(crate) fn consume_first_chunk(&mut self, used: usize) {
        // this backs (infallible) `BufRead::consume`, where `used` is
        // user-supplied.
        assert!(
            used <= self.chunk().map(|ch| ch.len()).unwrap_or_default(),
            "illegal `BufRead::consume` usage",
        );
        self.consume(used);
    }

    /// Drops the first `used` bytes, giving back each chunk they cover
    /// wholly.
    fn consume(&mut self, used: usize) {
        // first, mark the rightmost extent of the used buffer
        self.prefix_used += used;

        // then reduce `prefix_used` by discarding wholly-covered
        // buffers
        while let Some(buf) = self.chunks.front() {
            if self.prefix_used < buf.len() {
                return;
            } else {
                self.prefix_used -= buf.len();
                let capacity = buf.capacity();
                self.chunks.pop_front();
                self.paid.shrink_by(capacity);
            }
        }
        self.release_idle_places();

        debug_assert_eq!(
            self.prefix_used, 0,
            "attempted to `ChunkVecBuffer::consume` more than available"
        );
    }

    /// What the queue's allocations take, with what it has paid ahead.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.chunks.iter().map(Vec::capacity).sum::<usize>()
            + self.chunks.places() * PLACE
            + self.promised
            + self.reserve
            + match self.alert_room {
                AlertRoom::Kept => ALERT_ROOM,
                AlertRoom::Unpaid | AlertRoom::Spent => 0,
            }
    }

    /// Whether what is paid for is what is held, as the invariant says.
    #[cfg(test)]
    pub(crate) fn accounted(&self) -> bool {
        !self.paid.is_budgeted() || self.paid.bytes() == self.held()
    }
}

#[cfg(feature = "std")]
impl ChunkVecBuffer {
    pub(crate) fn is_full(&self) -> bool {
        self.limit
            .map(|limit| self.len() > limit)
            .unwrap_or_default()
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit, and none if the budget has no room.
    pub(crate) fn append_limited_copy(&mut self, payload: OutboundChunks<'_>) -> usize {
        let take = self.apply_limit(payload.len());
        if take == 0 || !self.append_with(take, || payload.split_at(take).0.to_vec()) {
            return 0;
        }
        take
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() {
            let Some(mut chunk) = self.chunk() else {
                break;
            };
            let used = chunk.read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }

        Ok(offs)
    }

    /// Read data out of this object, passing it `wr`
    pub(crate) fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let mut prefix = self.prefix_used;
        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, chunk) in bufs.iter_mut().zip(self.chunks.iter()) {
            *iov = io::IoSlice::new(&chunk[prefix..]);
            prefix = 0;
        }
        let len = cmp::min(bufs.len(), self.chunks.len());
        let bufs = &bufs[..len];
        let used = wr.write_vectored(bufs)?;
        let available_bytes = bufs.iter().map(|ch| ch.len()).sum();

        if used > available_bytes {
            // This is really unrecoverable, since the amount of data written
            // is now unknown.  Consume all the potentially-written data in
            // case the caller ignores the error.
            // See <https://github.com/rustls/rustls/issues/2316> for background.
            self.consume(available_bytes);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                std::format!("illegal write_vectored return value ({used} > {available_bytes})"),
            ));
        }
        self.consume(used);
        Ok(used)
    }
}

#[cfg(test)]
impl ChunkVecBuffer {
    /// Pays for a copy of `bytes` and appends it, for tests.
    pub(crate) fn append_copy(&mut self, bytes: &[u8]) -> bool {
        self.append_with(bytes.len(), || bytes.to_vec())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{ChunkVecBuffer, PLACE};
    use crate::budget::testing::Limit;
    use crate::budget::{Account, Paid, PaidBytes};

    #[test]
    fn a_queue_of_one_chunk_at_a_time_allocates_no_places() {
        let limit = Limit::new(1000);
        let account: Account = Some(limit.clone());
        let mut cvb = ChunkVecBuffer::paid_with(None, Paid::open(&account));
        for round in 0..3u8 {
            assert!(cvb.append_copy(&[round; 10]));
            assert_eq!(cvb.chunks.places(), 0, "round {round}");
            assert_eq!(limit.used(), cvb.len(), "round {round}");
            assert_eq!(cvb.pop(), Some(vec![round; 10]));
            assert_eq!(limit.used(), 0, "round {round}");
        }
        assert!(cvb.append_copy(&[1; 10]));
        assert!(cvb.append_copy(&[2; 10]));
        assert_ne!(cvb.chunks.places(), 0, "a second chunk needs places");
        assert!(cvb.accounted());
        assert_eq!(cvb.pop(), Some(vec![1; 10]));
        assert_eq!(cvb.pop(), Some(vec![2; 10]));
        assert_eq!((cvb.held(), limit.used()), (0, 0));
    }

    #[test]
    fn short_append_copy_with_limit() {
        let mut cvb = ChunkVecBuffer::new(Some(12));
        assert_eq!(cvb.append_limited_copy(b"hello"[..].into()), 5);
        assert_eq!(cvb.append_limited_copy(b"world"[..].into()), 5);
        assert_eq!(cvb.append_limited_copy(b"hello"[..].into()), 2);
        assert_eq!(cvb.append_limited_copy(b"world"[..].into()), 0);

        let mut buf = [0u8; 12];
        assert_eq!(cvb.read(&mut buf).unwrap(), 12);
        assert_eq!(buf.to_vec(), b"helloworldhe".to_vec());
    }

    #[test]
    fn read_byte_by_byte() {
        let mut cvb = ChunkVecBuffer::new(None);
        assert!(cvb.append_copy(b"test fixture data"));
        assert!(!cvb.is_empty());
        for expect in b"test fixture data" {
            let mut byte = [0];
            assert_eq!(cvb.read(&mut byte).unwrap(), 1);
            assert_eq!(byte[0], *expect);
        }

        assert_eq!(cvb.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn every_possible_chunk_interleaving() {
        let input = (0..=0xffu8).cycle().take(4096).collect::<Vec<u8>>();

        for input_chunk_len in 1..64usize {
            for output_chunk_len in 1..65usize {
                std::println!("check input={input_chunk_len} output={output_chunk_len}");
                let mut cvb = ChunkVecBuffer::new(None);
                for chunk in input.chunks(input_chunk_len) {
                    assert!(cvb.append_copy(chunk));
                }

                assert_eq!(cvb.len(), input.len());
                let mut buf = vec![0u8; output_chunk_len];

                for expect in input.chunks(output_chunk_len) {
                    assert_eq!(expect.len(), cvb.read(&mut buf).unwrap());
                    assert_eq!(expect, &buf[..expect.len()]);
                }

                assert_eq!(cvb.read(&mut [0]).unwrap(), 0);
            }
        }
    }

    #[cfg(read_buf)]
    #[test]
    fn read_buf() {
        use core::io::BorrowedBuf;
        use core::mem::MaybeUninit;

        {
            let mut cvb = ChunkVecBuffer::new(None);
            assert!(cvb.append_copy(b"test "));
            assert!(cvb.append_copy(b"fixture "));
            assert!(cvb.append_copy(b"data"));

            let mut buf = [MaybeUninit::<u8>::uninit(); 8];
            let mut buf: BorrowedBuf<'_, u8> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"test fix");
            buf.clear();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"ture dat");
            buf.clear();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"a");
        }

        {
            let mut cvb = ChunkVecBuffer::new(None);
            assert!(cvb.append_copy(b"short message"));

            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let mut buf: BorrowedBuf<'_, u8> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"short message");
        }
    }

    /// A small model of the queue: random payments, appends, reservations,
    /// reads and takes against a budget, checking after each that the
    /// charge is what the queue holds, that a refusal changes nothing, and
    /// that everything comes back at the end.
    #[test]
    fn a_paid_queue_holds_exactly_what_it_is_charged() {
        let limit = Limit::new(600);
        let account: Account = Some(limit.clone());
        let mut cvb = ChunkVecBuffer::paid_with(None, Paid::open(&account));
        let mut model = Vec::new();
        let mut taken = Vec::new();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n) as usize
        };
        for step in 0..4000usize {
            let used = limit.used();
            let len = cvb.len();
            match next(6) {
                0 | 1 => {
                    let n = 1 + next(120);
                    let byte = step as u8;
                    let need = cvb.room_for(n, 1).saturating_sub(cvb.reserve);
                    if cvb.append_with(n, || vec![byte; n]) {
                        model.extend(core::iter::repeat(byte).take(n));
                        assert_eq!(limit.used(), used + need);
                    } else {
                        assert_eq!((limit.used(), cvb.len()), (used, len));
                        assert!(used + need > 600);
                    }
                }
                2 => {
                    let n = next(200);
                    let need = cvb.room_for(n, 1).saturating_sub(cvb.reserve);
                    if cvb.reserve(n, 1) {
                        assert_eq!(limit.used(), used + need);
                    } else {
                        assert_eq!((limit.used(), cvb.len()), (used, len));
                        assert!(used + need > 600);
                    }
                }
                3 => {
                    let mut buf = vec![0; next(90)];
                    let n = cvb.read(&mut buf).unwrap();
                    assert_eq!(&buf[..n], &model[..n]);
                    model.drain(..n);
                    assert!(limit.used() <= used);
                }
                4 => {
                    // A chunk made elsewhere, paid for by a charge of its
                    // own on the same budget, joins without a copy.
                    let n = 1 + next(120);
                    let byte = step as u8;
                    let mut paid = Paid::open(&account);
                    let place = cvb.room_for(0, 1).saturating_sub(cvb.reserve);
                    if !paid.grow_by(n) {
                        assert!(used + n > 600);
                    } else if cvb.push_charged(PaidBytes::new(vec![byte; n], paid.split(n))) {
                        model.extend(core::iter::repeat(byte).take(n));
                        assert_eq!(limit.used(), used + n + place);
                    } else {
                        assert_eq!((limit.used(), cvb.len()), (used, len));
                        assert!(used + n + place > 600);
                    }
                }
                _ => {
                    let places = cvb.chunks.places() * PLACE;
                    if let Some(paid) = cvb.pop_paid() {
                        let (bytes, charge) = paid.into_parts();
                        assert_eq!(&bytes[..], &model[..bytes.len()]);
                        model.drain(..bytes.len());
                        assert_eq!(charge.as_ref().unwrap().bytes(), bytes.capacity());
                        // The chunk's charge leaves with it; only places the
                        // queue gave back leave the budget.
                        let freed = places - cvb.chunks.places() * PLACE;
                        assert_eq!(limit.used(), used - freed);
                        taken.push((bytes, charge));
                        if taken.len() > 3 {
                            taken.remove(0);
                        }
                    }
                    cvb.release_reserve();
                }
            }
            assert!(cvb.accounted(), "step {step}");
            if cvb.is_empty() && cvb.reserve == 0 {
                assert_eq!(cvb.held(), 0, "step {step}: an idle queue holds nothing");
            }
            assert_eq!(cvb.len(), model.len());
            assert!(limit.used() <= 600);
        }
        drop(taken);
        drop(cvb);
        assert_eq!(limit.used(), 0);
    }

    #[test]
    fn a_reservation_pays_for_what_follows_without_the_budget() {
        let limit = Limit::new(1000);
        let account: Account = Some(limit.clone());
        let mut cvb = ChunkVecBuffer::paid_with(None, Paid::open(&account));
        assert!(cvb.reserve(100, 2));
        let reserved = limit.used();
        assert!(reserved >= 100);
        limit.set_limit(reserved);
        assert!(cvb.append_with(60, || vec![1; 60]));
        assert!(cvb.append_with(40, || vec![2; 40]));
        assert_eq!(limit.used(), reserved);
        assert!(!cvb.append_with(1, || vec![3; 1]));
        assert!(cvb.accounted());
        cvb.release_reserve();
        assert!(cvb.accounted());
    }
}

#[cfg(bench)]
mod benchmarks {
    use alloc::vec;

    use super::{ChunkVecBuffer, PLACE};

    #[bench]
    fn read_one_byte_from_large_message(b: &mut test::Bencher) {
        b.iter(|| {
            let mut cvb = ChunkVecBuffer::new(None);
            assert!(cvb.append_copy(&vec![0u8; 16_384]));
            assert_eq!(1, cvb.read(&mut [0u8]).unwrap());
        });
    }

    #[bench]
    fn read_all_individual_from_large_message(b: &mut test::Bencher) {
        b.iter(|| {
            let mut cvb = ChunkVecBuffer::new(None);
            assert!(cvb.append_copy(&vec![0u8; 16_384]));
            loop {
                if let Ok(0) = cvb.read(&mut [0u8]) {
                    break;
                }
            }
        });
    }

    #[bench]
    fn read_half_bytes_from_large_message(b: &mut test::Bencher) {
        b.iter(|| {
            let mut cvb = ChunkVecBuffer::new(None);
            assert!(cvb.append_copy(&vec![0u8; 16_384]));
            assert_eq!(8192, cvb.read(&mut [0u8; 8192]).unwrap());
            assert_eq!(8192, cvb.read(&mut [0u8; 8192]).unwrap());
        });
    }

    #[bench]
    fn read_entire_large_message(b: &mut test::Bencher) {
        b.iter(|| {
            let mut cvb = ChunkVecBuffer::new(None);
            assert!(cvb.append_copy(&vec![0u8; 16_384]));
            assert_eq!(16_384, cvb.read(&mut [0u8; 16_384]).unwrap());
        });
    }
}
