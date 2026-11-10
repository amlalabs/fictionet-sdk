//! What a socket keeps of the bytes it sends: the application's chunks,
//! retained until acknowledged, not copied into a ring.

use std::collections::VecDeque;
use std::ops::Range;

use fictionet_buf::{Budget, Chunk};

use super::rx::{SEGMENTS, SLOT, SMALL, join_pair};

/// Room for the IP and TCP headers in front of a segment's payload: an
/// IPv4 header with options or an IPv6 header, and a TCP header with
/// options. A chunk written with this much headroom can go out as its own
/// segment with no copy.
pub const HEADROOM: usize = 120;

/// The send side of a socket.
///
/// The chunks the application wrote, in order, retained until the peer
/// acknowledges them; the first may be partly acknowledged. Admission is
/// by bytes, as a ring's was: a write fits when the capacity less what is
/// queued holds all of it. Writes shorter than [`SMALL`] are appended to
/// the last chunk when it has room no other piece shares, or gathered into
/// a block with [`HEADROOM`]. When [`SEGMENTS`] chunks are held, the two
/// neighbors with the fewest bytes are joined first. Blocks the store
/// makes are charged to its budget, and a refusal refuses the write.
#[derive(Debug)]
pub(crate) struct TxStore {
    capacity: usize,
    queued: usize,
    chunks: VecDeque<Chunk>,
    budget: Budget,
}

impl TxStore {
    pub(crate) fn new(capacity: usize, budget: Budget) -> TxStore {
        TxStore {
            capacity,
            queued: 0,
            chunks: VecDeque::with_capacity(SEGMENTS),
            budget,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Bytes queued and not yet acknowledged.
    pub(crate) fn len(&self) -> usize {
        self.queued
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.queued == 0
    }

    /// The bytes a write may still add.
    pub(crate) fn window(&self) -> usize {
        self.capacity - self.queued
    }

    /// The chunks retained.
    #[cfg(any(test, kani))]
    pub(crate) fn descriptors(&self) -> usize {
        self.chunks.len()
    }

    /// The memory the retained chunks keep alive, counting a backing once
    /// for every chunk that holds it.
    pub(crate) fn held(&self) -> usize {
        self.chunks.iter().map(Chunk::capacity).sum()
    }

    /// Where each retained chunk ends, as offsets from the first byte
    /// queued.
    #[cfg(any(test, kani))]
    pub(crate) fn ends(&self) -> impl Iterator<Item = usize> + '_ {
        self.chunks.iter().scan(0, |end, chunk| {
            *end += chunk.len();
            Some(*end)
        })
    }

    pub(crate) fn clear(&mut self) {
        self.chunks.clear();
        self.queued = 0;
    }

    /// Queues all of `chunk` after what is queued, or none of it: back,
    /// unchanged, when it does not fit the window or a block it needs is
    /// refused.
    pub(crate) fn push(&mut self, chunk: Chunk) -> Result<(), Chunk> {
        if chunk.len() > self.window() {
            return Err(chunk);
        }
        if chunk.is_empty() {
            return Ok(());
        }
        let short = chunk.len() < SMALL;
        if (short || self.chunks.len() >= SEGMENTS)
            && let Some(last) = self.chunks.back_mut()
            && last.extend_within(&chunk).is_ok()
        {
            self.queued += chunk.len();
            return Ok(());
        }
        while self.chunks.len() >= SEGMENTS {
            if self.join().is_err() {
                return Err(chunk);
            }
        }
        let gathered = short
            .then(|| {
                let mut block = Chunk::block(&self.budget, HEADROOM, HEADROOM + SLOT)?;
                block.extend_within(&chunk).ok()?;
                Some(block)
            })
            .flatten();
        self.queued += chunk.len();
        self.chunks.push_back(gathered.unwrap_or(chunk));
        Ok(())
    }

    /// Joins the two neighbors with the fewest bytes between them.
    fn join(&mut self) -> Result<(), super::rx::Full> {
        let i = (1..self.chunks.len())
            .min_by_key(|&i| self.chunks[i - 1].len() + self.chunks[i].len())
            .ok_or(super::rx::Full)?;
        join_pair(&self.budget, HEADROOM, self.chunks.range_mut(i - 1..=i))?;
        drop(self.chunks.remove(i));
        Ok(())
    }

    /// Where the byte at `offset` is: the chunk's index and the offset in it.
    fn locate(&self, mut offset: usize) -> Option<(usize, usize)> {
        for (i, chunk) in self.chunks.iter().enumerate() {
            if offset < chunk.len() {
                return Some((i, offset));
            }
            offset -= chunk.len();
        }
        None
    }

    /// Up to `len` bytes from `offset`, within one chunk: fewer at a
    /// chunk's end, as a ring's slice stopped at its wrap. Empty past the
    /// end.
    pub(crate) fn bytes(&self, offset: usize, len: usize) -> &[u8] {
        match self.locate(offset) {
            Some((i, at)) => {
                let chunk = &self.chunks[i];
                &chunk[at..chunk.len().min(at + len)]
            }
            None => &[],
        }
    }

    /// The bytes [`bytes`](Self::bytes) names, as a piece of the chunk
    /// that holds them, to send. `None` when there are none.
    pub(crate) fn piece(&mut self, offset: usize, len: usize) -> Option<Piece<'_>> {
        let (i, at) = self.locate(offset)?;
        let chunk = &mut self.chunks[i];
        let range = at..chunk.len().min(at + len);
        (!range.is_empty()).then_some(Piece { chunk, range })
    }

    /// Lets go of the first `bytes` queued, which the peer acknowledged.
    pub(crate) fn ack(&mut self, mut bytes: usize) {
        debug_assert!(bytes <= self.queued);
        self.queued -= bytes;
        while bytes > 0 {
            let front = self
                .chunks
                .front_mut()
                .expect("acknowledged bytes are queued");
            if front.len() <= bytes {
                bytes -= front.len();
                self.chunks.pop_front();
            } else {
                front.advance(bytes);
                bytes = 0;
            }
        }
    }
}

/// The payload of one segment: bytes of one retained chunk, never two.
#[derive(Debug)]
pub struct Piece<'a> {
    chunk: &'a mut Chunk,
    range: Range<usize>,
}

impl Piece<'_> {
    /// The payload's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.chunk[self.range.clone()]
    }

    pub fn len(&self) -> usize {
        self.range.len()
    }

    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    /// The segment as a chunk that shares the retained one, when the piece
    /// is all of a chunk the socket alone holds with `header` bytes of
    /// headroom: `write` gets the header's bytes followed by the payload,
    /// and writes the header. The socket keeps its view of the payload.
    /// `None`, calling nothing, otherwise: when another piece shares the
    /// chunk, such as the packet of an earlier send still on its way, the
    /// headroom is never written.
    pub fn in_place(&mut self, header: usize, write: impl FnOnce(&mut [u8])) -> Option<Chunk> {
        if self.range != (0..self.chunk.len()) {
            return None;
        }
        self.chunk.prepend(header)?;
        write(
            self.chunk
                .get_mut()
                .expect("prepend needs this chunk alone"),
        );
        let packet = self.chunk.clone();
        self.chunk.advance(header);
        Some(packet)
    }
}
