//! What a socket keeps of the bytes it received: the chunks the segments
//! arrived in, retained as they are, not copied into a ring.

use std::collections::VecDeque;

use fictionet_buf::{Budget, Chunk};

/// The most chunks one direction of a connection retains: what it is
/// charged for when it opens.
pub const SEGMENTS: usize = 64;

/// Pieces shorter than this are gathered into a block, so a peer sending a
/// byte at a time does not spend a chunk per byte.
pub(crate) const SMALL: usize = 128;

/// The least a block the store makes holds: one packet slot.
pub(crate) const SLOT: usize = 2048;

/// A store refused bytes: making room for them would take memory its
/// budget refused, or more chunks than [`SEGMENTS`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Full;

/// The receive side of a socket.
///
/// Bytes the application may read (`ready`, in order) and bytes received
/// out of order (`waiting`, by offset from the first byte not yet ready).
/// Each is a chunk of the segment it arrived in, so a segment of at least
/// [`SMALL`] bytes is kept with no copy while a chunk is free, unless its
/// clipped view would pin more than a slot of unused backing. The window
/// is the capacity less the bytes ready and unread, as a ring's was;
/// bytes waiting out of order do not shrink it, and are bounded by it.
///
/// The store keeps at most [`SEGMENTS`] chunks. Shorter pieces are
/// appended to the chunk before them when it has room and no other piece
/// shares it, or copied into a block of their own. When the chunks run
/// out, two neighbors are joined in a block of twice their length, so
/// bytes are copied a bounded number of times and a block holds at most
/// twice what it is used for. Blocks the store makes are charged to its
/// budget, and a refusal refuses the bytes, changing nothing.
#[derive(Debug)]
pub(crate) struct RxStore {
    capacity: usize,
    unread: usize,
    ready: VecDeque<Chunk>,
    /// Sorted by offset, disjoint, none empty, none at offset 0 between
    /// calls: bytes at offset 0 are contiguous and become ready.
    waiting: VecDeque<(usize, Chunk)>,
    budget: Budget,
}

impl RxStore {
    pub(crate) fn new(capacity: usize, budget: Budget) -> RxStore {
        RxStore {
            capacity,
            unread: 0,
            ready: VecDeque::with_capacity(SEGMENTS),
            waiting: VecDeque::with_capacity(SEGMENTS),
            budget,
        }
    }

    /// The window as a ring of this size had it.
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// What pays for the blocks the store makes.
    pub(crate) fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Bytes ready and not yet read.
    pub(crate) fn len(&self) -> usize {
        self.unread
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.unread == 0
    }

    /// The bytes that may still arrive: the capacity less what is unread.
    pub(crate) fn window(&self) -> usize {
        self.capacity - self.unread
    }

    /// The chunks retained, ready and waiting.
    pub(crate) fn descriptors(&self) -> usize {
        self.ready.len() + self.waiting.len()
    }

    /// The memory the retained chunks keep alive, counting a backing once
    /// for every chunk that holds it: at least what is retained.
    pub(crate) fn held(&self) -> usize {
        let ready = self.ready.iter().map(Chunk::capacity);
        let waiting = self.waiting.iter().map(|(_, c)| c.capacity());
        ready.chain(waiting).sum()
    }

    /// The bytes waiting out of order, by offset from the first byte not
    /// yet ready.
    #[cfg(any(test, kani))]
    pub(crate) fn waiting(&self) -> impl Iterator<Item = (usize, &[u8])> + '_ {
        self.waiting.iter().map(|(at, c)| (*at, &c[..]))
    }

    /// Drops everything, as a socket that resets does.
    pub(crate) fn clear(&mut self) {
        self.ready.clear();
        self.waiting.clear();
        self.unread = 0;
    }

    /// Keeps the bytes of `payload` at `offset` from the first byte not
    /// yet ready that it does not hold yet: where a segment overlaps bytes
    /// already held, the first copy stays. `payload` lies within the
    /// window. Refuses, keeping none of it, when there is no room for its
    /// pieces; blocks joined to make room stay joined, which changes no
    /// byte.
    pub(crate) fn insert(&mut self, offset: usize, payload: &Chunk) -> Result<(), Full> {
        let end = offset + payload.len();
        debug_assert!(end <= self.window(), "a payload past the window");
        let pieces = self.gaps(offset, end).count();
        while self.descriptors() + pieces > SEGMENTS {
            self.join()?;
        }
        // What the store keeps is paid for: bytes that came paid keep their
        // payment, and bytes nothing pays for yet are charged to the store's
        // budget, or refused.
        let mut paid;
        let payload = if payload.charged() == 0 && pieces > 0 {
            paid = payload.clone();
            if !paid.repay(&self.budget) {
                return Err(Full);
            }
            &paid
        } else {
            payload
        };
        // A clipped contribution from an overlapping jumbo packet must not
        // pin the whole reassembly allocation. Prepare every needed copy
        // before changing the ranges, so a refusal keeps all input out.
        let mut pending: [Option<(usize, Chunk)>; SEGMENTS] = [const { None }; SEGMENTS];
        for (place, (start, stop)) in pending.iter_mut().zip(self.gaps(offset, end)) {
            let range = start - offset..stop - offset;
            let piece = if payload.capacity().saturating_sub(range.len()) > SLOT {
                Chunk::copy_of(&self.budget, &payload[range]).ok_or(Full)?
            } else {
                payload.slice(range)
            };
            *place = Some((start, piece));
        }
        for place in &mut pending[..pieces] {
            let (start, piece) = place.take().expect("every gap was prepared");
            self.place(start, piece);
        }
        Ok(())
    }

    /// The ranges within `start..end` that no waiting chunk holds.
    fn gaps(&self, start: usize, end: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
        let mut at = start;
        let mut held = self.waiting.iter().map(|(o, c)| (*o, o + c.len()));
        let mut next = held.next();
        core::iter::from_fn(move || {
            while at < end {
                match next {
                    Some((_, stop)) if stop <= at => next = held.next(),
                    Some((o, stop)) if o <= at => at = stop,
                    Some((o, _)) => {
                        let gap = (at, o.min(end));
                        at = gap.1;
                        return Some(gap);
                    }
                    None => {
                        let gap = (at, end);
                        at = end;
                        return Some(gap);
                    }
                }
            }
            None
        })
    }

    /// Keeps `piece`, which no waiting chunk overlaps, at `offset`: on the
    /// end of the chunk just before it if it is short and that chunk has
    /// room no other piece shares, or as a chunk of its own.
    fn place(&mut self, offset: usize, piece: Chunk) {
        let index = self.waiting.partition_point(|(o, _)| *o < offset);
        if piece.len() < SMALL
            && let Some((o, before)) = index.checked_sub(1).map(|i| &mut self.waiting[i])
            && *o + before.len() == offset
            && before.extend_within(&piece).is_ok()
        {
            return;
        }
        self.waiting.insert(index, (offset, piece));
    }

    /// Joins the two neighboring chunks, ready or waiting, with the fewest
    /// bytes between them, freeing one: in place when the first has room
    /// no other piece shares, otherwise in a new block.
    fn join(&mut self) -> Result<(), Full> {
        let ready = (1..self.ready.len()).map(|i| {
            let len = self.ready[i - 1].len() + self.ready[i].len();
            (len, Side::Ready(i))
        });
        let waiting = (1..self.waiting.len()).filter_map(|i| {
            let ((a, x), (b, y)) = (&self.waiting[i - 1], &self.waiting[i]);
            (a + x.len() == *b).then_some((x.len() + y.len(), Side::Waiting(i)))
        });
        let Some((len, side)) = ready.chain(waiting).min_by_key(|(len, _)| *len) else {
            return Err(Full);
        };
        match side {
            Side::Ready(i) => {
                join_pair(&self.budget, 0, SLOT.max(2 * len), self.ready.range_mut(i - 1..=i))?;
                drop(self.ready.remove(i));
            }
            Side::Waiting(i) => {
                let pair = self.waiting.range_mut(i - 1..=i).map(|(_, c)| c);
                join_pair(&self.budget, 0, SLOT.max(2 * len), pair)?;
                drop(self.waiting.remove(i));
            }
        }
        Ok(())
    }

    /// The waiting chunk at offset 0, now contiguous, taken out: the rest
    /// move down by its length. `None` when no chunk starts there.
    pub(crate) fn take_contiguous(&mut self) -> Option<Chunk> {
        if self.waiting.front()?.0 != 0 {
            return None;
        }
        let (_, chunk) = self.waiting.pop_front()?;
        for (offset, _) in &mut self.waiting {
            *offset -= chunk.len();
        }
        Some(chunk)
    }

    /// Makes `chunk` ready to read after what is: a short one on the end of
    /// the last ready chunk when that has room no other piece shares, or
    /// copied into a block of its own when the budget lets it.
    pub(crate) fn commit(&mut self, chunk: Chunk) {
        if chunk.is_empty() {
            return;
        }
        self.unread += chunk.len();
        if chunk.len() >= SMALL {
            return self.ready.push_back(chunk);
        }
        if let Some(last) = self.ready.back_mut()
            && last.extend_within(&chunk).is_ok()
        {
            return;
        }
        let gathered = Chunk::block(&self.budget, 0, SLOT).and_then(|mut block| {
            block.extend_within(&chunk).ok()?;
            Some(block)
        });
        self.ready.push_back(gathered.unwrap_or(chunk));
    }

    /// Up to `most` of the bytes ready, from the first chunk only.
    pub(crate) fn pop(&mut self, most: usize) -> Option<Chunk> {
        if most == 0 {
            return None;
        }
        let front = self.ready.front_mut()?;
        let chunk = if front.len() <= most {
            self.ready.pop_front()?
        } else {
            front.split_to(most)
        };
        self.unread -= chunk.len();
        Some(chunk)
    }

    /// The bytes ready, in order.
    pub(crate) fn unread(&self) -> impl Iterator<Item = &Chunk> {
        self.ready.iter()
    }

    /// Replaces each ready chunk, in order, by what `f` makes of it with
    /// the store's budget.
    pub(crate) fn rewrite(&mut self, mut f: impl FnMut(Chunk, &Budget) -> Chunk) {
        for _ in 0..self.ready.len() {
            let chunk = self.ready.pop_front().expect("counted");
            self.unread -= chunk.len();
            let chunk = f(chunk, &self.budget);
            self.unread += chunk.len();
            if !chunk.is_empty() {
                self.ready.push_back(chunk);
            }
        }
    }
}

/// Which neighbors [`RxStore::join`] joins: the chunk at this index and
/// the one before it.
#[derive(Clone, Copy)]
enum Side {
    Ready(usize),
    Waiting(usize),
}

/// Gathers the second of two neighboring chunks onto the first, which then
/// holds both: in place when the first has room no other piece shares,
/// otherwise in a new block with `headroom` followed by `capacity` bytes
/// that takes its place. The capacity must hold both pieces. The
/// caller drops the second after. Refuses, changing nothing, when the
/// budget refuses the block.
pub(crate) fn join_pair<'a>(
    budget: &Budget,
    headroom: usize,
    capacity: usize,
    mut pair: impl Iterator<Item = &'a mut Chunk>,
) -> Result<(), Full> {
    let (first, second) = (pair.next().expect("two"), pair.next().expect("two"));
    if first.extend_within(second).is_err() {
        let mut block = Chunk::block(budget, headroom, headroom + capacity).ok_or(Full)?;
        block.extend_within(first).expect("the first piece fits");
        block.extend_within(second).expect("both pieces fit");
        *first = block;
    }
    Ok(())
}

