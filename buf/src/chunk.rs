use std::ops::{Deref, Range};
use std::sync::{Arc, Weak};

use crate::budget::{Budget, Charge};
use crate::pool::PoolShared;

/// Owned bytes on their way through a world, with what they cost.
///
/// A chunk is a view of a backing: the bytes from its cursor to its end.
/// Pieces split from one chunk ([`split_to`](Self::split_to),
/// [`slice`](Self::slice), [`Clone`]) share the backing without copying,
/// and see disjoint or equal bytes of it. A receiver that takes only part
/// of a chunk [`advance`](Self::advance)s past what it took and hands the
/// chunk back, so the rest keeps its place.
///
/// The backing holds two independent things that are given back when its
/// last piece is dropped: a reservation that pays for the allocation's
/// memory (its capacity), and an optional [`Held`] value, such as a
/// receive-credit lease, that the bytes keep until they are consumed.
/// Bytes are paid for when they are made ([`copy_of`](Self::copy_of),
/// [`paid`](Self::paid), [`Pool::take`](crate::Pool::take)) or when a
/// receiver admits them ([`repay`](Self::repay)). Whatever moves the
/// payment pays the new budget before the old one lets go, and allocates
/// nothing before it is paid.
///
/// A backing from a [`Pool`](crate::Pool) goes back to it whole, header
/// and bytes, when the last piece is dropped, so a steady exchange takes
/// and gives back the same backings and allocates nothing. Such a backing
/// is paid for at its full capacity, at every moment, by exactly one
/// budget: the taker's, then whoever admits it, then the pool's again.
///
/// Room before the cursor is headroom, and room after the end is room: a
/// chunk that alone holds its backing writes there in place
/// ([`prepend`](Self::prepend), [`extend_within`](Self::extend_within),
/// [`fill`](Self::fill)), which is how a header goes in front of bytes
/// already written. A shared backing is never written: the writers refuse
/// and [`make_mut`](Self::make_mut) copies.
pub struct Chunk {
    /// Always present while the chunk lives; taken out only as it drops,
    /// so the backing can go back to its pool whole.
    backing: Option<Arc<Backing>>,
    start: usize,
    end: usize,
}

/// The storage behind a chunk and every piece split from it.
pub(crate) struct Backing {
    /// Every byte the pieces can address. A pooled backing's length is its
    /// capacity, written once when it is made and never cleared again; an
    /// unpooled one's length is the bytes it was made from.
    pub(crate) bytes: Vec<u8>,
    /// Memory: what pays for `bytes`' allocation, if anything does yet.
    pub(crate) reservation: Option<Reservation>,
    /// What the bytes keep until their last piece is dropped.
    pub(crate) held: Option<Arc<dyn Held>>,
    /// The pool it goes back to, while that pool lives.
    pub(crate) pool: Option<Weak<PoolShared>>,
}

/// What pays for a backing's memory: a charge of its own, or a share of
/// one that pays for many, such as a child's receive window.
pub(crate) enum Reservation {
    Own(Charge),
    Shared(Arc<Charge>),
}

impl Reservation {
    fn charge(&self) -> &Charge {
        match self {
            Reservation::Own(charge) => charge,
            Reservation::Shared(charge) => charge,
        }
    }
}

/// Something bytes keep until their last piece is dropped, such as a lease
/// on a child's receive credit that returns the credit when dropped. It is
/// separate from what pays for the memory.
pub trait Held: Send + Sync + 'static {}

impl Backing {
    /// A pooled backing of `slot` bytes, empty of any payment.
    pub(crate) fn pooled(slot: usize, pool: Weak<PoolShared>) -> Backing {
        Backing {
            bytes: vec![0; slot],
            reservation: None,
            held: None,
            pool: Some(pool),
        }
    }
}

/// A vector of exactly `bytes`, whose capacity is its length.
fn exact(bytes: &[u8]) -> Vec<u8> {
    Box::<[u8]>::from(bytes).into_vec()
}

impl Chunk {
    /// Bytes nothing pays for yet: input from the wire, data from the
    /// world. Whoever takes them in pays at admission
    /// ([`repay`](Self::repay)).
    pub fn unpaid(bytes: impl Into<Vec<u8>>) -> Chunk {
        Self::backed(bytes.into(), None, None)
    }

    /// Bytes in a vector allocated before its payment was attached, such
    /// as a library's buffer or a container that held its own charge.
    /// `room` pays for them from now on: it must hold at least their
    /// capacity, and what it holds past that goes back. Otherwise both
    /// come back unchanged.
    pub fn paid(bytes: Vec<u8>, mut room: Charge) -> Result<Chunk, (Vec<u8>, Charge)> {
        if room.bytes() < bytes.capacity() {
            return Err((bytes, room));
        }
        room.shrink_to(bytes.capacity());
        Ok(Self::backed(bytes, Some(Reservation::Own(room)), None))
    }

    /// A copy of `bytes` in an allocation of exactly their size, charged to
    /// `budget` before it is made. `None`, with nothing allocated, if the
    /// budget has no room.
    pub fn copy_of(budget: &Budget, bytes: &[u8]) -> Option<Chunk> {
        let charge = budget.charge(bytes.len())?;
        Some(Self::backed(
            exact(bytes),
            Some(Reservation::Own(charge)),
            None,
        ))
    }

    /// An empty block of `capacity` bytes, not from a pool, with its cursor
    /// at `headroom`, charged to `budget` at its full capacity before it is
    /// made: a place to gather bytes with
    /// [`extend_within`](Self::extend_within) when no pool slot is large
    /// enough. `None`, with nothing allocated, if the budget has no room or
    /// `headroom` is past `capacity`.
    pub fn block(budget: &Budget, headroom: usize, capacity: usize) -> Option<Chunk> {
        if headroom > capacity {
            return None;
        }
        let charge = budget.charge(capacity)?;
        let mut chunk = Self::backed(vec![0; capacity], Some(Reservation::Own(charge)), None);
        chunk.start = headroom;
        chunk.end = headroom;
        Some(chunk)
    }

    /// Bytes for a child, made in the receive window its receiver lent and
    /// still keeps, which paid for them before it granted the credit they
    /// use: nothing is charged, and the receiver takes them in with no
    /// charge moving. Their capacity is their length, as the window pays
    /// for bytes, not spare room.
    pub fn in_window(mut bytes: Vec<u8>, window: Arc<Charge>) -> Chunk {
        bytes.shrink_to_fit();
        Self::backed(bytes, Some(Reservation::Shared(window)), None)
    }

    /// An empty view at `headroom` of a pooled backing the caller has just
    /// paid for.
    pub(crate) fn pooled(backing: Arc<Backing>, headroom: usize) -> Chunk {
        Chunk {
            backing: Some(backing),
            start: headroom,
            end: headroom,
        }
    }

    fn backed(
        bytes: Vec<u8>,
        reservation: Option<Reservation>,
        held: Option<Arc<dyn Held>>,
    ) -> Chunk {
        let end = bytes.len();
        Chunk {
            backing: Some(Arc::new(Backing {
                bytes,
                reservation,
                held,
                pool: None,
            })),
            start: 0,
            end,
        }
    }

    fn backing(&self) -> &Backing {
        self.backing
            .as_deref()
            .expect("a chunk holds its backing until it drops")
    }

    /// The backing, when this chunk alone holds it.
    fn unique(&mut self) -> Option<&mut Backing> {
        self.backing.as_mut().and_then(Arc::get_mut)
    }

    /// Whether the backing goes back to a pool.
    fn pooled_backing(&self) -> bool {
        self.backing().pool.is_some()
    }

    /// Whether the bytes not yet taken are all of an unpooled backing's
    /// bytes, so its spare capacity is all that lies outside them.
    fn whole(&self) -> bool {
        !self.pooled_backing() && self.start == 0 && self.end == self.backing().bytes.len()
    }

    /// The backing, when this chunk alone holds it and the bytes are all
    /// of an unpooled backing, so it can be resized in place.
    fn sole_whole(&mut self) -> Option<&mut Backing> {
        if self.whole() { self.unique() } else { None }
    }

    /// Makes these bytes a backing of their own, paid by `reservation`,
    /// holding `bytes`, a copy of them. The other pieces keep the old
    /// backing, with what pays for it. What the bytes held stays held.
    fn rebacked(&mut self, bytes: Vec<u8>, reservation: Reservation) {
        let held = self.backing().held.clone();
        *self = Self::backed(bytes, Some(reservation), held);
    }

    /// Puts the bytes in a receive window that `window` already pays for,
    /// so what paid for them before may release, and lets go of what they
    /// held: the window holds a new lease ([`hold`](Self::hold)). Unpooled
    /// bytes this chunk alone holds whole give back their spare capacity in
    /// place; others are copied into an allocation of their own size, so
    /// the shared charge covers no more than the bytes, and a pooled
    /// backing goes back to its pool.
    pub fn move_into_window(&mut self, window: Arc<Charge>) {
        if let Some(backing) = self.sole_whole() {
            backing.bytes.shrink_to_fit();
            backing.reservation = Some(Reservation::Shared(window));
            backing.held = None;
            return;
        }
        *self = Self::backed(exact(self), Some(Reservation::Shared(window)), None);
    }

    /// Makes the bytes keep `held` until every piece of them is released,
    /// in place of what they kept before. Hands it back when another piece
    /// shares the backing.
    pub fn hold<H: Held>(&mut self, held: H) -> Result<(), H> {
        match self.unique() {
            Some(backing) => {
                backing.held = Some(Arc::new(held));
                Ok(())
            }
            None => Err(held),
        }
    }

    /// Makes `budget` pay for the bytes: for bytes a receiver admits, or
    /// that pass from one owner to another. What paid for them before
    /// lets go only after `budget` has paid, and nothing is allocated
    /// before it is paid for. What the bytes hold stays held.
    ///
    /// - Bytes `budget` pays for already stay as they are, except that
    ///   spare capacity an unpooled chunk alone holds goes back. This
    ///   cannot fail and never raises what `budget` holds.
    /// - A pooled backing this chunk alone holds moves in place: `budget`
    ///   is charged its whole capacity, then the old payment goes.
    /// - Unpooled bytes this chunk alone holds, all of its backing, move in
    ///   place: `budget` is charged their whole capacity first, then the
    ///   spare capacity goes back and the old reservation goes.
    /// - Otherwise the bytes are copied into an allocation of exactly
    ///   their size, charged before it is made. The other pieces keep the
    ///   old backing and what pays for it.
    ///
    /// A refusal changes nothing: no copy, no reallocation, no release.
    #[must_use = "bytes a budget refused to pay for are not admitted"]
    pub fn repay(&mut self, budget: &Budget) -> bool {
        let paid_here = self
            .backing()
            .reservation
            .as_ref()
            .is_some_and(|reservation| reservation.charge().budget().same(budget));
        if paid_here {
            if let Some(backing) = self.sole_whole()
                && let Some(Reservation::Own(charge)) = &mut backing.reservation
            {
                backing.bytes.shrink_to_fit();
                charge.shrink_to(backing.bytes.capacity());
            }
            return true;
        }
        if self.pooled_backing()
            && let Some(backing) = self.unique()
        {
            let Some(charge) = budget.charge(backing.bytes.capacity()) else {
                return false;
            };
            backing.reservation = Some(Reservation::Own(charge));
            return true;
        }
        if let Some(backing) = self.sole_whole() {
            let Some(mut charge) = budget.charge(backing.bytes.capacity()) else {
                return false;
            };
            backing.bytes.shrink_to_fit();
            charge.shrink_to(backing.bytes.capacity());
            backing.reservation = Some(Reservation::Own(charge));
            return true;
        }
        let Some(charge) = budget.charge(self.len()) else {
            return false;
        };
        self.rebacked(exact(self), Reservation::Own(charge));
        true
    }

    /// Edits the remaining bytes without losing their reservation or what
    /// they hold. Backing this chunk alone holds is edited where it is, and
    /// if nothing pays for it yet, `budget` is charged all of its capacity
    /// first: other bytes may follow these. Shared backing is copied into
    /// an allocation of exactly these bytes, charged before it is made; the
    /// other pieces keep the original. A refusal changes nothing.
    pub fn make_mut(&mut self, budget: &Budget) -> Option<&mut [u8]> {
        if self.unique().is_none() {
            let charge = budget.charge(self.len())?;
            self.rebacked(exact(self), Reservation::Own(charge));
        }
        let range = self.start..self.end;
        let backing = self.unique()?;
        if backing.reservation.is_none() {
            let charge = budget.charge(backing.bytes.capacity())?;
            backing.reservation = Some(Reservation::Own(charge));
        }
        Some(&mut backing.bytes[range])
    }

    /// The remaining bytes to edit in place, when this chunk alone holds
    /// its backing. Charges nothing: what pays for the backing, or nothing,
    /// stays as it is. `None` when another piece shares it.
    pub fn get_mut(&mut self) -> Option<&mut [u8]> {
        let range = self.start..self.end;
        Some(&mut self.unique()?.bytes[range])
    }

    /// The room before the cursor: bytes [`prepend`](Self::prepend) can
    /// move it back over while this chunk alone holds its backing.
    pub fn headroom(&self) -> usize {
        self.start
    }

    /// Moves the cursor back `n` bytes and returns them, for the caller to
    /// write every one: a header in front of bytes already written. `None`,
    /// changing nothing, when another piece shares the backing or the
    /// headroom is short. Charges nothing: the backing is paid for whole,
    /// or not at all, already.
    pub fn prepend(&mut self, n: usize) -> Option<&mut [u8]> {
        if n > self.start {
            return None;
        }
        self.unique()?;
        self.start -= n;
        let start = self.start;
        Some(&mut self.unique()?.bytes[start..start + n])
    }

    /// The room after the end, within the backing: bytes
    /// [`extend_within`](Self::extend_within) and [`fill`](Self::fill) can
    /// write while this chunk alone holds its backing.
    pub fn room(&self) -> usize {
        self.backing().bytes.len() - self.end
    }

    /// Appends `bytes` within the room, when this chunk alone holds its
    /// backing. Otherwise writes none and returns how many of them would
    /// not fit: all of them when the backing is shared. Never reallocates
    /// and charges nothing.
    pub fn extend_within(&mut self, bytes: &[u8]) -> Result<(), usize> {
        let end = self.end;
        let Some(backing) = self.unique() else {
            return Err(bytes.len());
        };
        let room = backing.bytes.len() - end;
        if bytes.len() > room {
            return Err(bytes.len() - room);
        }
        backing.bytes[end..end + bytes.len()].copy_from_slice(bytes);
        self.end += bytes.len();
        Ok(())
    }

    /// Writes into the room with `fill`, which returns how many bytes it
    /// wrote from the start of what it was given, and adds them to the
    /// chunk. Returns that count, or `None`, calling nothing, when another
    /// piece shares the backing. The room may hold old bytes: `fill` must
    /// write every byte it counts. Panics if it counts more than the room.
    pub fn fill(&mut self, fill: impl FnOnce(&mut [u8]) -> usize) -> Option<usize> {
        let end = self.end;
        let backing = self.unique()?;
        let room = &mut backing.bytes[end..];
        let most = room.len();
        let wrote = fill(room);
        assert!(wrote <= most, "a fill counted more than its room");
        self.end += wrote;
        Some(wrote)
    }

    /// The bytes in `range` of the remaining ones, as a chunk of their own
    /// that shares the backing, without taking them from this one. Panics
    /// if the range is backwards or past the end.
    pub fn slice(&self, range: Range<usize>) -> Chunk {
        assert!(
            range.start <= range.end && range.end <= self.len(),
            "chunk slice exceeds its remaining bytes"
        );
        Chunk {
            backing: self.backing.clone(),
            start: self.start + range.start,
            end: self.start + range.end,
        }
    }

    /// The bytes not yet taken.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether every byte has been taken.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Marks the first `n` bytes as taken. Panics if fewer remain.
    pub fn advance(&mut self, n: usize) {
        assert!(n <= self.len(), "chunk cursor exceeds its remaining bytes");
        self.start += n;
    }

    /// Splits off the first `n` bytes without allocating. Both pieces keep
    /// the same backing and what pays for it until their last owner
    /// releases it. Panics if fewer remain.
    pub fn split_to(&mut self, n: usize) -> Chunk {
        let prefix = self.slice(0..n);
        self.start += n;
        prefix
    }

    /// The bytes not yet taken, as a vector. Reuses the allocation when
    /// this chunk alone owns unpooled, uncharged backing that holds exactly
    /// these bytes and nothing else, and copies them otherwise. Any charge
    /// goes back when the chunk's backing is dropped, and a pooled backing
    /// goes back to its pool: the vector carries neither.
    pub fn into_vec(mut self) -> Vec<u8> {
        let free = self.backing().reservation.is_none() && self.backing().held.is_none();
        if self.whole() && free {
            let backing = self.backing.take().expect("a chunk holds its backing");
            return match Arc::try_unwrap(backing) {
                Ok(backing) => backing.bytes,
                Err(backing) => backing.bytes[self.start..self.end].to_vec(),
            };
        }
        self.to_vec()
    }

    /// The charge that pays for the backing. Pieces of one backing name
    /// the same charge; their charged values must not be added together.
    pub fn charged(&self) -> usize {
        self.backing()
            .reservation
            .as_ref()
            .map_or(0, |reservation| reservation.charge().bytes())
    }

    /// What the backing's allocation holds, written or not: the memory the
    /// chunk keeps alive, whoever pays for it.
    pub fn capacity(&self) -> usize {
        self.backing().bytes.capacity()
    }

    /// Whether the two are pieces of one backing.
    pub fn shares(&self, other: &Chunk) -> bool {
        match (&self.backing, &other.backing) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

#[cfg(test)]
impl Chunk {
    /// The backing's address, to tell pieces of one backing from another's.
    pub(crate) fn backing_id(&self) -> usize {
        self.backing.as_ref().map_or(0, |b| Arc::as_ptr(b).addr())
    }

    /// The budget that pays for the backing, if one does.
    pub(crate) fn payer(&self) -> Option<Budget> {
        let reservation = self.backing().reservation.as_ref()?;
        Some(reservation.charge().budget().clone())
    }

    /// Whether the backing goes back to a pool.
    pub(crate) fn is_pooled(&self) -> bool {
        self.pooled_backing()
    }
}

impl Clone for Chunk {
    /// Another piece of the same backing and the same bytes: no copy.
    fn clone(&self) -> Chunk {
        Chunk {
            backing: self.backing.clone(),
            start: self.start,
            end: self.end,
        }
    }
}

impl Drop for Chunk {
    /// The last piece of a pooled backing gives it back to its pool, which
    /// keeps it or frees it; any other piece only lets go of its share.
    fn drop(&mut self) {
        let Some(mut backing) = self.backing.take() else {
            return;
        };
        // Only the sole holder can see a count of one: no one else holds
        // the backing to clone it behind this check.
        if Arc::get_mut(&mut backing).is_none() {
            return;
        }
        if let Some(pool) = backing.pool.as_ref().and_then(Weak::upgrade) {
            pool.recycle(backing);
        }
    }
}

impl Deref for Chunk {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.backing().bytes[self.start..self.end]
    }
}

impl AsRef<[u8]> for Chunk {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl PartialEq for Chunk {
    /// Equal bytes, wherever they are and whatever pays for them.
    fn eq(&self, other: &Chunk) -> bool {
        **self == **other
    }
}

impl Eq for Chunk {}

impl std::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chunk")
            .field("len", &self.len())
            .field("charged", &self.charged())
            .finish()
    }
}
