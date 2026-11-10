//! Containers whose memory is paid for.
//!
//! Each holds its [`Charge`] inside, and its only ways to grow charge the
//! growth first: the budget has room for an allocation before it is made,
//! and a refusal allocates nothing and changes nothing. Giving memory back
//! cannot fail, so it returns nothing. At every moment outside their own
//! methods, a container's charge is what its allocation holds: the
//! capacity, counted in bytes, never its length. Items that own heap of
//! their own, such as a [`Chunk`], carry their own charge; a queue pays
//! only for its places.

use std::collections::{BTreeMap, VecDeque};
use std::ops::{Deref, DerefMut, RangeBounds, RangeInclusive};

use super::{Budget, Charge, Chunk, WriteFailure};

/// Bytes whose allocation is paid for: its capacity is its charge.
///
/// They are made from a charge, never paired with one afterwards: no
/// constructor takes a vector someone else allocated.
pub struct ChargedBytes {
    bytes: Vec<u8>,
    charge: Charge,
}

impl Charge {
    /// The bytes this charge pays for: an empty allocation of exactly
    /// [`bytes`](Self::bytes).
    pub fn into_bytes(self) -> ChargedBytes {
        ChargedBytes {
            bytes: Vec::with_capacity(self.bytes()),
            charge: self,
        }
    }

    /// The places of a queue this charge pays for: as many as it holds in
    /// whole items, and no more, since the queue holds what it was paid
    /// for. What the charge holds past the last whole place goes back.
    pub fn into_deque<T>(mut self) -> ChargedDeque<T> {
        let places = self.bytes().checked_div(size_of::<T>()).unwrap_or(0);
        self.shrink_to(places * size_of::<T>());
        ChargedDeque {
            items: VecDeque::with_capacity(places),
            charge: self,
            most: places,
        }
    }

    /// The whole vector places this charge pays for. Partial places are
    /// released and the vector cannot grow beyond the reserved places.
    pub fn into_vec<T>(mut self) -> ChargedVec<T> {
        let places = self.bytes().checked_div(size_of::<T>()).unwrap_or(0);
        self.shrink_to(places * size_of::<T>());
        ChargedVec {
            items: Vec::with_capacity(places),
            charge: self,
            most: places,
        }
    }
}

impl ChargedBytes {
    /// No bytes and no room yet, which costs nothing, counted against
    /// `budget` as it grows.
    pub fn new(budget: &Budget) -> ChargedBytes {
        Charge::nothing(budget).into_bytes()
    }

    /// Room for `capacity` bytes, charged before it is allocated. `None`,
    /// with nothing allocated, if the budget has no room.
    pub fn with_capacity(budget: &Budget, capacity: usize) -> Option<ChargedBytes> {
        Some(budget.charge(capacity)?.into_bytes())
    }

    /// Room for as much of `want` as the budget has, charged before it is
    /// allocated. `None` if not even the start of `want` fits.
    pub fn with_capacity_within(
        budget: &Budget,
        want: RangeInclusive<usize>,
    ) -> Option<ChargedBytes> {
        Some(budget.charge_within(want)?.into_bytes())
    }

    /// A copy of `bytes` in an allocation of exactly their size, charged
    /// before it is made.
    pub fn copy_of(budget: &Budget, bytes: &[u8]) -> Option<ChargedBytes> {
        let mut copy = Self::with_capacity(budget, bytes.len())?;
        copy.bytes.extend_from_slice(bytes);
        Some(copy)
    }

    /// How many bytes the allocation holds, written or not.
    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// How many more bytes fit without growing.
    pub fn room(&self) -> usize {
        self.bytes.capacity() - self.bytes.len()
    }

    /// The bytes charged, which is the capacity.
    pub fn charged(&self) -> usize {
        self.charge.bytes()
    }

    /// Appends `bytes` if they fit in the room left. Otherwise writes none
    /// and returns how many bytes past the capacity they would reach.
    /// Never reallocates.
    pub fn extend_within(&mut self, bytes: &[u8]) -> Result<(), usize> {
        let room = self.room();
        if bytes.len() > room {
            return Err(bytes.len() - room);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Grows the capacity to `capacity`, charging the growth before
    /// reallocating. Refuses, changing nothing, if the budget has no room.
    /// A capacity already reached is kept.
    #[must_use = "a refused growth leaves no room for what was to be written"]
    pub fn grow_to(&mut self, capacity: usize) -> bool {
        if capacity <= self.bytes.capacity() {
            return true;
        }
        if !self.charge.grow_to(capacity) {
            return false;
        }
        self.bytes.reserve_exact(capacity - self.bytes.len());
        true
    }

    /// Gives back the capacity past the length.
    pub fn trim(&mut self) {
        self.bytes.shrink_to_fit();
        self.charge.shrink_to(self.bytes.capacity());
    }

    /// Keeps the first `len` bytes. The capacity stays.
    pub fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len);
    }

    /// Forgets every byte. The capacity stays.
    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    /// Runs `write` with the bytes as a vector, for writers that take one,
    /// such as [`Wire::write`](fictionet::stdlib::codec::Wire::write). A
    /// writer that grows the vector past its capacity has its write undone:
    /// the bytes are cut back to what they were and the capacity to what is
    /// paid for, and the result is [`WriteFailure::Bound`], a writer that
    /// needed more room than it was given, found here rather than paid
    /// for. A writer's own failure is [`WriteFailure::Value`] and leaves
    /// what it wrote.
    pub fn fill<T, E>(
        &mut self,
        write: impl FnOnce(&mut Vec<u8>) -> Result<T, E>,
    ) -> Result<T, WriteFailure<E>> {
        let (len, capacity) = (self.bytes.len(), self.bytes.capacity());
        let written = write(&mut self.bytes);
        if self.bytes.capacity() > capacity {
            self.bytes.truncate(len);
            self.bytes.shrink_to(capacity);
            return Err(WriteFailure::Bound);
        }
        // A writer may give capacity back; then less is paid for.
        self.charge.shrink_to(self.bytes.capacity());
        written.map_err(WriteFailure::Value)
    }

    /// The bytes as a chunk, which carries their charge.
    pub fn into_chunk(self) -> Chunk {
        Chunk::from_bytes(self)
    }

    /// The vector and the charge that pays for it, for an owner that keeps
    /// them together itself, such as [`Owned`].
    pub fn into_parts(self) -> (Vec<u8>, Charge) {
        (self.bytes, self.charge)
    }
}

impl Deref for ChargedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

/// The bytes written can change in place, as a read into them does; their
/// length and capacity cannot.
impl DerefMut for ChargedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl std::fmt::Debug for ChargedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChargedBytes")
            .field("len", &self.bytes.len())
            .field("capacity", &self.bytes.capacity())
            .finish()
    }
}

/// Writes up to the capacity and no further: a write that does not fit
/// takes what fits, and a full buffer takes nothing.
impl std::io::Write for ChargedBytes {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.room());
        self.bytes.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        let mut total = 0;
        for buf in bufs {
            let n = self.write(buf)?;
            total += n;
            if n < buf.len() {
                break;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The places an empty queue or vector grows to first when the budget has
/// room. An owner that gives places back after a burst keeps this many to
/// stay where its first push left it.
pub const FIRST_PLACES: usize = 4;

/// The places a queue grows to when it is full and the budget has room:
/// twice as many, at least [`FIRST_PLACES`], at most `most`.
fn more_places(places: usize, most: usize) -> usize {
    places.saturating_mul(2).max(FIRST_PLACES).min(most)
}

/// Charges the places a container of `places` places grows by to hold
/// `wanted` items of `size` bytes, at most `most`: up to
/// [`more_places`] or `wanted` if that is more, and as few as `wanted`
/// when the budget has room for no more. Returns the places to add, or
/// `None`, changing nothing, when not even `wanted` fits or `wanted`
/// passes `most`.
pub(super) fn charge_places(
    charge: &mut Charge,
    places: usize,
    wanted: usize,
    most: usize,
    size: usize,
) -> Option<usize> {
    if wanted <= places || wanted > most {
        return None;
    }
    let up_to = more_places(places, most).max(wanted);
    charge.grow_by_units(wanted - places..=up_to - places, size)
}

/// A queue whose places are paid for: what it is charged is its places
/// times the size of an item. At most `most` items.
///
/// A full queue grows to twice its places, at least four, when the budget
/// has room for that, and by as many places as there is room for when it
/// has not; only when not one more place fits does a push refuse.
pub struct ChargedDeque<T> {
    items: VecDeque<T>,
    charge: Charge,
    most: usize,
}

/// One more place in a [`ChargedDeque`], made and paid for before the
/// item that goes in it exists: for an item that cannot be handed back
/// once it is taken from where it was, as work a layer hands over.
#[must_use = "a place that is not filled stays paid for, empty"]
pub struct Place<'a, T> {
    deque: &'a mut ChargedDeque<T>,
}

impl<T> Place<'_, T> {
    /// Puts `item` last, in the place made for it. Cannot fail.
    pub fn push_back(self, item: T) {
        self.deque.items.push_back(item);
    }
}

impl<T> ChargedDeque<T> {
    /// An empty queue with no places yet, which costs nothing, for at most
    /// `most` items.
    pub fn new(budget: &Budget, most: usize) -> ChargedDeque<T> {
        ChargedDeque {
            items: VecDeque::new(),
            charge: Charge::nothing(budget),
            most,
        }
    }

    /// An empty queue with `places` places charged before they are
    /// allocated, up to `most`, for at most `most` items.
    pub fn with_places(budget: &Budget, places: usize, most: usize) -> Option<ChargedDeque<T>> {
        let places = places.min(most);
        let charge = budget.charge(places.checked_mul(size_of::<T>())?)?;
        Some(ChargedDeque {
            items: VecDeque::with_capacity(places),
            charge,
            most,
        })
    }

    /// Makes places for `additional` more items, so that many pushes
    /// cannot refuse, charging new places before they are allocated. It
    /// grows as a push does: by doubling, or to exactly what is asked if
    /// that is more, when the budget has room, and by as few as are asked
    /// when it has not. Refuses, changing nothing, if not even that fits
    /// the budget or the items would pass `most`.
    #[must_use = "a refused reservation leaves no places for the items"]
    pub fn reserve(&mut self, additional: usize) -> bool {
        let len = self.items.len();
        let places = self.items.capacity();
        let Some(wanted) = len.checked_add(additional).filter(|&n| n <= self.most) else {
            return false;
        };
        if wanted <= places {
            return true;
        }
        let Some(more) = charge_places(&mut self.charge, places, wanted, self.most, size_of::<T>())
        else {
            return false;
        };
        self.items.reserve_exact(places + more - len);
        true
    }

    /// A place for one more item, made and paid for first: `None`,
    /// changing nothing, if the growth does not fit the budget or the
    /// queue holds `most` items. Filling it cannot fail.
    pub fn place(&mut self) -> Option<Place<'_, T>> {
        self.reserve(1).then_some(Place { deque: self })
    }

    /// Holds at most `most` items from now on. Places past it go back as
    /// far as the items held allow.
    pub fn set_most(&mut self, most: usize) {
        self.most = most;
        if self.items.capacity() > most {
            self.shrink_to(most);
        }
    }

    /// Puts `item` last, growing first if the queue is full. Hands `item`
    /// back, changing nothing, if the growth does not fit the budget or
    /// the queue holds `most` items.
    pub fn push_back(&mut self, item: T) -> Result<(), T> {
        if !self.reserve(1) {
            return Err(item);
        }
        self.items.push_back(item);
        Ok(())
    }

    /// Puts `item` first, as [`push_back`](Self::push_back) puts it last.
    pub fn push_front(&mut self, item: T) -> Result<(), T> {
        if !self.reserve(1) {
            return Err(item);
        }
        self.items.push_front(item);
        Ok(())
    }

    /// Takes the first item. Its place stays paid for.
    pub fn pop_front(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    /// Takes the last item. Its place stays paid for.
    pub fn pop_back(&mut self) -> Option<T> {
        self.items.pop_back()
    }

    /// The first item.
    pub fn front(&self) -> Option<&T> {
        self.items.front()
    }

    /// The first item, to change.
    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.items.front_mut()
    }

    /// The item at `index`, counting from the first.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.items.get(index)
    }

    /// The item at `index`, to change.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.items.get_mut(index)
    }

    /// Takes the item at `index`, counting from the first. Its place stays
    /// paid for.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        self.items.remove(index)
    }

    /// Keeps the first `len` items. Their places stay paid for.
    pub fn truncate(&mut self, len: usize) {
        self.items.truncate(len);
    }

    /// Keeps the items `keep` accepts, in order. Their places stay paid
    /// for.
    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.items.retain(keep);
    }

    /// Forgets every item. Their places stay paid for.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// How many items it holds.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The items, first to last.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    /// The items, first to last, to change in place.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.items.iter_mut()
    }

    /// Takes the items in `range`. Their places stay paid for.
    pub fn drain(&mut self, range: impl RangeBounds<usize>) -> impl Iterator<Item = T> {
        self.items.drain(range)
    }

    /// Gives back places down to `keep`, or to the items held if there are
    /// more. How many to keep is the owner's choice.
    pub fn shrink_to(&mut self, keep: usize) {
        self.items.shrink_to(keep.max(self.items.len()));
        self.charge
            .shrink_to(self.items.capacity() * size_of::<T>());
    }

    /// The places allocated, filled or not.
    pub fn places(&self) -> usize {
        self.items.capacity()
    }

    /// The most items it holds.
    pub fn most(&self) -> usize {
        self.most
    }

    /// The bytes charged: the places times the size of an item.
    pub fn charged(&self) -> usize {
        self.charge.bytes()
    }
}

impl<T> std::fmt::Debug for ChargedDeque<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChargedDeque")
            .field("len", &self.items.len())
            .field("places", &self.items.capacity())
            .finish()
    }
}

/// A vector whose places are paid for, as [`ChargedDeque`] is a queue.
pub struct ChargedVec<T> {
    items: Vec<T>,
    charge: Charge,
    most: usize,
}

impl<T> ChargedVec<T> {
    /// An empty vector with no places yet, which costs nothing, for at
    /// most `most` items.
    pub fn new(budget: &Budget, most: usize) -> ChargedVec<T> {
        ChargedVec {
            items: Vec::new(),
            charge: Charge::nothing(budget),
            most,
        }
    }

    /// An empty vector with `places` places charged before they are
    /// allocated, up to `most`, for at most `most` items.
    pub fn with_places(budget: &Budget, places: usize, most: usize) -> Option<ChargedVec<T>> {
        let places = places.min(most);
        let charge = budget.charge(places.checked_mul(size_of::<T>())?)?;
        Some(ChargedVec {
            items: Vec::with_capacity(places),
            charge,
            most,
        })
    }

    /// Puts `item` last, growing first if the vector is full. Hands `item`
    /// back, changing nothing, if the growth does not fit the budget or
    /// the vector holds `most` items.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        let len = self.items.len();
        if len >= self.most {
            return Err(item);
        }
        if len == self.items.capacity() {
            let Some(more) =
                charge_places(&mut self.charge, len, len + 1, self.most, size_of::<T>())
            else {
                return Err(item);
            };
            self.items.reserve_exact(more);
        }
        self.items.push(item);
        Ok(())
    }

    /// Takes the last item. Its place stays paid for.
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }

    /// Keeps the items `keep` accepts, in order. Their places stay paid
    /// for.
    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.items.retain(keep);
    }

    /// Forgets every item. Their places stay paid for.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Takes the items in `range`. Their places stay paid for.
    pub fn drain(&mut self, range: impl RangeBounds<usize>) -> impl Iterator<Item = T> {
        self.items.drain(range)
    }

    /// Gives back places down to `keep`, or to the items held if there are
    /// more.
    pub fn shrink_to(&mut self, keep: usize) {
        self.items.shrink_to(keep.max(self.items.len()));
        self.charge
            .shrink_to(self.items.capacity() * size_of::<T>());
    }

    /// The places allocated, filled or not.
    pub fn places(&self) -> usize {
        self.items.capacity()
    }

    /// The bytes charged: the places times the size of an item.
    pub fn charged(&self) -> usize {
        self.charge.bytes()
    }
}

impl<T> Deref for ChargedVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.items
    }
}

/// Items can be changed in place; a slice cannot grow.
impl<T> DerefMut for ChargedVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.items
    }
}

impl<T> std::fmt::Debug for ChargedVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChargedVec")
            .field("len", &self.items.len())
            .field("places", &self.items.capacity())
            .finish()
    }
}

/// A map of at most `limit` entries, paid for once when it is made, so
/// nothing it holds grows its charge. Its nodes are not visible, so the
/// charge is what `limit` entries may take at most
/// ([`BoundedMap::storage`]). Ordered, so iteration is the same in every
/// run.
pub struct BoundedMap<K, V> {
    map: BTreeMap<K, V>,
    limit: usize,
    charge: Charge,
}

impl<K: Ord, V> BoundedMap<K, V> {
    /// The largest node of std's B-tree map, an inner one: eleven entries,
    /// the parent link and two counts, twelve child links, and padding to
    /// the alignment before the keys, the values, the links and the end.
    const NODE: usize = 11 * size_of::<(K, V)>()
        + 16 * size_of::<usize>()
        + 4 * if align_of::<(K, V)>() > size_of::<usize>() {
            align_of::<(K, V)>()
        } else {
            size_of::<usize>()
        };

    /// The most `limit` entries may take. Every node but the root holds at
    /// least five entries, so `limit` entries use at most `limit / 5 + 1`
    /// nodes. `None` if that overflows.
    pub fn storage(limit: usize) -> Option<usize> {
        if limit == 0 {
            return Some(0);
        }
        (limit / 5 + 1).checked_mul(Self::NODE)
    }

    /// An empty map for at most `limit` entries, charged for all of them
    /// now. `None` if the budget has no room.
    pub fn new(budget: &Budget, limit: usize) -> Option<BoundedMap<K, V>> {
        let charge = budget.charge(Self::storage(limit)?)?;
        Some(BoundedMap {
            map: BTreeMap::new(),
            limit,
            charge,
        })
    }

    /// Puts `value` under `key`, handing back what was there. A new key
    /// past the limit is refused, handing both back.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        if self.map.len() >= self.limit && !self.map.contains_key(&key) {
            return Err((key, value));
        }
        Ok(self.map.insert(key, value))
    }

    /// The value under `key`.
    pub fn get<Q: Ord + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
    {
        self.map.get(key)
    }

    /// The value under `key`, to change.
    pub fn get_mut<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: std::borrow::Borrow<Q>,
    {
        self.map.get_mut(key)
    }

    /// The key stored for `key`, with its value.
    pub fn get_key_value<Q: Ord + ?Sized>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: std::borrow::Borrow<Q>,
    {
        self.map.get_key_value(key)
    }

    /// Takes the value under `key`.
    pub fn remove<Q: Ord + ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
    {
        self.map.remove(key)
    }

    /// The entry with the least key.
    pub fn first_key_value(&self) -> Option<(&K, &V)> {
        self.map.first_key_value()
    }

    /// Takes the entry with the least key.
    pub fn pop_first(&mut self) -> Option<(K, V)> {
        self.map.pop_first()
    }

    /// The entries whose keys are in `range`, in key order.
    pub fn range<Q, R>(&self, range: R) -> std::collections::btree_map::Range<'_, K, V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
        R: RangeBounds<Q>,
    {
        self.map.range(range)
    }

    /// Takes every entry. The charge stays, paying for the entries the
    /// map may hold again.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// How many entries it holds.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The most entries it holds.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The entries, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }

    /// The bytes charged, all of them when the map was made.
    pub fn charged(&self) -> usize {
        self.charge.bytes()
    }
}

impl<K, V> std::fmt::Debug for BoundedMap<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedMap")
            .field("len", &self.map.len())
            .field("limit", &self.limit)
            .finish()
    }
}

/// An owned value and the reservation that follows its allocation.
#[derive(Debug)]
pub struct Owned<T> {
    value: T,
    charge: Charge,
}

impl<T> Owned<T> {
    /// Attaches a reservation acquired before constructing the value.
    pub fn new(value: T, charge: Charge) -> Self {
        Self { value, charge }
    }

    /// Transfers both the value and its reservation to another owner.
    pub fn into_parts(self) -> (T, Charge) {
        (self.value, self.charge)
    }

    /// Reserved allocation bytes.
    pub fn charged(&self) -> usize {
        self.charge.bytes()
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Owned<T> {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl<T> Deref for Owned<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    //! Random sequences of calls on the charged containers, charges and
    //! chunks of two budgets, each checked against a model of what is held:
    //!
    //! - Cover: everything is charged what its allocation holds.
    //! - Sum: a budget's count is the sum of what it pays for, within its
    //!   limit.
    //! - Order: a refused call changes nothing, allocations included.
    //! - Return: a drop or a shrink gives back what Cover says was held.
    //! - Move: moving within one budget never raises its count; across
    //!   budgets the target is charged at most what moved.
    //! - Wake: the first release after a refusal that leaves room for the
    //!   least refused charge wakes each runner that asked in between,
    //!   once; a release that leaves less wakes none; and a runner that
    //!   asks after memory was freed, or while there is room, is woken at
    //!   once.

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    use fictionet::stdlib::layer::{Refusals, Waiter};
    use fictionet::{Entropy, Seed, SeededEntropy};

    /// A runner's waker that counts its wakes.
    #[derive(Default)]
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct Runner {
        count: Arc<Count>,
        waiter: Waiter,
        /// The wakes the model says it has had.
        woken: usize,
    }

    /// What the model knows of one budget's waiting runners.
    #[derive(Default)]
    struct Waits {
        refusals: u64,
        /// The least a charge refused since the last wake needed; 0 if
        /// none was refused.
        wanted: usize,
        woken_at: u64,
        waiting: Vec<usize>,
    }

    enum Item {
        Bytes(ChargedBytes),
        Deque(ChargedDeque<u64>),
        List(ChargedVec<u32>),
        Map(BoundedMap<u16, u64>),
        Charge(Charge),
        /// A piece of a chunk, and whether it is all of its backing.
        Chunk(Chunk, bool),
    }

    impl Item {
        fn charged(&self) -> usize {
            match self {
                Item::Bytes(bytes) => bytes.charged(),
                Item::Deque(deque) => deque.charged(),
                Item::List(list) => list.charged(),
                Item::Map(map) => map.charged(),
                Item::Charge(charge) => charge.bytes(),
                Item::Chunk(chunk, _) => chunk.charged(),
            }
        }

        /// What its allocation holds, in bytes.
        fn holds(&self) -> usize {
            match self {
                Item::Bytes(bytes) => bytes.capacity(),
                Item::Deque(deque) => deque.places() * size_of::<u64>(),
                Item::List(list) => list.places() * size_of::<u32>(),
                Item::Map(map) => BoundedMap::<u16, u64>::storage(map.limit()).unwrap(),
                Item::Charge(charge) => charge.bytes(),
                Item::Chunk(chunk, _) => chunk.backing_capacity(),
            }
        }

        /// Everything a refused call must leave as it was.
        fn shape(&self) -> (usize, usize, usize, usize) {
            match self {
                Item::Bytes(b) => (b.charged(), b.capacity(), b.len(), b.as_ptr() as usize),
                Item::Deque(d) => (d.charged(), d.places(), d.len(), 0),
                Item::List(l) => (l.charged(), l.places(), l.len(), l.as_ptr() as usize),
                Item::Map(m) => (m.charged(), m.limit(), m.len(), 0),
                Item::Charge(c) => (c.bytes(), 0, 0, 0),
                Item::Chunk(c, _) => (
                    c.charged(),
                    c.backing_capacity(),
                    c.len(),
                    c.as_ptr() as usize,
                ),
            }
        }
    }

    /// Something held, and the budget that pays for it.
    struct Held {
        item: Item,
        payer: usize,
    }

    /// What one call did that the counts alone do not show.
    #[derive(Default)]
    struct Acted {
        /// The call refused, or found nothing to act on.
        refused: bool,
        /// The budget a refused charge was on, and the bytes it needed.
        need: Option<(usize, usize)>,
        /// The budget a charge was given back to although the call charged
        /// more on it overall: a chunk paid for whole, then trimmed.
        trimmed: Option<usize>,
    }

    /// How often the sequences reached the paths worth reaching, so that a
    /// run that never refuses or wakes cannot pass unnoticed.
    #[derive(Default)]
    struct Reached {
        refusals: usize,
        /// Releases after a refusal that left too little room for it.
        released_too_little: usize,
        woken_after_waiting: usize,
        woken_at_once: usize,
        moved_in_place: usize,
        moved_by_copy: usize,
        overruns: usize,
    }

    struct Model {
        rng: SeededEntropy,
        budgets: [Budget; 2],
        held: Vec<Held>,
        waits: [Waits; 2],
        runners: Vec<Runner>,
        /// A mark a runner took before an earlier round, to ask with later.
        stale: [Option<(Refusals, u64)>; 2],
        reached: Reached,
    }

    impl Model {
        fn new(seed: u64) -> Model {
            let rng = SeededEntropy::new(Seed::from_u64(seed));
            let limit = |rng: &SeededEntropy| 64 + rng.random_below(448) as usize;
            let budgets = [Budget::new(limit(&rng)), Budget::new(limit(&rng))];
            let runners = (0..4)
                .map(|_| {
                    let count = Arc::new(Count::default());
                    Runner {
                        waiter: Waiter::new(Waker::from(count.clone())),
                        count,
                        woken: 0,
                    }
                })
                .collect();
            Model {
                rng,
                budgets,
                held: Vec::new(),
                waits: Default::default(),
                runners,
                stale: [None, None],
                reached: Reached::default(),
            }
        }

        fn below(&self, n: usize) -> usize {
            self.rng.random_below(n as u64) as usize
        }

        fn room(&self, budget: usize) -> usize {
            self.budgets[budget].limit() - self.budgets[budget].used()
        }

        fn bytes(&self, n: usize) -> Vec<u8> {
            let mut bytes = vec![0; n];
            self.rng.fill_random(&mut bytes);
            bytes
        }

        /// A held item that `wanted` picks, at random.
        fn pick(&self, wanted: impl Fn(&Item) -> bool) -> Option<usize> {
            let found: Vec<usize> = (0..self.held.len())
                .filter(|&i| wanted(&self.held[i].item))
                .collect();
            (!found.is_empty()).then(|| found[self.below(found.len())])
        }

        /// Whether another held piece shares the backing of chunk `at`.
        fn shared(&self, at: usize) -> bool {
            let Item::Chunk(chunk, _) = &self.held[at].item else {
                return false;
            };
            self.held.iter().enumerate().any(|(i, held)| {
                i != at
                    && matches!(&held.item, Item::Chunk(other, _) if other.shares_backing(chunk))
            })
        }

        fn add(&mut self, item: Item, payer: usize) {
            self.held.push(Held { item, payer });
        }

        fn act(&mut self) -> Acted {
            let budget = self.below(2);
            let refused = |done: bool| Acted {
                refused: !done,
                ..Acted::default()
            };
            // A call on budget `payer` that needed `need` bytes of it.
            let charging = |done: bool, payer: usize, need: usize| Acted {
                refused: !done,
                need: (!done).then_some((payer, need)),
                ..Acted::default()
            };
            match self.below(23) {
                0 | 1 => {
                    let n = self.below(96);
                    let fits = n <= self.room(budget);
                    let made = ChargedBytes::with_capacity(&self.budgets[budget], n);
                    assert_eq!(made.is_some(), fits);
                    let done = made.is_some();
                    if let Some(bytes) = made {
                        assert_eq!(bytes.capacity(), n);
                        self.add(Item::Bytes(bytes), budget);
                    }
                    charging(done, budget, n)
                }
                2 => {
                    let start = self.below(64);
                    let end = start + self.below(64);
                    let room = self.room(budget);
                    let made =
                        ChargedBytes::with_capacity_within(&self.budgets[budget], start..=end);
                    assert_eq!(made.is_some(), start <= room);
                    let done = made.is_some();
                    if let Some(bytes) = made {
                        assert_eq!(bytes.capacity(), end.min(room));
                        self.add(Item::Bytes(bytes), budget);
                    }
                    charging(done, budget, start)
                }
                3 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Bytes(_))) else {
                        return refused(false);
                    };
                    let payer = self.held[at].payer;
                    let to = self.below(128);
                    let room = self.room(payer);
                    let Item::Bytes(bytes) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let more = to.saturating_sub(bytes.capacity());
                    let fits = more <= room;
                    let grew = bytes.grow_to(to);
                    assert_eq!(grew, fits);
                    if grew {
                        assert!(bytes.capacity() >= to);
                    }
                    charging(grew, payer, more)
                }
                4 | 5 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Bytes(_))) else {
                        return refused(false);
                    };
                    let more = self.bytes(self.below(48));
                    let Item::Bytes(bytes) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let (len, room) = (bytes.len(), bytes.room());
                    let written = bytes.extend_within(&more);
                    match written {
                        Ok(()) => assert_eq!(&bytes[len..], &more[..]),
                        Err(over) => assert_eq!(over, more.len() - room),
                    }
                    refused(written.is_ok())
                }
                6 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Bytes(_))) else {
                        return refused(false);
                    };
                    let more = self.bytes(self.below(48));
                    let used = self.budgets[self.held[at].payer].used();
                    let Item::Bytes(bytes) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let fits = more.len() <= bytes.room();
                    let (was, capacity) = (bytes.to_vec(), bytes.capacity());
                    let filled = bytes.fill(|out| {
                        out.extend_from_slice(&more);
                        Ok::<_, ()>(())
                    });
                    assert_eq!(filled.is_ok(), fits);
                    if !fits {
                        // Undone, though not without an allocation: the
                        // writer's growth is found, then given back.
                        assert!(matches!(filled, Err(WriteFailure::Bound)));
                        assert_eq!((&bytes[..], bytes.capacity()), (&was[..], capacity));
                        assert_eq!(bytes.charged(), capacity);
                        assert_eq!(self.budgets[self.held[at].payer].used(), used);
                        self.reached.overruns += 1;
                    }
                    refused(true)
                }
                7 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Bytes(_))) else {
                        return refused(false);
                    };
                    let keep = self.below(64);
                    let Item::Bytes(bytes) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let charged = bytes.charged();
                    if keep.is_multiple_of(2) {
                        bytes.truncate(keep);
                    } else {
                        bytes.trim();
                        assert_eq!(bytes.capacity(), bytes.len());
                    }
                    assert!(bytes.charged() <= charged);
                    refused(true)
                }
                8 | 9 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Deque(_))) else {
                        let most = 1 + self.below(12);
                        let places = self.below(2 * most);
                        let fits = places.min(most) * size_of::<u64>() <= self.room(budget);
                        let made = ChargedDeque::with_places(&self.budgets[budget], places, most);
                        assert_eq!(made.is_some(), fits);
                        let done = made.is_some();
                        if let Some(deque) = made {
                            self.add(Item::Deque(deque), budget);
                        }
                        return charging(done, budget, places.min(most) * size_of::<u64>());
                    };
                    let payer = self.held[at].payer;
                    let room = self.room(payer);
                    let item = self.rng.random_u64();
                    let front = self.below(2) == 0;
                    let Item::Deque(deque) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let (len, places) = (deque.len(), deque.places());
                    let full = len == places;
                    let fits = len < deque.most && (!full || size_of::<u64>() <= room);
                    // A full queue doubles if there is room, else takes
                    // the places there is room for.
                    let grown =
                        more_places(places, deque.most).min(places + room / size_of::<u64>());
                    let pushed = if front {
                        deque.push_front(item)
                    } else {
                        deque.push_back(item)
                    };
                    assert_eq!(pushed.is_ok(), fits);
                    match pushed {
                        Ok(()) => {
                            assert_eq!(deque.places(), if full { grown } else { places });
                            assert_eq!(deque.len(), len + 1);
                            let at = if front {
                                deque.iter().next()
                            } else {
                                deque.iter().last()
                            };
                            assert_eq!(at, Some(&item));
                        }
                        Err(back) => assert_eq!(back, item),
                    }
                    charging(pushed.is_ok(), payer, size_of::<u64>())
                }
                10 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Deque(_))) else {
                        return refused(false);
                    };
                    let keep = self.below(16);
                    let Item::Deque(deque) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    match keep % 4 {
                        0 => {
                            deque.pop_front();
                        }
                        3 => {
                            let len = deque.len();
                            deque.retain(|item| item % 2 == 0);
                            assert!(deque.len() <= len);
                            assert!(deque.iter().all(|item| item % 2 == 0));
                        }
                        1 => {
                            let half = deque.len() / 2;
                            assert_eq!(deque.drain(..half).count(), half);
                        }
                        _ => {
                            let places = deque.places();
                            deque.shrink_to(keep);
                            assert_eq!(deque.places(), keep.max(deque.len()).min(places));
                        }
                    }
                    refused(true)
                }
                11 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::List(_))) else {
                        let most = 1 + self.below(12);
                        let made = ChargedVec::with_places(&self.budgets[budget], 0, most);
                        let done = made.is_some();
                        if let Some(list) = made {
                            self.add(Item::List(list), budget);
                        }
                        return refused(done);
                    };
                    let payer = self.held[at].payer;
                    let room = self.room(payer);
                    let item = self.rng.random_u64() as u32;
                    let shrink = self.below(4) == 0;
                    let Item::List(list) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    if shrink {
                        match item % 3 {
                            0 => drop(list.pop()),
                            1 => list.retain(|item| item % 2 == 1),
                            _ => list.clear(),
                        }
                        let places = list.places();
                        assert_eq!(list.charged(), places * size_of::<u32>(), "still paid for");
                        list.shrink_to(0);
                        assert_eq!(list.places(), list.len());
                        return refused(true);
                    }
                    let (len, places) = (list.len(), list.places());
                    let full = len == places;
                    let fits = len < list.most && (!full || size_of::<u32>() <= room);
                    let grown =
                        more_places(places, list.most).min(places + room / size_of::<u32>());
                    let pushed = list.push(item);
                    assert_eq!(pushed.is_ok(), fits);
                    if pushed.is_ok() {
                        assert_eq!(list.places(), if full { grown } else { places });
                        assert_eq!(list.last(), Some(&item));
                    }
                    charging(pushed.is_ok(), payer, size_of::<u32>())
                }
                12 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Map(_))) else {
                        let limit = self.below(6);
                        let fits =
                            BoundedMap::<u16, u64>::storage(limit).unwrap() <= self.room(budget);
                        let made = BoundedMap::new(&self.budgets[budget], limit);
                        assert_eq!(made.is_some(), fits);
                        let done = made.is_some();
                        if let Some(map) = made {
                            self.add(Item::Map(map), budget);
                        }
                        return charging(
                            done,
                            budget,
                            BoundedMap::<u16, u64>::storage(limit).unwrap(),
                        );
                    };
                    let key = self.below(8) as u16;
                    let value = self.rng.random_u64();
                    let Item::Map(map) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let fits = map.len() < map.limit() || map.get(&key).is_some();
                    let inserted = map.insert(key, value);
                    assert_eq!(inserted.is_ok(), fits);
                    if inserted.is_ok() {
                        assert_eq!(map.get(&key), Some(&value));
                    }
                    assert!(map.len() <= map.limit());
                    refused(inserted.is_ok())
                }
                13 => {
                    let n = self.below(64);
                    let fits = n <= self.room(budget);
                    let made = self.budgets[budget].charge(n);
                    assert_eq!(made.is_some(), fits);
                    let done = made.is_some();
                    if let Some(charge) = made {
                        self.add(Item::Charge(charge), budget);
                    }
                    charging(done, budget, n)
                }
                14 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Charge(_))) else {
                        return refused(false);
                    };
                    let payer = self.held[at].payer;
                    let room = self.room(payer);
                    let to = self.below(96);
                    let Item::Charge(charge) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let was = charge.bytes();
                    if self.rng.random_below(2) == 0 {
                        charge.shrink_to(to);
                        assert_eq!(charge.bytes(), was.min(to));
                        return refused(true);
                    }
                    let grew = charge.grow_to(to);
                    assert_eq!(grew, to <= was || to - was <= room);
                    assert_eq!(charge.bytes(), if grew { was.max(to) } else { was });
                    charging(grew, payer, to.saturating_sub(was))
                }
                15 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Charge(_))) else {
                        return refused(false);
                    };
                    let payer = self.held[at].payer;
                    let part = self.below(48);
                    let Item::Charge(charge) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let was = charge.bytes();
                    let split = charge.split(part);
                    assert_eq!(split.is_some(), part <= was);
                    let done = split.is_some();
                    if let Some(split) = split {
                        assert_eq!(split.bytes() + charge.bytes(), was);
                        self.add(Item::Charge(split), payer);
                    }
                    refused(done)
                }
                16 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Charge(_))) else {
                        return refused(false);
                    };
                    let from = self.held[at].payer;
                    let to = self.below(2);
                    let (room, before) = (self.room(to), [0, 1].map(|b| self.budgets[b].used()));
                    let target = self.budgets[to].clone();
                    let Item::Charge(charge) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let bytes = charge.bytes();
                    let moved = charge.transfer(&target);
                    assert_eq!(moved, from == to || bytes <= room);
                    let after = [0, 1].map(|b| self.budgets[b].used());
                    if from == to {
                        assert_eq!(after, before, "a move within one budget changes nothing");
                    } else if moved {
                        assert_eq!(after[from], before[from] - bytes);
                        assert_eq!(after[to], before[to] + bytes);
                        self.held[at].payer = to;
                    }
                    charging(moved, to, bytes)
                }
                21 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Deque(_))) else {
                        return refused(false);
                    };
                    let payer = self.held[at].payer;
                    let room = self.room(payer);
                    let additional = self.below(24);
                    let Item::Deque(deque) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let (len, places) = (deque.len(), deque.places());
                    let wanted = len + additional;
                    let fits = wanted <= deque.most
                        && (wanted <= places || (wanted - places) * size_of::<u64>() <= room);
                    // Growth doubles, or goes to what is asked if that is
                    // more, when there is room, else takes the places
                    // there is room for, never fewer than asked.
                    let grown = more_places(places, deque.most)
                        .max(wanted)
                        .min(places + room / size_of::<u64>());
                    let reserved = deque.reserve(additional);
                    assert_eq!(reserved, fits);
                    if reserved {
                        assert_eq!(
                            deque.places(),
                            if wanted <= places { places } else { grown }
                        );
                        for item in 0..additional as u64 {
                            assert!(deque.push_back(item).is_ok(), "a reserved place refused");
                        }
                        assert_eq!(deque.len(), wanted);
                    }
                    charging(
                        reserved,
                        payer,
                        wanted.saturating_sub(places) * size_of::<u64>(),
                    )
                }
                17 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Bytes(_))) else {
                        return refused(false);
                    };
                    let held = self.held.swap_remove(at);
                    let Item::Bytes(bytes) = held.item else {
                        unreachable!()
                    };
                    let (len, charged) = (bytes.len(), bytes.charged());
                    let chunk = bytes.into_chunk();
                    assert_eq!((chunk.len(), chunk.charged()), (len, charged));
                    self.add(Item::Chunk(chunk, true), held.payer);
                    refused(true)
                }
                18 => {
                    let Some(at) =
                        self.pick(|item| matches!(item, Item::Chunk(c, _) if c.len() > 1))
                    else {
                        return refused(false);
                    };
                    let payer = self.held[at].payer;
                    let Item::Chunk(chunk, whole) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let n = 1 + self.rng.random_below(chunk.len() as u64 - 1) as usize;
                    let charged = chunk.charged();
                    let prefix = chunk.split_to(n);
                    *whole = false;
                    assert_eq!(prefix.charged(), charged, "pieces name one charge");
                    self.add(Item::Chunk(prefix, false), payer);
                    refused(true)
                }
                19 | 20 => {
                    let Some(at) = self.pick(|item| matches!(item, Item::Chunk(..))) else {
                        return refused(false);
                    };
                    let (payer, to) = (self.held[at].payer, self.below(2));
                    let shared = self.shared(at);
                    let room = self.room(to);
                    let before = [0, 1].map(|b| self.budgets[b].used());
                    let target = self.budgets[to].clone();
                    let Item::Chunk(chunk, whole) = &mut self.held[at].item else {
                        unreachable!()
                    };
                    let (bytes, capacity) = (chunk.to_vec(), chunk.backing_capacity());
                    let in_place = *whole && !shared;
                    let fits = payer == to
                        || if in_place {
                            capacity <= room
                        } else {
                            bytes.len() <= room
                        };
                    let repaid = chunk.repay(&target);
                    assert_eq!(repaid, fits);
                    assert_eq!(&chunk[..], &bytes[..]);
                    let after = [0, 1].map(|b| self.budgets[b].used());
                    if payer == to {
                        assert!(
                            after[to] <= before[to],
                            "a move within one budget never raises it"
                        );
                        return refused(repaid);
                    }
                    if !repaid {
                        return charging(false, to, if in_place { capacity } else { bytes.len() });
                    }
                    assert!(
                        after[to] - before[to] <= capacity,
                        "the target pays at most what moved"
                    );
                    *whole = true;
                    self.held[at].payer = to;
                    if in_place {
                        self.reached.moved_in_place += 1;
                    } else {
                        self.reached.moved_by_copy += 1;
                    }
                    Acted {
                        refused: false,
                        trimmed: (in_place && bytes.len() < capacity).then_some(to),
                        need: None,
                    }
                }
                _ => {
                    if self.held.is_empty() {
                        return refused(false);
                    }
                    let at = self.below(self.held.len());
                    let shared = self.shared(at);
                    let payer = self.held[at].payer;
                    let before = self.budgets[payer].used();
                    let held = self.held.swap_remove(at);
                    let charged = held.item.charged();
                    drop(held);
                    let freed = before - self.budgets[payer].used();
                    assert_eq!(freed, if shared { 0 } else { charged });
                    refused(true)
                }
            }
        }

        /// Asks runner `runner` to be woken when memory frees on `budget`,
        /// with a mark it took before a round.
        fn ask(&mut self, budget: usize, runner: usize, (mark, counted): (Refusals, u64)) {
            let room = self.room(budget);
            let waits = &mut self.waits[budget];
            if waits.refusals != counted {
                if waits.woken_at > counted || waits.wanted == 0 || room >= waits.wanted {
                    self.runners[runner].woken += 1;
                    self.reached.woken_at_once += 1;
                } else if !waits.waiting.contains(&runner) {
                    waits.waiting.push(runner);
                }
            }
            self.budgets[budget].wake_when_freed(&self.runners[runner].waiter, mark);
        }

        /// Memory came back to `budget`: once there is room for the least
        /// refused charge, the runners that asked are woken.
        fn released(&mut self, budget: usize) {
            let room = self.room(budget);
            let waits = &mut self.waits[budget];
            if waits.wanted == 0 {
                return;
            }
            if room < waits.wanted {
                self.reached.released_too_little += 1;
                return;
            }
            for runner in waits.waiting.drain(..) {
                self.runners[runner].woken += 1;
                self.reached.woken_after_waiting += 1;
            }
            waits.wanted = 0;
            waits.woken_at = waits.refusals;
        }

        fn step(&mut self) {
            let marks = [0, 1].map(|b| (self.budgets[b].refusals(), self.waits[b].refusals));
            let used = [0, 1].map(|b| self.budgets[b].used());
            let shapes: Vec<_> = self.held.iter().map(|held| held.item.shape()).collect();
            let acted = self.act();
            if acted.refused {
                let now: Vec<_> = self.held.iter().map(|held| held.item.shape()).collect();
                assert_eq!(now, shapes, "a refused call changed something");
                assert_eq!([0, 1].map(|b| self.budgets[b].used()), used);
            }
            for b in 0..2 {
                let refused = self.budgets[b].refusals() != marks[b].0;
                let released = self.budgets[b].used() < used[b] || acted.trimmed == Some(b);
                assert!(!(refused && released), "one call refused and released");
                if refused {
                    let Some((on, need)) = acted.need else {
                        panic!("a call the model thought fit was refused");
                    };
                    assert_eq!(on, b, "refused on the budget it charged");
                    let waits = &mut self.waits[b];
                    waits.refusals += 1;
                    if waits.wanted == 0 || need < waits.wanted {
                        waits.wanted = need;
                    }
                    self.reached.refusals += 1;
                }
                if released {
                    self.released(b);
                }
                if refused && self.below(2) == 0 {
                    let runner = self.below(self.runners.len());
                    self.ask(b, runner, marks[b]);
                }
                if refused && self.below(4) == 0 {
                    self.stale[b] = Some(marks[b]);
                }
                if let Some(mark) = self.stale[b]
                    && self.below(8) == 0
                {
                    let runner = self.below(self.runners.len());
                    self.ask(b, runner, mark);
                }
                if !refused && self.below(16) == 0 {
                    let runner = self.below(self.runners.len());
                    self.ask(b, runner, marks[b]);
                }
            }
            self.check();
        }

        fn check(&self) {
            for held in &self.held {
                assert_eq!(
                    held.item.charged(),
                    held.item.holds(),
                    "charged what it holds"
                );
            }
            for b in 0..2 {
                let mut paid = 0;
                for (i, held) in self.held.iter().enumerate() {
                    if held.payer != b {
                        continue;
                    }
                    // Pieces of one chunk name one charge: count it once.
                    let counted = matches!(&held.item, Item::Chunk(chunk, _)
                        if self.held[..i].iter().any(|earlier| matches!(&earlier.item,
                            Item::Chunk(other, _) if other.shares_backing(chunk))));
                    if !counted {
                        paid += held.item.charged();
                    }
                }
                assert_eq!(
                    self.budgets[b].used(),
                    paid,
                    "the count is what is paid for"
                );
                assert!(self.budgets[b].used() <= self.budgets[b].limit());
            }
            for runner in &self.runners {
                assert_eq!(runner.count.0.load(Ordering::Relaxed), runner.woken);
            }
        }
    }

    #[test]
    fn random_calls_keep_cover_sum_order_return_move_and_wake() {
        let mut reached = Reached::default();
        for seed in 0..64 {
            let mut model = Model::new(seed);
            for _ in 0..400 {
                model.step();
            }
            while let Some(held) = model.held.pop() {
                let before = model.budgets[held.payer].used();
                drop(held.item);
                if model.budgets[held.payer].used() < before {
                    model.released(held.payer);
                }
                model.check();
            }
            for budget in &model.budgets {
                assert_eq!(budget.used(), 0, "seed {seed}: everything came back");
            }
            let r = &model.reached;
            reached.refusals += r.refusals;
            reached.released_too_little += r.released_too_little;
            reached.woken_after_waiting += r.woken_after_waiting;
            reached.woken_at_once += r.woken_at_once;
            reached.moved_in_place += r.moved_in_place;
            reached.moved_by_copy += r.moved_by_copy;
            reached.overruns += r.overruns;
        }
        assert!(reached.refusals > 0);
        assert!(reached.released_too_little > 0);
        assert!(reached.woken_after_waiting > 0);
        assert!(reached.woken_at_once > 0);
        assert!(reached.moved_in_place > 0);
        assert!(reached.moved_by_copy > 0);
        assert!(reached.overruns > 0);
    }

    #[test]
    fn a_writer_past_the_capacity_is_undone_and_found() {
        let budget = Budget::new(64);
        let mut bytes = ChargedBytes::copy_of(&budget, b"head").unwrap();
        assert!(bytes.grow_to(8));
        let (capacity, charged) = (bytes.capacity(), budget.used());
        let wrote = bytes.fill(|out| {
            out.extend_from_slice(&[7; 32]);
            Ok::<_, ()>(())
        });
        assert!(matches!(wrote, Err(WriteFailure::Bound)));
        assert_eq!(&bytes[..], b"head");
        assert_eq!(bytes.capacity(), capacity);
        assert_eq!(budget.used(), charged);
        let failed = bytes.fill(|out| {
            out.push(1);
            Err::<(), _>("no")
        });
        assert!(matches!(failed, Err(WriteFailure::Value("no"))));
        assert_eq!(
            &bytes[..],
            b"head\x01",
            "a writer's own failure keeps what it wrote"
        );
    }

    #[test]
    fn writing_stops_at_the_capacity() {
        use std::io::Write;
        let budget = Budget::new(64);
        let mut bytes = ChargedBytes::with_capacity(&budget, 6).unwrap();
        assert_eq!(bytes.write(b"abcd").unwrap(), 4);
        assert_eq!(
            bytes
                .write_vectored(&[std::io::IoSlice::new(b"ef"), std::io::IoSlice::new(b"gh")])
                .unwrap(),
            2
        );
        assert_eq!(bytes.write(b"i").unwrap(), 0);
        assert!(bytes.write_all(b"j").is_err());
        assert_eq!(&bytes[..], b"abcdef");
        assert_eq!(bytes.capacity(), budget.used());
    }

    #[test]
    fn a_charge_becomes_the_places_it_pays_for() {
        let budget = Budget::new(64);
        let charge = budget.charge(3 * size_of::<u64>() + 5).unwrap();
        let mut deque = charge.into_deque::<u64>();
        assert_eq!(deque.places() * size_of::<u64>(), deque.charged());
        assert_eq!(
            budget.used(),
            deque.charged(),
            "the part past a place went back"
        );
        for i in 0..deque.places() as u64 {
            assert!(deque.push_back(i).is_ok());
        }
        assert_eq!(
            deque.push_back(9),
            Err(9),
            "the queue holds what was paid for"
        );
        assert_eq!(budget.used(), deque.charged());
        drop(deque);
        assert_eq!(budget.used(), 0);
        for paid in [
            0,
            size_of::<u64>() - 1,
            3 * size_of::<u64>() + 1,
            budget.limit(),
        ] {
            let mut vector = budget.charge(paid).unwrap().into_vec::<u64>();
            assert_eq!(vector.places(), paid / size_of::<u64>());
            assert_eq!(vector.charged(), vector.places() * size_of::<u64>());
            for value in 0..vector.places() {
                assert!(vector.push(value as u64).is_ok());
            }
            assert!(vector.push(0).is_err());
            assert_eq!(budget.used(), vector.charged());
            drop(vector);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn a_full_queue_near_the_limit_grows_by_the_places_that_fit() {
        let size = size_of::<u64>();
        // Room for four places and part of a fifth, not for eight.
        let budget = Budget::new(5 * size - 1);
        let mut deque = ChargedDeque::<u64>::new(&budget, 64);
        for i in 0..4 {
            assert!(deque.push_back(i).is_ok());
        }
        assert_eq!(deque.places(), 4);
        let mark = budget.refusals();
        // Full, and doubling does not fit: no place more fits either.
        assert_eq!(deque.push_back(4), Err(4));
        assert_ne!(budget.refusals(), mark);
        let other = Budget::new(6 * size);
        let mut deque = ChargedDeque::<u64>::new(&other, 64);
        for i in 0..4 {
            assert!(deque.push_back(i).is_ok());
        }
        let mark = other.refusals();
        // Doubling to eight does not fit; two more places do.
        assert!(deque.push_back(4).is_ok());
        assert_eq!(deque.places(), 6);
        assert_eq!(deque.charged(), other.used());
        assert_eq!(other.refusals(), mark, "growing less is not a refusal");
        drop((deque, other));
        assert_eq!(budget.used(), 4 * size);
    }

    #[test]
    fn a_place_is_paid_for_before_its_item_exists() {
        let size = size_of::<u64>();
        let budget = Budget::new(2 * size);
        let mut deque = ChargedDeque::<u64>::new(&budget, 8);
        deque.place().expect("room for a place").push_back(1);
        deque.place().expect("room for a place").push_back(2);
        let used = budget.used();
        assert!(deque.place().is_none(), "no room for a third");
        assert_eq!((deque.len(), deque.places(), budget.used()), (2, 2, used));
        assert_eq!(deque.get_mut(1).map(|v| *v), Some(2));
        assert_eq!(deque.remove(0), Some(1));
        assert_eq!(deque.places() * size, deque.charged());
        deque
            .place()
            .expect("the removed place is still paid for")
            .push_back(3);
        assert_eq!(deque.iter().copied().collect::<Vec<_>>(), [2, 3]);
        deque.set_most(1);
        assert!(deque.place().is_none(), "more than the most are held");
        deque.pop_front();
        deque.set_most(1);
        assert_eq!(deque.places(), 1);
        assert_eq!(budget.used(), size);
        drop(deque);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn a_bounded_map_is_paid_for_once() {
        let budget = Budget::new(1 << 16);
        let mut map = BoundedMap::new(&budget, 3).unwrap();
        let charged = budget.used();
        assert_eq!(charged, BoundedMap::<u32, [u8; 40]>::storage(3).unwrap());
        for key in 0..3u32 {
            assert_eq!(map.insert(key, [key as u8; 40]), Ok(None));
        }
        assert_eq!(map.insert(9, [9; 40]), Err((9, [9; 40])));
        assert_eq!(map.insert(1, [7; 40]), Ok(Some([1; 40])));
        assert_eq!(map.remove(&0), Some([0; 40]));
        assert_eq!(map.insert(9, [9; 40]), Ok(None));
        assert_eq!(budget.used(), charged);
        assert_eq!(map.iter().map(|(k, _)| *k).collect::<Vec<_>>(), [1, 2, 9]);
        drop(map);
        assert_eq!(budget.used(), 0);
        let none = Budget::new(BoundedMap::<u32, [u8; 40]>::storage(3).unwrap() - 1);
        assert!(BoundedMap::<u32, [u8; 40]>::new(&none, 3).is_none());
    }

    #[test]
    fn taking_from_a_bounded_map_frees_places_but_keeps_the_charge() {
        let budget = Budget::new(1 << 16);
        let mut map = BoundedMap::new(&budget, 3).unwrap();
        let charged = budget.used();
        for key in [5u32, 1, 3] {
            assert_eq!(map.insert(key, key * 10), Ok(None));
        }
        assert_eq!(map.first_key_value(), Some((&1, &10)));
        assert_eq!(map.get_key_value(&3), Some((&3, &30)));
        assert_eq!(
            map.range(2..).map(|(k, _)| *k).collect::<Vec<_>>(),
            [3, 5],
            "a range is in key order"
        );
        assert_eq!(map.pop_first(), Some((1, 10)));
        assert_eq!(map.insert(7, 70), Ok(None), "the popped place is free");
        assert_eq!(map.insert(8, 80), Err((8, 80)));
        map.clear();
        assert!(map.is_empty());
        assert_eq!(budget.used(), charged, "the charge pays for the places");
        for key in 0..3u32 {
            assert_eq!(map.insert(key, key), Ok(None));
        }
        assert_eq!(budget.used(), charged);
        drop(map);
        assert_eq!(budget.used(), 0);
    }
}
