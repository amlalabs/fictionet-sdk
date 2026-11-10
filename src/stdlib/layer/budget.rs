use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::Waker;

use fictionet::sync::Mutex;

/// Bytes that connections may hold, shared by everything charged to it:
/// one sandbox's connections in [`Net`](fictionet::stdlib::world::net::Net).
/// Cheap to clone; clones share the count.
///
/// A [`Charge`] holds part of it and gives it back when dropped. Charge
/// before growing: [`Budget::charge`] and [`Charge::grow_to`] refuse,
/// changing nothing, when the total would pass the limit, so the limit
/// holds at every moment and not only when someone checks. The charged
/// containers ([`ChargedBytes`](super::ChargedBytes),
/// [`ChargedDeque`](super::ChargedDeque) and the rest) hold their charge
/// inside, so they cannot grow without it. A layer reaches its
/// connection's budget through [`Env::budget`](super::Env::budget); a
/// [`Chunk`](super::Chunk) carries its charge with it, so the charge moves
/// with the bytes.
///
/// A refusal is not a dead end. The runner that drove the refused layer
/// asks to be woken when memory frees ([`Budget::wake_when_freed`]), and
/// the next release wakes it, so the layer tries again.
///
/// The [stack runners](fictionet::stdlib::services::stack) charge each
/// connection its read buffer, the bytes read but not yet taken, and the
/// table of the stack's work; each layer charges what it holds, such as a
/// framer's buffer and the replies not yet written.
#[derive(Clone)]
pub struct Budget {
    inner: Arc<BudgetInner>,
}

struct BudgetInner {
    used: AtomicUsize,
    limit: usize,
    /// A charge found no room, and no release has woken the runners since.
    /// Set before the charge tries a last time and cleared by the release
    /// that wakes, so room freed after a refusal always wakes someone.
    starved: AtomicBool,
    /// How many charges found no room at first. Counted before the last
    /// try, so a runner that compares it across its round never misses a
    /// refusal of its own.
    refusals: AtomicU64,
    waiters: Mutex<Waiters>,
}

/// The runners waiting for memory, and when they were last woken.
struct Waiters {
    /// Each is woken once, by the first release after it registered.
    wakers: Vec<Waker>,
    /// The count of refusals when a release last woke the runners.
    woken_at: u64,
}

/// A point in a budget's count of refused charges. A runner takes one
/// before a round and hands it to [`Budget::wake_when_freed`] after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusals(u64);

impl std::fmt::Debug for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Budget")
            .field("used", &self.used())
            .field("limit", &self.limit())
            .finish()
    }
}

impl Budget {
    /// At most `limit` bytes.
    pub fn new(limit: usize) -> Budget {
        Budget {
            inner: Arc::new(BudgetInner {
                used: AtomicUsize::new(0),
                limit,
                starved: AtomicBool::new(false),
                refusals: AtomicU64::new(0),
                waiters: Mutex::new(Waiters {
                    wakers: Vec::new(),
                    woken_at: 0,
                }),
            }),
        }
    }

    /// A budget that never refuses, for code that is not limited.
    pub fn unlimited() -> Budget {
        Budget::new(usize::MAX)
    }

    /// Bytes charged now.
    pub fn used(&self) -> usize {
        self.inner.used.load(Ordering::Relaxed)
    }

    /// The limit.
    pub fn limit(&self) -> usize {
        self.inner.limit
    }

    /// Whether the two count against one limit: clones of one budget.
    pub fn same(&self, other: &Budget) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// A charge of exactly `bytes`, or `None` if they do not fit.
    pub fn charge(&self, bytes: usize) -> Option<Charge> {
        self.charge_within(bytes..=bytes)
    }

    /// A charge of as much of `want` as fits: its end if there is room,
    /// less if not, and `None` if not even its start fits.
    pub fn charge_within(&self, want: RangeInclusive<usize>) -> Option<Charge> {
        let now = self.take(want)?;
        Some(Charge {
            budget: self.clone(),
            now,
        })
    }

    /// Where the count of refused charges stands. A runner takes this
    /// before a round of its stack, to hand to
    /// [`wake_when_freed`](Self::wake_when_freed) after it.
    pub fn refusals(&self) -> Refusals {
        Refusals(self.inner.refusals.load(Ordering::SeqCst))
    }

    /// Wakes `waker` once memory frees after a charge refused since
    /// `since`. A runner calls this after each round, with what
    /// [`refusals`](Self::refusals) said before it; a layer never does.
    /// When nothing was refused since, it does nothing. When memory was
    /// freed after the refusal already, it wakes `waker` at once. A
    /// refusal on another connection of the same budget also counts, which
    /// costs one poll for nothing.
    pub fn wake_when_freed(&self, waker: &Waker, since: Refusals) {
        if self.inner.refusals.load(Ordering::SeqCst) == since.0 {
            return;
        }
        let mut waiters = self.inner.waiters.lock();
        if waiters.woken_at > since.0 || !self.inner.starved.load(Ordering::SeqCst) {
            drop(waiters);
            waker.wake_by_ref();
            return;
        }
        if !waiters.wakers.iter().any(|w| w.will_wake(waker)) {
            waiters.wakers.push(waker.clone());
        }
    }

    /// Takes as much of `want` as fits, or nothing.
    fn take(&self, want: RangeInclusive<usize>) -> Option<usize> {
        if *want.end() == 0 {
            return (*want.start() == 0).then_some(0);
        }
        self.take_with(|room| {
            let take = (*want.end()).min(room);
            (take >= *want.start()).then_some(take)
        })
    }

    /// Takes as many whole `unit`s of bytes as fit within `units`, or
    /// nothing. Returns how many units it took.
    fn take_units(&self, units: RangeInclusive<usize>, unit: usize) -> Option<usize> {
        if unit == 0 || *units.end() == 0 {
            // No bytes at all: always fits.
            return Some(*units.end());
        }
        let taken = self.take_with(|room| {
            let take = (*units.end()).min(room / unit);
            (take >= *units.start()).then_some(take * unit)
        })?;
        Some(taken / unit)
    }

    /// Takes what `fits` says of the room left, or nothing when it says
    /// nothing fits.
    fn take_with(&self, fits: impl Fn(usize) -> Option<usize>) -> Option<usize> {
        if let Some(taken) = self.try_take(&fits) {
            return Some(taken);
        }
        // No room. Count the refusal and mark the budget starved before
        // trying once more: a release that frees room after the first try
        // either comes before this try, which then takes the room, or
        // sees the mark and wakes the runners.
        self.inner.refusals.fetch_add(1, Ordering::SeqCst);
        self.inner.starved.store(true, Ordering::SeqCst);
        self.try_take(&fits)
    }

    /// One pass over the count: what `fits` says of the room left, if
    /// anything.
    fn try_take(&self, fits: &impl Fn(usize) -> Option<usize>) -> Option<usize> {
        let room = |used: usize| self.inner.limit.saturating_sub(used);
        let before = self
            .inner
            .used
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                fits(room(used)).map(|take| used + take)
            })
            .ok()?;
        fits(room(before))
    }

    /// Gives back `bytes`, waking the runners if a charge was refused
    /// since they were last woken.
    fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.inner.used.fetch_sub(bytes, Ordering::SeqCst);
        if !self.inner.starved.load(Ordering::SeqCst)
            || !self.inner.starved.swap(false, Ordering::SeqCst)
        {
            return;
        }
        let wakers = {
            let mut waiters = self.inner.waiters.lock();
            waiters.woken_at = self.inner.refusals.load(Ordering::SeqCst);
            std::mem::take(&mut waiters.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

/// Bytes charged to a [`Budget`], given back when dropped.
#[must_use = "a charge that is dropped gives its bytes back"]
pub struct Charge {
    budget: Budget,
    now: usize,
}

impl std::fmt::Debug for Charge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Charge").field("bytes", &self.now).finish()
    }
}

impl Charge {
    /// A charge of nothing, which always fits.
    pub(super) fn nothing(budget: &Budget) -> Charge {
        Charge {
            budget: budget.clone(),
            now: 0,
        }
    }

    /// The bytes charged now.
    pub fn bytes(&self) -> usize {
        self.now
    }

    /// The budget it counts against.
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Charges `to` bytes in all, if that is more than now. Refuses,
    /// changing nothing, if the budget has no room for the difference.
    #[must_use = "a refused growth must not be followed by the growth"]
    pub fn grow_to(&mut self, to: usize) -> bool {
        if to <= self.now {
            return true;
        }
        let more = to - self.now;
        if self.budget.take(more..=more).is_none() {
            return false;
        }
        self.now = to;
        true
    }

    /// Grows by as many whole `unit`s of bytes as fit, at least
    /// `units.start()` and at most `units.end()`, as a container grows by
    /// places: twice as many if there is room, fewer if not. Returns how
    /// many units it grew by, or `None`, changing nothing, if not even the
    /// start fits.
    #[must_use = "a refused growth must not be followed by the growth"]
    pub fn grow_by_units(&mut self, units: RangeInclusive<usize>, unit: usize) -> Option<usize> {
        let more = self.budget.take_units(units, unit)?;
        self.now += more * unit;
        Some(more)
    }

    /// Charges only `to` bytes, if that is less than now, giving back the
    /// rest. Giving back cannot fail.
    pub fn shrink_to(&mut self, to: usize) {
        if to >= self.now {
            return;
        }
        let freed = self.now - to;
        self.now = to;
        self.budget.release(freed);
    }

    /// Moves `bytes` of this charge into a new one, as when part of what it
    /// pays for changes owner. The budget's total does not change. `None`,
    /// changing nothing, if this charge holds less.
    pub fn split(&mut self, bytes: usize) -> Option<Charge> {
        if bytes > self.now {
            return None;
        }
        self.now -= bytes;
        Some(Charge {
            budget: self.budget.clone(),
            now: bytes,
        })
    }

    /// Moves this charge to `to`. Within one budget nothing changes.
    /// Otherwise `to` is charged first and this charge's budget given back
    /// after, so a refusal changes nothing.
    #[must_use = "a refused transfer leaves the charge where it was"]
    pub fn transfer(&mut self, to: &Budget) -> bool {
        if self.budget.same(to) {
            return true;
        }
        if to.take(self.now..=self.now).is_none() {
            return false;
        }
        let from = std::mem::replace(&mut self.budget, to.clone());
        from.release(self.now);
        true
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.release(self.now);
    }
}

/// The lifetime of work issued by a layer. Dropping or cancelling it makes
/// every outstanding lease invalid; the runner drops the work before polling.
pub struct WorkOwner {
    live: Arc<std::sync::atomic::AtomicBool>,
}

impl WorkOwner {
    /// A new live owner.
    pub fn new() -> Self {
        Self {
            live: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    /// Associate work with this lifetime.
    pub fn own<W>(&self, work: W) -> OwnedWork<W> {
        OwnedWork {
            work,
            live: self.live.clone(),
        }
    }

    /// Invalidate all outstanding work, without waiting for its tasks.
    pub fn cancel(&self) {
        self.live.store(false, Ordering::Release);
    }
}

impl Drop for WorkOwner {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Work carrying the lifetime of the layer that issued it.
pub struct OwnedWork<W> {
    pub(crate) work: W,
    live: Arc<std::sync::atomic::AtomicBool>,
}

impl<W> OwnedWork<W> {
    /// Whether the issuing lifetime has ended.
    pub fn cancelled(&self) -> bool {
        !self.live.load(Ordering::Acquire)
    }
}

impl Default for WorkOwner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Wake;

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

    impl Count {
        fn woken(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn charge_within_takes_what_fits_or_nothing() {
        let budget = Budget::new(10);
        let first = budget.charge(4).unwrap();
        let room = budget.limit() - budget.used();
        let second = budget.charge_within(2..=room + 3).unwrap();
        assert_eq!(second.bytes(), room, "less than the end, all that fits");
        assert_eq!(budget.used(), budget.limit());
        let mark = budget.refusals();
        assert!(budget.charge_within(1..=3).is_none());
        assert_ne!(budget.refusals(), mark, "a refusal is counted");
        assert_eq!(budget.used(), budget.limit());
        drop(second);
        let third = budget.charge_within(1..=3).unwrap();
        assert_eq!(third.bytes(), 3, "the end, when it fits");
        assert_eq!(budget.used(), first.bytes() + third.bytes());
        drop((first, third));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn growing_refuses_changing_nothing_and_shrinking_gives_back() {
        let budget = Budget::new(16);
        let other = budget.charge(10).unwrap();
        let mut charge = budget.charge(4).unwrap();
        assert!(!charge.grow_to(budget.limit() - other.bytes() + 1));
        assert_eq!(charge.bytes(), 4);
        assert_eq!(budget.used(), other.bytes() + charge.bytes());
        assert!(charge.grow_to(budget.limit() - other.bytes()));
        assert_eq!(budget.used(), budget.limit());
        let held = charge.bytes();
        assert!(charge.grow_to(1), "a size already reached is kept");
        assert_eq!(charge.bytes(), held);
        charge.shrink_to(1);
        assert_eq!(budget.used(), other.bytes() + 1);
        charge.shrink_to(held);
        assert_eq!(charge.bytes(), 1, "shrinking never grows");
        drop((other, charge));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn growing_by_units_takes_whole_units_that_fit_or_nothing() {
        let budget = Budget::new(64);
        let other = budget.charge(30).unwrap();
        let mut charge = budget.charge(6).unwrap();
        let mark = budget.refusals();
        let room = budget.limit() - budget.used();
        let unit = 8;
        // Asked for more units than fit: as many whole ones as fit, and
        // no refusal, since the start fit.
        let grew = charge.grow_by_units(1..=room, unit).unwrap();
        assert_eq!(grew, room / unit);
        assert_eq!(charge.bytes(), 6 + grew * unit);
        assert!(budget.limit() - budget.used() < unit);
        assert_eq!(budget.refusals(), mark, "taking fewer is not a refusal");
        let (held, used) = (charge.bytes(), budget.used());
        assert_eq!(charge.grow_by_units(1..=4, unit), None);
        assert_ne!(budget.refusals(), mark, "nothing fitting is a refusal");
        assert_eq!((charge.bytes(), budget.used()), (held, used));
        drop((other, charge));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn a_transfer_within_one_budget_changes_nothing() {
        let budget = Budget::new(8);
        let mut charge = budget.charge(8).unwrap();
        // The budget is full, so charging before releasing would refuse.
        assert!(charge.transfer(&budget.clone()));
        assert_eq!(budget.used(), 8);
        assert!(charge.budget().same(&budget));
        drop(charge);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn a_transfer_across_budgets_charges_the_target_first() {
        let from = Budget::new(8);
        let to = Budget::new(8);
        assert!(!from.same(&to));
        let mut charge = from.charge(6).unwrap();
        let held = to.charge(3).unwrap();
        assert!(!charge.transfer(&to));
        assert_eq!((from.used(), to.used()), (6, 3));
        assert!(charge.budget().same(&from));
        drop(held);
        assert!(charge.transfer(&to));
        assert_eq!((from.used(), to.used()), (0, 6));
        assert!(charge.budget().same(&to));
        drop(charge);
        assert_eq!(to.used(), 0);
    }

    #[test]
    fn a_release_after_a_refusal_wakes_each_waiting_runner_once() {
        let budget = Budget::new(8);
        let held = budget.charge(8).unwrap();
        let (a, b) = (Arc::new(Count::default()), Arc::new(Count::default()));
        let (wake_a, wake_b) = (Waker::from(a.clone()), Waker::from(b.clone()));
        let mark = budget.refusals();
        budget.wake_when_freed(&wake_a, mark);
        assert!(budget.charge(1).is_none());
        budget.wake_when_freed(&wake_a, mark);
        budget.wake_when_freed(&wake_a, mark);
        budget.wake_when_freed(&wake_b, mark);
        assert_eq!((a.woken(), b.woken()), (0, 0), "nothing freed yet");
        drop(held);
        assert_eq!((a.woken(), b.woken()), (1, 1));
        // Woken, they wait for nothing more until a charge is refused again.
        drop(budget.charge(8).unwrap());
        assert_eq!((a.woken(), b.woken()), (1, 1));
    }

    #[test]
    fn a_runner_that_asks_after_memory_freed_is_woken_at_once() {
        let budget = Budget::new(8);
        let held = budget.charge(8).unwrap();
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let mark = budget.refusals();
        assert!(budget.charge(1).is_none());
        drop(held);
        budget.wake_when_freed(&waker, mark);
        assert_eq!(count.woken(), 1);
        // Another refusal after the release does not hide that memory was
        // freed after this runner's.
        let held = budget.charge(8).unwrap();
        assert!(budget.charge(1).is_none());
        budget.wake_when_freed(&waker, mark);
        assert_eq!(count.woken(), 2);
        drop(held);
    }
}
