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
/// the release that leaves room for the refused charge wakes it, so the
/// layer tries again. A release too small for it wakes nothing, so memory
/// that comes and goes in small amounts does not keep a runner busy.
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
    /// The least that a charge refused since the runners were last woken
    /// needed, or 0 if none was refused. Lowered before the refused charge
    /// tries a last time, and cleared by the first release that leaves
    /// that much room, which wakes the runners. So room freed after a
    /// refusal wakes someone once it is enough for the smallest refused
    /// charge, and not before.
    wanted: AtomicUsize,
    /// How many charges found no room at first. Counted before the last
    /// try, so a runner that compares it across its round never misses a
    /// refusal of its own.
    refusals: AtomicU64,
    waiters: Mutex<Waiters>,
}

/// The runners waiting for memory, and when they were last woken.
struct Waiters {
    /// Each is woken once, by the first release after it registered that
    /// leaves room for the least refused charge. One whose owner dropped
    /// it leaves at the next registration.
    waiting: Vec<Arc<dyn Waits>>,
    /// The count of refusals when a release last woke the runners.
    woken_at: u64,
}

/// What a budget wakes when memory frees after a refusal: a stack, or one
/// child of a stack ([`Children`](super::Children)), with the waker that
/// gets it run again.
///
/// Its owner makes it once and keeps it, so asking again while it waits
/// adds nothing to the budget's list. Dropping it takes it off: it is
/// never woken after, and it leaves the list at the budget's next
/// registration or wake, so a list holds at most the waiters alive at
/// the last registration.
pub struct Waiter {
    inner: Arc<dyn Waits>,
    waker: Waker,
}

/// What the budget's list holds of a [`Waiter`].
trait Waits: Send + Sync {
    /// Wakes it, unless its owner dropped it.
    fn wake(&self);
    /// Its owner dropped it.
    fn gone(&self) -> bool;
    fn leave(&self);
}

/// A waiter's shared part: what waking it does, and whether its owner
/// dropped it.
struct Node<F> {
    wake: F,
    gone: AtomicBool,
}

impl<F: Fn() + Send + Sync> Waits for Node<F> {
    fn wake(&self) {
        if !self.gone() {
            (self.wake)();
        }
    }

    fn gone(&self) -> bool {
        self.gone.load(Ordering::Acquire)
    }

    fn leave(&self) {
        self.gone.store(true, Ordering::Release);
    }
}

/// The waker of a waiter made by [`Waiter::from_fn`] is its node.
impl<F: Fn() + Send + Sync + 'static> std::task::Wake for Node<F> {
    fn wake(self: Arc<Self>) {
        (self.wake)();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        (self.wake)();
    }
}

impl Waiter {
    /// A waiter that wakes `waker`.
    pub fn new(waker: Waker) -> Waiter {
        let wakes = waker.clone();
        Waiter {
            inner: Arc::new(Node {
                wake: move || wakes.wake_by_ref(),
                gone: AtomicBool::new(false),
            }),
            waker,
        }
    }

    /// A waiter that calls `wake` when woken, and whose
    /// [`waker`](Self::waker) calls it too: one allocation for both, for an
    /// owner that makes the waker only to wait with it, as a child of
    /// [`Children`](super::Children) does.
    pub fn from_fn(wake: impl Fn() + Send + Sync + 'static) -> Waiter {
        let node = Arc::new(Node {
            wake,
            gone: AtomicBool::new(false),
        });
        Waiter {
            waker: Waker::from(node.clone()),
            inner: node,
        }
    }

    /// What it wakes.
    pub fn waker(&self) -> &Waker {
        &self.waker
    }
}

impl std::fmt::Debug for Waiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Waiter").finish_non_exhaustive()
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.inner.leave();
    }
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
                wanted: AtomicUsize::new(0),
                refusals: AtomicU64::new(0),
                waiters: Mutex::new(Waiters {
                    waiting: Vec::new(),
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

    /// Wakes `waiter` once memory frees after a charge refused since
    /// `since`: once a release leaves room for the least that a charge
    /// refused since the last wake needed. A runner calls this after each
    /// round, with what [`refusals`](Self::refusals) said before it; a
    /// layer never does, though a layer that runs others, as
    /// [`Children`](super::Children) does, calls it for each of them.
    /// When nothing was refused since, it does nothing. When memory was
    /// freed after the refusal already, or there is room now, it wakes
    /// `waiter` at once. A refusal on another connection of the same
    /// budget also counts, which can cost a poll for nothing, but only
    /// when memory freed was enough for that refusal.
    pub fn wake_when_freed(&self, waiter: &Waiter, since: Refusals) {
        if self.inner.refusals.load(Ordering::SeqCst) == since.0 {
            return;
        }
        let mut waiters = self.inner.waiters.lock();
        let wanted = self.inner.wanted.load(Ordering::SeqCst);
        if waiters.woken_at > since.0 || wanted == 0 || self.room() >= wanted {
            drop(waiters);
            waiter.inner.wake();
            return;
        }
        let waiting = &mut waiters.waiting;
        waiting.retain(|w| !w.gone());
        if !waiting.iter().any(|w| Arc::ptr_eq(w, &waiter.inner)) {
            waiting.push(waiter.inner.clone());
        }
    }

    /// The bytes that still fit.
    fn room(&self) -> usize {
        self.inner.limit.saturating_sub(self.used())
    }

    /// Takes as much of `want` as fits, or nothing. Outside this module
    /// only a holder that keeps its own count calls it, as rustls's charges
    /// do ([`services::tls`](fictionet::stdlib::services::tls)), and gives
    /// the bytes back with [`release`](Self::release).
    pub(crate) fn take(&self, want: RangeInclusive<usize>) -> Option<usize> {
        if *want.end() == 0 {
            return (*want.start() == 0).then_some(0);
        }
        self.take_with(*want.start(), |room| {
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
        let taken = self.take_with(units.start().saturating_mul(unit), |room| {
            let take = (*units.end()).min(room / unit);
            (take >= *units.start()).then_some(take * unit)
        })?;
        Some(taken / unit)
    }

    /// Takes what `fits` says of the room left, or nothing when it says
    /// nothing fits, which happens only while less than `need` bytes fit.
    fn take_with(&self, need: usize, fits: impl Fn(usize) -> Option<usize>) -> Option<usize> {
        if let Some(taken) = self.try_take(&fits) {
            return Some(taken);
        }
        // No room. Count the refusal and note what it needs before trying
        // once more: a release that frees room after the first try either
        // comes before this try, which then takes the room, or sees the
        // need and wakes the runners once there is room for it.
        self.inner.refusals.fetch_add(1, Ordering::SeqCst);
        let _ = self
            .inner
            .wanted
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |wanted| {
                (wanted == 0 || need < wanted).then_some(need)
            });
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

    /// Gives back `bytes`, waking the runners if that leaves room for the
    /// least that a charge refused since they were last woken needed.
    pub(crate) fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let used = self.inner.used.fetch_sub(bytes, Ordering::SeqCst) - bytes;
        let room = self.inner.limit.saturating_sub(used);
        let enough = self
            .inner
            .wanted
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |wanted| {
                (wanted != 0 && wanted <= room).then_some(0)
            });
        if enough.is_err() {
            return;
        }
        let waiting = {
            let mut waiters = self.inner.waiters.lock();
            waiters.woken_at = self.inner.refusals.load(Ordering::SeqCst);
            std::mem::take(&mut waiters.waiting)
        };
        for waiter in waiting {
            waiter.wake();
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
    pub(crate) fn nothing(budget: &Budget) -> Charge {
        Charge {
            budget: budget.clone(),
            now: 0,
        }
    }

    /// A charge of `bytes` that `budget` already counts, taken over from
    /// a holder that ended its own charge without giving them back, as
    /// rustls's charges do when bytes leave a connection. The budget's
    /// total does not change.
    pub(crate) fn adopt(budget: &Budget, bytes: usize) -> Charge {
        Charge {
            budget: budget.clone(),
            now: bytes,
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

    /// A waiter whose wakes `count` counts.
    fn waiter(count: &Arc<Count>) -> Waiter {
        Waiter::new(Waker::from(count.clone()))
    }

    #[test]
    fn a_release_after_a_refusal_wakes_each_waiting_runner_once() {
        let budget = Budget::new(8);
        let held = budget.charge(8).unwrap();
        let (a, b) = (Arc::new(Count::default()), Arc::new(Count::default()));
        let (wake_a, wake_b) = (waiter(&a), waiter(&b));
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
        let waker = waiter(&count);
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

    /// Memory that comes and goes in amounts too small for the refused
    /// charge wakes nothing, however often it does; the release that
    /// leaves room for it wakes the waiter once.
    #[test]
    fn a_release_wakes_only_when_it_leaves_room_for_the_refused_charge() {
        let budget = Budget::new(64);
        let mut hog = budget.charge(40).unwrap();
        let mut churn = budget.charge(budget.limit() - hog.bytes()).unwrap();
        let count = Arc::new(Count::default());
        let waker = waiter(&count);
        let need = 32;
        let mark = budget.refusals();
        assert!(budget.charge(need).is_none());
        budget.wake_when_freed(&waker, mark);
        let churned = churn.bytes();
        for _ in 0..100 {
            churn.shrink_to(0);
            assert!(budget.limit() - budget.used() < need);
            assert!(churn.grow_to(churned));
        }
        assert_eq!(count.woken(), 0, "no release left room for the charge");
        // Less than the room needed, then enough.
        hog.shrink_to(budget.limit() - churned - need + 1);
        assert!(budget.limit() - budget.used() < need);
        assert_eq!(count.woken(), 0);
        hog.shrink_to(hog.bytes() - 1);
        assert!(budget.limit() - budget.used() >= need);
        assert_eq!(count.woken(), 1);
        let charge = budget.charge(need).unwrap();
        drop((hog, churn, charge));
        assert_eq!(count.woken(), 1, "woken once");
    }

    /// A charge larger than the limit can never fit, so no release wakes
    /// anyone for it.
    #[test]
    fn a_charge_past_the_limit_wakes_nothing() {
        let budget = Budget::new(16);
        let held = budget.charge(8).unwrap();
        let count = Arc::new(Count::default());
        let waker = waiter(&count);
        let mark = budget.refusals();
        assert!(budget.charge(budget.limit() + 1).is_none());
        budget.wake_when_freed(&waker, mark);
        drop(held);
        assert_eq!(budget.used(), 0);
        assert_eq!(count.woken(), 0);
    }

    /// A waiter that asks again adds nothing to the list, and one whose
    /// owner dropped it is never woken and leaves at the next registration.
    #[test]
    fn a_kept_waiter_waits_once_and_a_dropped_one_leaves() {
        let waiting = |budget: &Budget| budget.inner.waiters.lock().waiting.len();
        let budget = Budget::new(8);
        let held = budget.charge(8).unwrap();
        let (a, b) = (Arc::new(Count::default()), Arc::new(Count::default()));
        let (wake_a, wake_b) = (waiter(&a), waiter(&b));
        let mark = budget.refusals();
        assert!(budget.charge(1).is_none());
        for _ in 0..10 {
            budget.wake_when_freed(&wake_a, mark);
        }
        assert_eq!(waiting(&budget), 1);
        drop(wake_a);
        budget.wake_when_freed(&wake_b, mark);
        assert_eq!(waiting(&budget), 1, "the dropped waiter left");
        drop(held);
        assert_eq!((a.woken(), b.woken()), (0, 1));
        assert_eq!(waiting(&budget), 0);
    }
}
