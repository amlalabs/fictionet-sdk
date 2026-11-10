use std::sync::Arc;

use crate::budget::{Budget, Charge};
use crate::chunk::{Backing, Chunk, Reservation};
use crate::sync::Mutex;

/// Backings of one size, kept for reuse: a [`Chunk`] taken from a pool
/// goes back to it whole, header and bytes, when its last piece is
/// dropped, so a steady exchange takes the same backings again and
/// allocates nothing.
///
/// Every backing a pool made is paid for at its full size by exactly one
/// budget at every moment. A taken one is paid by the taker's budget, or
/// by whoever [admitted](Chunk::repay) it since. A free one is paid by the
/// pool's budget, which also pays for the free list's places. When a
/// backing comes back paid by another budget, the pool's budget is charged
/// first and the other's charge goes after; if the pool's budget refuses,
/// or the free list already holds `most`, the backing is freed instead. So
/// the pool is a cache and never a limit: [`take`](Self::take) makes a new
/// backing when none is free, and the budgets are the limits.
///
/// A pool may also keep a reserve for blocks that must go out whatever the
/// data budget says ([`reserve_control`](Self::reserve_control),
/// [`take_control`](Self::take_control)): bytes of its budget charged in
/// advance, which free backings count toward.
///
/// Cloning shares the pool. Backings still taken when the last clone is
/// dropped are freed by their last piece.
#[derive(Clone)]
pub struct Pool {
    shared: Arc<PoolShared>,
}

/// What a pool and the backings it made share.
pub(crate) struct PoolShared {
    /// The bytes of every backing.
    slot: usize,
    /// The most free backings kept.
    most: usize,
    /// The pool's own view of its owner's budget, so that a refusal of
    /// what the pool charges is not taken for its owner's.
    budget: Budget,
    state: Mutex<State>,
}

struct State {
    free: Vec<Arc<Backing>>,
    /// Pays for every free backing and the control reserve: at least
    /// `free.len() * slot` at every moment, and at least `floor` after a
    /// refill that succeeded.
    paid: Charge,
    /// The bytes kept for control blocks.
    floor: usize,
    /// Pays for the free list's places, charged when it first keeps one.
    places: Charge,
}

impl State {
    /// What `paid` must hold with `free` free backings: their bytes, and
    /// the reserve.
    fn keep(&self, free: usize, slot: usize) -> usize {
        self.floor.max(free * slot)
    }

    /// Pays for the free list's `most` places through `budget`, a view of
    /// the pool's budget, and makes them, once. Refuses, changing nothing,
    /// when the budget has no room or is another budget.
    fn reserve_places(&mut self, budget: &Budget, most: usize) -> bool {
        if self.free.capacity() >= most {
            return true;
        }
        let want = most * size_of::<Arc<Backing>>();
        let short = want.saturating_sub(self.places.bytes());
        if !budget.same(self.places.budget()) {
            return false;
        }
        let Some(charge) = budget.charge(short) else {
            return false;
        };
        if self.places.absorb(charge).is_err() {
            return false;
        }
        let more = most - self.free.len();
        self.free.reserve_exact(more);
        true
    }

    /// What `paid` holds past what it must, split off to go back once the
    /// lock is let go.
    fn surplus(&mut self, slot: usize) -> Option<Charge> {
        let keep = self.keep(self.free.len(), slot);
        let over = self
            .paid
            .bytes()
            .checked_sub(keep)
            .filter(|&over| over > 0)?;
        self.paid.split(over)
    }
}

impl Pool {
    /// A pool of backings of `slot` bytes that keeps at most `most` of them
    /// free, paying for what it keeps from `budget`. Nothing is allocated
    /// or charged yet.
    pub fn new(budget: &Budget, slot: usize, most: usize) -> Pool {
        let budget = budget.view();
        Pool {
            shared: Arc::new(PoolShared {
                slot,
                most,
                state: Mutex::new(State {
                    free: Vec::new(),
                    paid: Charge::nothing(&budget),
                    floor: 0,
                    places: Charge::nothing(&budget),
                }),
                budget,
            }),
        }
    }

    /// The bytes of every backing.
    pub fn slot(&self) -> usize {
        self.shared.slot
    }

    /// How many backings are free now.
    pub fn free(&self) -> usize {
        self.shared.state.lock().free.len()
    }

    /// The bytes the pool's budget pays for now: free backings, the
    /// control reserve, and the free list's places.
    pub fn charged(&self) -> usize {
        let state = self.shared.state.lock();
        state.paid.bytes() + state.places.bytes()
    }

    /// One backing, empty, with its cursor at `headroom`, paid for at its
    /// full size by `budget`. A free one is taken when there is one: its
    /// payment moves to `budget`, charged before the pool's lets go. A new
    /// one is charged before it is allocated. `None`, changing nothing,
    /// when `budget` refuses or `headroom` is past the slot. Never zeroes:
    /// the bytes are written before they are read.
    pub fn take(&self, budget: &Budget, headroom: usize) -> Option<Chunk> {
        let shared = &self.shared;
        let slot = shared.slot;
        if headroom > slot {
            return None;
        }
        let mut state = shared.state.lock();
        let Some(backing) = state.free.pop() else {
            drop(state);
            let charge = budget.charge(slot)?;
            let backing = Backing::pooled(slot, Arc::downgrade(shared));
            return Some(Self::taken(Arc::new(backing), charge, headroom));
        };
        let keep = state.keep(state.free.len(), slot);
        if budget.same(&shared.budget) && state.paid.bytes() >= keep + slot {
            // Within one budget the payment moves and the total does not.
            let charge = state.paid.split(slot).expect("paid holds the slot");
            drop(state);
            return Some(Self::taken(backing, charge, headroom));
        }
        let Some(charge) = budget.charge(slot) else {
            state.free.push(backing);
            return None;
        };
        let surplus = state.surplus(slot);
        drop(state);
        drop(surplus);
        Some(Self::taken(backing, charge, headroom))
    }

    /// One backing as [`take`](Self::take) gives it, paid from the control
    /// reserve or a free backing's payment instead of a budget, for a block
    /// that must go out whatever the data budget says. `None` when the
    /// reserve and the free backings are spent.
    pub fn take_control(&self, headroom: usize) -> Option<Chunk> {
        let shared = &self.shared;
        let slot = shared.slot;
        if headroom > slot {
            return None;
        }
        let mut state = shared.state.lock();
        let charge = state.paid.split(slot)?;
        let free = state.free.pop();
        drop(state);
        let backing =
            free.unwrap_or_else(|| Arc::new(Backing::pooled(slot, Arc::downgrade(shared))));
        Some(Self::taken(backing, charge, headroom))
    }

    /// Keeps `slots` backings' worth of the pool's budget for
    /// [`take_control`](Self::take_control), charged now through `budget`,
    /// a view of the pool's own budget, so that a refusal is recorded where
    /// its caller looks. Free backings count toward it. Refuses, changing
    /// nothing, when the budget has no room or is another budget.
    #[must_use = "a refused reserve keeps nothing for control blocks"]
    pub fn reserve_control(&self, budget: &Budget, slots: usize) -> bool {
        let Some(floor) = slots.checked_mul(self.shared.slot) else {
            return false;
        };
        let mut state = self.shared.state.lock();
        let (floor_before, paid_before) = (state.floor, state.paid.bytes());
        state.floor = floor;
        if !Self::top_up(&mut state, budget, self.shared.slot) {
            state.floor = floor_before;
            return false;
        }
        // The reserve's blocks come back to the free list, so its places
        // are paid for now too; without room for them the top-up goes back.
        if !state.reserve_places(budget, self.shared.most) {
            state.floor = floor_before;
            let topped = state.paid.bytes() - paid_before;
            let undone = state.paid.split(topped);
            drop(state);
            drop(undone);
            return false;
        }
        let surplus = state.surplus(self.shared.slot);
        drop(state);
        drop(surplus);
        true
    }

    /// Charges the control reserve back up through `budget`, after control
    /// blocks it paid for left with their payment. Refuses, changing
    /// nothing, when the budget has no room or is another budget.
    #[must_use = "a refused refill leaves the reserve short"]
    pub fn refill(&self, budget: &Budget) -> bool {
        let mut state = self.shared.state.lock();
        Self::top_up(&mut state, budget, self.shared.slot)
    }

    /// Charges what `paid` lacks of what it must hold through `budget`.
    fn top_up(state: &mut State, budget: &Budget, slot: usize) -> bool {
        let keep = state.keep(state.free.len(), slot);
        let Some(short) = keep.checked_sub(state.paid.bytes()).filter(|&s| s > 0) else {
            return true;
        };
        if !budget.same(state.paid.budget()) {
            return false;
        }
        let Some(charge) = budget.charge(short) else {
            return false;
        };
        state.paid.absorb(charge).is_ok()
    }

    /// A backing paid by `charge`, as a chunk at `headroom`.
    fn taken(mut backing: Arc<Backing>, charge: Charge, headroom: usize) -> Chunk {
        let inner = Arc::get_mut(&mut backing).expect("a free backing has no other holder");
        inner.reservation = Some(Reservation::Own(charge));
        Chunk::pooled(backing, headroom)
    }
}

impl PoolShared {
    /// Takes back a backing whose last piece was dropped. It lets go of
    /// what it held, and its payment moves to the pool's budget: within
    /// that budget the charge moves, from another the pool's budget is
    /// charged first. It is freed instead when the free list is full or
    /// busy, or the pool's budget refuses. Never waits: a list another
    /// thread holds means a plain free.
    pub(crate) fn recycle(&self, mut backing: Arc<Backing>) {
        let inner = Arc::get_mut(&mut backing).expect("only the last piece recycles");
        // Dropped once the lock is let go, as is every charge given back.
        let _held = inner.held.take();
        let reservation = inner.reservation.take();
        let Some(mut state) = self.state.try_lock() else {
            return;
        };
        if state.free.len() >= self.most {
            return;
        }
        if !state.reserve_places(&self.budget, self.most) {
            return;
        }
        let (paid, stale) = match reservation {
            Some(Reservation::Own(charge))
                if charge.budget().same(&self.budget) && charge.bytes() == self.slot =>
            {
                (charge, None)
            }
            other => match self.budget.charge(self.slot) {
                Some(charge) => (charge, other),
                None => {
                    drop(state);
                    return;
                }
            },
        };
        state
            .paid
            .absorb(paid)
            .expect("both charges are on the pool's budget");
        state.free.push(backing);
        let surplus = state.surplus(self.slot);
        drop(state);
        drop((stale, surplus));
    }
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("slot", &self.shared.slot)
            .field("most", &self.shared.most)
            .finish_non_exhaustive()
    }
}
