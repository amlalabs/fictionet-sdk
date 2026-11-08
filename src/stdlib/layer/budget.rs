use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bytes that connections may hold, shared by everything charged to it:
/// one sandbox's connections in [`Net`](fictionet::stdlib::world::net::Net).
/// Cheap to clone; clones share the count.
///
/// A [`Charge`] holds part of it and gives it back when dropped. Charge
/// before growing: [`Budget::charge`] and [`Charge::set`] refuse, changing
/// nothing, when the total would pass the limit, so the limit holds at every
/// moment and not only when someone checks.
///
/// [`serve`](fictionet::stdlib::services::serve) charges each connection the
/// larger of its decoder's capacity and its read buffer, the decoder's held
/// state, the bytes read but not yet decoded, what the service and its
/// deferred work hold, and the reply bytes not yet written.
#[derive(Clone)]
pub struct Budget {
    inner: Arc<BudgetInner>,
}

struct BudgetInner {
    used: AtomicUsize,
    limit: usize,
}

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
            }),
        }
    }

    /// Bytes charged now.
    pub fn used(&self) -> usize {
        self.inner.used.load(Ordering::Relaxed)
    }

    /// The limit.
    pub fn limit(&self) -> usize {
        self.inner.limit
    }

    /// Moves a charge from `from` bytes to `to`. Refuses, changing
    /// nothing, if that would pass the limit.
    fn recharge(&self, from: usize, to: usize) -> bool {
        if to <= from {
            self.inner.used.fetch_sub(from - to, Ordering::Relaxed);
            return true;
        }
        let more = to - from;
        self.inner
            .used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(more).filter(|n| *n <= self.inner.limit)
            })
            .is_ok()
    }

    /// A charge of `bytes`, or `None` if they do not fit.
    pub fn charge(&self, bytes: usize) -> Option<Charge> {
        let mut charge = Charge {
            budget: self.clone(),
            now: 0,
        };
        charge.set(bytes).then_some(charge)
    }
}

/// Bytes charged to a [`Budget`], given back when dropped.
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
    /// The bytes charged now.
    pub fn bytes(&self) -> usize {
        self.now
    }

    /// Charges `to` bytes instead. Refuses, changing nothing, if that
    /// would take the budget past its limit; less always fits.
    pub fn set(&mut self, to: usize) -> bool {
        if to == self.now {
            return true;
        }
        if self.budget.recharge(self.now, to) {
            self.now = to;
            true
        } else {
            false
        }
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.recharge(self.now, 0);
    }
}
