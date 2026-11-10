//! The lifetime of work a layer issues.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The lifetime of work issued by a layer. Dropping or cancelling it makes
/// every outstanding lease invalid; the runner drops the work before polling.
pub struct WorkOwner {
    live: Arc<AtomicBool>,
}

impl WorkOwner {
    /// A new live owner.
    pub fn new() -> Self {
        Self {
            live: Arc::new(AtomicBool::new(true)),
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

    /// Makes this a new live owner, as [`new`](Self::new) makes one, for
    /// an owner that issues work for one lifetime after another. Its old
    /// lifetime ends. When no work of it is still out, its place is used
    /// again and nothing is allocated; otherwise that work keeps it,
    /// cancelled, and the new lifetime gets a place of its own.
    pub fn renew(&mut self) {
        match Arc::get_mut(&mut self.live) {
            Some(live) => *live.get_mut() = true,
            None => {
                self.cancel();
                self.live = Arc::new(AtomicBool::new(true));
            }
        }
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
    live: Arc<AtomicBool>,
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

    /// A renewed owner's new work is live, and work of its old lifetime
    /// stays cancelled however the owner is renewed: with that work still
    /// out, or after it was dropped.
    #[test]
    fn work_of_a_renewed_owners_old_lifetime_stays_cancelled() {
        let mut owner = WorkOwner::new();
        let old = owner.own(());
        owner.cancel();
        owner.renew();
        assert!(old.cancelled(), "work still out keeps the old lifetime");
        let new = owner.own(());
        assert!(!new.cancelled());
        owner.renew();
        assert!(new.cancelled(), "renewing ends the lifetime before");
        drop((old, new));
        owner.cancel();
        owner.renew();
        let newer = owner.own(());
        assert!(!newer.cancelled(), "a place nothing holds is live again");
    }
}
