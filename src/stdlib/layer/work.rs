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
