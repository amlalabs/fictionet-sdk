//! Synchronization without mutex poisoning.

pub use std::sync::MutexGuard;

/// A mutex whose lock operation returns a guard without a poison error.
pub struct Mutex<T: ?Sized> {
    inner: std::sync::Mutex<T>,
}

impl<T> Mutex<T> {
    /// Creates a mutex holding `value`.
    pub const fn new(value: T) -> Self {
        Self {
            inner: std::sync::Mutex::new(value),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Waits for exclusive access to the value.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Returns a guard if the lock is available, without waiting.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        match self.inner.try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    /// Borrows the value exclusively without acquiring the lock.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut().unwrap_or_else(|e| e.into_inner())
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized + std::fmt::Debug> std::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mutex").finish_non_exhaustive()
    }
}

/// The waker of one consumer that waits for producers, and a flag that says
/// it is there, so that a producer finding the flag down takes no lock.
///
/// The consumer looks for work, [`park`](Parked::park)s when it found none,
/// then looks once more before it returns `Pending`. A producer publishes
/// its work, then calls [`wake`](Parked::wake). The two fences between
/// those steps make the second look see the work, or the producer see the
/// flag: no wake is lost. While work keeps coming, the consumer never parks
/// and neither side locks.
#[derive(Default)]
pub(crate) struct Parked {
    parked: std::sync::atomic::AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
}

impl Parked {
    /// Leaves `waker` to be woken by the next [`wake`](Parked::wake). The
    /// caller looks for work once more after this.
    pub(crate) fn park(&self, waker: &std::task::Waker) {
        use std::sync::atomic::{Ordering, fence};
        let old = {
            let mut slot = self.waker.lock();
            let old = match &*slot {
                Some(w) if w.will_wake(waker) => None,
                _ => slot.replace(waker.clone()),
            };
            self.parked.store(true, Ordering::Relaxed);
            old
        };
        // Dropped outside the lock: dropping a waker can run any code.
        drop(old);
        fence(Ordering::SeqCst);
    }

    /// Wakes the parked consumer, if one is parked. The caller published
    /// its work before this.
    pub(crate) fn wake(&self) {
        use std::sync::atomic::{Ordering, fence};
        fence(Ordering::SeqCst);
        if !self.parked.load(Ordering::Relaxed) {
            return;
        }
        if let Some(waker) = self.take() {
            waker.wake();
        }
    }

    /// Takes the parked waker without waking it.
    pub(crate) fn take(&self) -> Option<std::task::Waker> {
        let mut slot = self.waker.lock();
        self.parked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        slot.take()
    }

    /// The lock that guards the waker, if it is free, for tests that hold
    /// it to show a path never takes it.
    #[cfg(test)]
    pub(crate) fn try_lock(&self) -> Option<std::sync::MutexGuard<'_, Option<std::task::Waker>>> {
        self.waker.try_lock()
    }
}

#[cfg(test)]
mod tests {
    use super::Mutex;

    #[test]
    fn guard_mutates_and_unlocks() {
        let mut mutex = Mutex::new(vec![1]);
        mutex.lock().push(2);
        assert_eq!(&*mutex.lock(), &[1, 2]);
        mutex.get_mut().push(3);
        assert_eq!(&*mutex.lock(), &[1, 2, 3]);
    }

    #[test]
    fn threads_serialize_updates() {
        let mutex = Mutex::new(0);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let mutex = &mutex;
                scope.spawn(move || {
                    for _ in 0..1000 {
                        *mutex.lock() += 1;
                    }
                });
            }
        });
        assert_eq!(*mutex.lock(), 4000);
    }

    #[test]
    fn panic_releases_lock() {
        let mutex = Mutex::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            *mutex.lock() = 7;
            panic!("release guard");
        }));
        assert!(result.is_err(), "the closure panics while holding the lock");
        assert_eq!(*mutex.lock(), 7);
    }
}
