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
