//! Synchronization without mutex poisoning.

#[cfg(not(feature = "std"))]
use std::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

/// A mutex whose lock operation returns a guard without a poison error.
///
/// With `std`, this uses the standard library mutex and recovers poisoned
/// guards. Without `std`, it spins until the lock becomes available.
pub struct Mutex<T: ?Sized> {
    #[cfg(feature = "std")]
    inner: std::sync::Mutex<T>,
    #[cfg(not(feature = "std"))]
    locked: AtomicBool,
    #[cfg(not(feature = "std"))]
    inner: UnsafeCell<T>,
}

#[cfg(feature = "std")]
pub use std::sync::MutexGuard;

/// Exclusive access to a mutex's value. Dropping the guard releases the lock.
#[cfg(not(feature = "std"))]
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
    // Match the standard guard's thread affinity and Sync bound.
    marker: std::marker::PhantomData<std::sync::MutexGuard<'a, T>>,
}

// Only the lock holder can access the value; transferring it requires Send.
#[cfg(not(feature = "std"))]
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
#[cfg(not(feature = "std"))]
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Creates a mutex holding `value`.
    pub const fn new(value: T) -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std::sync::Mutex::new(value),
            #[cfg(not(feature = "std"))]
            locked: AtomicBool::new(false),
            #[cfg(not(feature = "std"))]
            inner: UnsafeCell::new(value),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Waits for exclusive access to the value.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        #[cfg(feature = "std")]
        {
            self.inner.lock().unwrap_or_else(|e| e.into_inner())
        }
        #[cfg(not(feature = "std"))]
        {
            while self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                while self.locked.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            }
            MutexGuard {
                mutex: self,
                marker: std::marker::PhantomData,
            }
        }
    }

    /// Returns a guard if the lock is available, without waiting.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        #[cfg(feature = "std")]
        {
            match self.inner.try_lock() {
                Ok(guard) => Some(guard),
                Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            }
        }
        #[cfg(not(feature = "std"))]
        {
            self.locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .ok()
                .map(|_| MutexGuard {
                    mutex: self,
                    marker: std::marker::PhantomData,
                })
        }
    }

    /// Borrows the value exclusively without acquiring the lock.
    pub fn get_mut(&mut self) -> &mut T {
        #[cfg(feature = "std")]
        {
            self.inner.get_mut().unwrap_or_else(|e| e.into_inner())
        }
        #[cfg(not(feature = "std"))]
        {
            self.inner.get_mut()
        }
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

#[cfg(not(feature = "std"))]
impl<T: ?Sized> std::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // This guard holds the lock until drop.
        unsafe { &*self.mutex.inner.get() }
    }
}
#[cfg(not(feature = "std"))]
impl<T: ?Sized> std::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // The lock and mutable guard provide exclusive access.
        unsafe { &mut *self.mutex.inner.get() }
    }
}
#[cfg(not(feature = "std"))]
impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
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
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            *mutex.lock() = 7;
            panic!("release guard");
        }));
        assert_eq!(*mutex.lock(), 7);
    }
}
