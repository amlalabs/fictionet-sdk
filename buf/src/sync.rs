//! A mutex without poisoning: what it guards is consistent between any two
//! statements, so a panic elsewhere leaves nothing to recover.

use std::sync::{MutexGuard, TryLockError};

pub(crate) struct Mutex<T> {
    inner: std::sync::Mutex<T>,
}

impl<T> Mutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            inner: std::sync::Mutex::new(value),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, T> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The guard, unless another thread holds the lock.
    pub(crate) fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        match self.inner.try_lock() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(error)) => Some(error.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }
}
