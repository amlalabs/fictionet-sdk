use core::task::Waker;

/// Utility struct to register and wake a waker.
#[derive(Debug)]
pub(crate) struct WakerRegistration {
    waker: Option<Waker>,
}

impl WakerRegistration {
    pub(crate) const fn new() -> Self {
        Self { waker: None }
    }

    /// Registers a waker and returns a displaced waker for release by the caller.
    pub(crate) fn register(&mut self, w: &Waker) -> Option<Waker> {
        match self.waker {
            Some(ref old) if old.will_wake(w) => None,
            _ => self.waker.replace(w.clone()),
        }
    }

    /// Wake the registered waker, if any.
    pub(crate) fn wake(&mut self) {
        if let Some(w) = self.waker.take() {
            w.wake()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Wake;

    #[test]
    fn replacement_transfers_the_old_waker_to_the_owner() {
        struct CheckDrop(Arc<AtomicBool>);
        impl Wake for CheckDrop {
            fn wake(self: Arc<Self>) {
                panic!("replacing or releasing a waiter must not wake it");
            }
        }
        impl Drop for CheckDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(CheckDrop(dropped.clone())));
        let mut registration = WakerRegistration::new();
        assert!(registration.register(&waker).is_none());
        assert!(registration.register(&waker).is_none());
        drop(waker);
        let old = registration.register(Waker::noop());
        assert!(!dropped.load(Ordering::SeqCst));
        drop(old);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
