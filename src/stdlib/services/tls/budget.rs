//! rustls's buffers paid from a connection's [`Budget`].
//!
//! The vendored rustls charges a [`BufferBudget`] before any of a
//! connection's buffers grows (see [`rustls::budget`]). A [`TlsBudget`] is
//! one: rustls takes and gives back bytes through the same count every
//! [`Charge`](fictionet::stdlib::layer::Charge) uses, so a refusal wakes the
//! runner when memory frees, as every other refusal does.

use std::sync::Arc;

use rustls::budget::BufferBudget;

use fictionet::stdlib::layer::Budget;

/// A connection's [`Budget`] as rustls charges it.
pub struct TlsBudget(Budget);

impl TlsBudget {
    /// `budget`, for a rustls connection to charge.
    pub fn of(budget: &Budget) -> Arc<dyn BufferBudget> {
        Arc::new(TlsBudget(budget.clone()))
    }
}

impl BufferBudget for TlsBudget {
    fn take(&self, bytes: usize) -> bool {
        self.0.take(bytes..=bytes).is_some()
    }

    fn give_back(&self, bytes: usize) {
        self.0.release(bytes);
    }
}
