//! rustls's buffers paid from a connection's [`Budget`].
//!
//! The vendored rustls charges a [`BufferBudget`] before any of a
//! connection's buffers grows (see [`rustls::budget`]). A [`TlsBudget`] is
//! one: rustls takes and gives back bytes through the same count every
//! [`Charge`] uses, so a refusal wakes the runner when memory frees, as
//! every other refusal does.

use std::any::Any;
use std::sync::Arc;

use rustls::budget::{BufferBudget, BufferCharge};

use fictionet::stdlib::layer::{Budget, Charge};

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

/// The [`Charge`] that holds the bytes rustls handed over with bytes it took
/// out of a connection paid from a [`Budget`]. `None`, giving the bytes
/// back, for a charge on another kind of budget.
pub(crate) fn charge_of(charge: BufferCharge) -> Option<Charge> {
    let budget = (&**charge.budget() as &dyn Any)
        .downcast_ref::<TlsBudget>()?
        .0
        .clone();
    Some(Charge::adopt(&budget, charge.into_bytes()))
}
