//! rustls's buffers paid from a connection's [`Budget`].
//!
//! The vendored rustls charges a [`BufferBudget`] before any of a
//! connection's buffers grows (see [`rustls::budget`]). A [`Budget`] is one:
//! rustls takes and gives back bytes through the same count every
//! [`Charge`] uses, so a refusal wakes the runner when memory frees, as
//! every other refusal does.

use std::any::Any;

use rustls::budget::{BufferBudget, BufferCharge};

use fictionet::stdlib::layer::{Budget, Charge};

impl BufferBudget for Budget {
    fn take(&self, bytes: usize) -> bool {
        Budget::take(self, bytes..=bytes).is_some()
    }

    fn give_back(&self, bytes: usize) {
        self.release(bytes);
    }
}

/// The [`Charge`] that holds the bytes rustls handed over with bytes it took
/// out of a connection paid from a [`Budget`]. `None`, giving the bytes
/// back, for a charge on another kind of budget.
pub(crate) fn charge_of(charge: BufferCharge) -> Option<Charge> {
    let budget = (&**charge.budget() as &dyn Any)
        .downcast_ref::<Budget>()?
        .clone();
    Some(Charge::adopt(&budget, charge.into_bytes()))
}
