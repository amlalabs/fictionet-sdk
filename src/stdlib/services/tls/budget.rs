//! rustls's buffers paid from a connection's [`Budget`].
//!
//! The vendored rustls charges a [`BufferBudget`] before any of a
//! connection's buffers grows (see [`rustls::budget`]). A [`Budget`] is one:
//! each buffer holds a [`Charge`] on it, so a refusal wakes the runner when
//! memory frees, as every other charge does.

use std::any::Any;

use rustls::budget::{BufferBudget, BufferCharge};

use fictionet::stdlib::layer::{Budget, Charge};

impl BufferBudget for Budget {
    fn open(&self) -> Box<dyn BufferCharge> {
        Box::new(Charge::nothing(self))
    }
}

impl BufferCharge for Charge {
    fn bytes(&self) -> usize {
        Charge::bytes(self)
    }

    fn grow_to(&mut self, to: usize) -> bool {
        Charge::grow_to(self, to)
    }

    fn shrink_to(&mut self, to: usize) {
        Charge::shrink_to(self, to);
    }

    fn split(&mut self, bytes: usize) -> Option<Box<dyn BufferCharge>> {
        Charge::split(self, bytes).map(|charge| Box::new(charge) as Box<dyn BufferCharge>)
    }

    fn absorb(&mut self, other: Box<dyn BufferCharge>) -> Result<(), Box<dyn Any + Send>> {
        let other = other.into_any().downcast::<Charge>()?;
        Charge::absorb(self, *other).map_err(|other| Box::new(other) as Box<dyn Any + Send>)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

/// The [`Charge`] rustls handed over with bytes it took out of a connection
/// paid from a [`Budget`]. `None` from a connection without one.
pub(crate) fn charge_of(charge: Option<Box<dyn BufferCharge>>) -> Option<Charge> {
    charge?
        .into_any()
        .downcast::<Charge>()
        .ok()
        .map(|charge| *charge)
}
