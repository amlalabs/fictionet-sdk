//! Bytes on their way through a Fictionet world, and what pays for them.
//!
//! One buffer type carries a packet from the wire to the code that reads
//! it: a [`Chunk`], a view of a backing that pieces share without copying.
//! A [`Budget`] limits the bytes a connection or a sandbox may hold, a
//! [`Charge`] holds part of it, and a chunk carries the charge that pays
//! for its backing. A [`Pool`] keeps backings of one size for reuse, whole,
//! so a steady exchange allocates nothing.
//!
//! The crate depends on nothing but the standard library, so the TCP stack
//! Fictionet vendors can hold chunks too. Fictionet re-exports it as
//! `fictionet::buf` and at `fictionet::stdlib::layer`.

mod budget;
mod chunk;
mod pool;
mod sync;

pub use budget::{Budget, Charge, Refusals, Starved, Waiter};
pub use chunk::{Chunk, Held};
pub use pool::Pool;

#[cfg(test)]
mod tests;

#[cfg(kani)]
#[path = "../../verification/buf/kani/mod.rs"]
mod proofs;
