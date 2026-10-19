/*! Specialized containers.

The `storage` module provides containers for use in other modules.
The containers support both borrowed buffers and owned heap allocations.
*/

mod assembler;
mod ring_buffer;

pub use self::assembler::Assembler;
pub use self::ring_buffer::RingBuffer;

/// A trait for setting a value to a known state.
///
/// In-place analog of Default.
pub trait Resettable {
    fn reset(&mut self);
}

/// Error returned when enqueuing into a full buffer.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Full;

/// Error returned when dequeuing from an empty buffer.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Empty;
