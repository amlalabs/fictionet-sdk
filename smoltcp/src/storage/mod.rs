//! Out-of-order segment tracking, and the byte ring the socket kept before
//! it retained chunks, kept only as the model its stores are checked against.

mod assembler;
#[cfg(test)]
#[path = "../../../verification/tcp-store/ring.rs"]
mod ring_buffer;

pub(crate) use self::assembler::Assembler;
#[cfg(test)]
pub(crate) use self::ring_buffer::RingBuffer;
