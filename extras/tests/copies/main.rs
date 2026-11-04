//! Copies of real DNS servers: learned zones and what they answer, the
//! authoritative engine running copies, copies resolved in memory, and
//! the mirror that places copies at the real servers' addresses on a
//! simulated network.

mod engine;
mod learned;
mod memory;
mod mirror;
mod slices;
