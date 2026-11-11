#![deny(unsafe_code)]
#![allow(clippy::match_like_matches_macro)]

//! Fictionet's fork of smoltcp 0.14.0.
//!
//! TCP sockets and IPv4/IPv6 packet representations. Fictionet supplies an
//! explicit context, simulation clock, initial sequence numbers, and packet emission.

#[macro_use]
mod macros;

pub mod iface;

pub mod socket;
mod storage;
pub mod time;
pub mod wire;

#[cfg(test)]
mod tests;

// The counting allocator and the cost recorder of the resource properties
// (verification/README.md), for the stores' costed sessions.
#[cfg(test)]
#[allow(unsafe_code)]
#[path = "../../verification/resources/alloc.rs"]
mod alloc;
#[cfg(test)]
#[path = "../../verification/resources/cost.rs"]
mod cost;

/// Counts what the code under a Kani proof allocates: see
/// verification/resources/kani/counting.rs.
#[cfg(kani)]
#[allow(unsafe_code)]
#[path = "../../verification/resources/kani/counting.rs"]
mod counting;
