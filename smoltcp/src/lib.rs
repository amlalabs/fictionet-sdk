#![deny(unsafe_code)]
// Keep explicit protocol predicate matches consistent with upstream.
#![allow(clippy::match_like_matches_macro)]

//! Fictionet's fork of smoltcp 0.14.0.
//!
//! TCP sockets, an in-memory IP interface, and IPv4/IPv6 packet handling.
//! Fictionet supplies the device, simulation clock, and seeded entropy.

extern crate alloc;

#[macro_use]
mod macros;
mod parsers;
mod rand;

pub mod config;

pub mod iface;

pub mod phy;

pub mod socket;
pub mod storage;
pub mod time;
pub mod wire;

#[cfg(test)]
mod tests;
