//! The stdlib module tree compiled in a consumer crate.
//! Unit tests run in the SDK; this fixture only checks public dependencies.
#![cfg(not(test))]

#[path = "../../src/stdlib/mod.rs"]
pub mod stdlib;

fn main() {}
