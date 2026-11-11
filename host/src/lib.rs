//! Host HTTP and DNS transports, and a raw Ethernet attachment.
//! [`dns::Internet`] puts a world's DNS lookups to real servers.
//!
//! The `raw-ethernet` feature adds [`raw`]: whole Ethernet frames between a
//! world and the code that drives a network card.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

#[cfg(all(not(target_arch = "wasm32"), feature = "raw-ethernet"))]
pub mod raw;

#[cfg(not(target_arch = "wasm32"))]
fictionet::cfg_web_proxy! {
    mod client;
    pub use client::Client;
}

#[cfg(not(target_arch = "wasm32"))]
pub mod dns;

// Filesystem capacity has no standard library query; keep its FFI here.
#[cfg(all(target_os = "linux", feature = "filesystem"))]
#[allow(unsafe_code)]
pub mod filesystem;
