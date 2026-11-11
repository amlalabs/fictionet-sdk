//! Host HTTP and DNS transports, and a raw Ethernet attachment.
//! [`dns::Internet`] puts a world's DNS lookups to real servers.
//!
//! The `raw-ethernet` feature adds [`raw`]: whole Ethernet frames between a
//! world and the code that drives a network card. The `af-xdp` feature
//! adds [`xdp`], which drives one Linux interface through native XDP and an
//! AF_XDP socket, and `raw::RawPump`, which runs it for a world.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

#[cfg(all(not(target_arch = "wasm32"), feature = "raw-ethernet"))]
pub mod raw;

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
#[allow(
    unsafe_code,
    reason = "bpf(2), AF_XDP socket options, shared ring memory and ethtool ioctls"
)]
pub mod xdp;

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
