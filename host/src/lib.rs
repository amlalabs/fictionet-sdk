//! Host HTTP and DNS transports and optional guest-only raw Ethernet I/O.
//! [`dns::Internet`] puts a world's DNS lookups to real servers.
//!
//! The `virtio-net` feature adds a polling VFIO driver for a dedicated modern
//! virtio network device in an explicitly opted-in QEMU guest.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

#[cfg(all(target_os = "linux", feature = "tun"))]
#[allow(
    unsafe_code,
    reason = "Linux TUN configuration and descriptor registration"
)]
pub mod tun;

#[cfg(all(target_os = "linux", feature = "virtio-net"))]
#[allow(unsafe_code, reason = "VFIO mappings and volatile device access")]
pub mod virtio;

#[cfg(all(not(target_arch = "wasm32"), feature = "raw-ethernet"))]
pub mod raw;

#[cfg(all(target_os = "linux", feature = "virtio-net"))]
pub use virtio::{PciAddress, VirtioNet};

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
