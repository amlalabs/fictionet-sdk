//! Host HTTP and DNS transports and optional guest-only raw Ethernet I/O.
//! [`dns::Live`] puts a world's DNS questions to real servers.
//!
//! The `virtio-net` feature adds a polling VFIO driver for a dedicated modern
//! virtio network device in an explicitly opted-in QEMU guest.

#[cfg(all(target_os = "linux", feature = "virtio-net"))]
pub mod virtio;

#[cfg(all(target_os = "linux", feature = "virtio-net"))]
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
