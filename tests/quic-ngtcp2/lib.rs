//! The QUIC Interop Runner's cases over QUIC version 2, between the SDK's
//! QUIC layer and ngtcp2, on a simulated link in virtual time.
//!
//! ngtcp2, nghttp3 and OpenSSL come from the system. This crate has its own
//! test binary, apart from the quiche crate's BoringSSL, since both define
//! the same OpenSSL symbols.

#[cfg(all(test, not(target_arch = "wasm32")))]
mod network;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod ngtcp2;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod sdk;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod cases;
