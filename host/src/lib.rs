//! Host transports for worlds: the HTTP client behind the core's
//! explicitly injected web proxy, and [`dns::Live`], which puts a world's
//! DNS lookups to real servers.

#[cfg(not(target_arch = "wasm32"))]
fictionet::cfg_web_proxy! {
    mod client;
    pub use client::Client;
}

#[cfg(not(target_arch = "wasm32"))]
pub mod dns;
