//! Host HTTP transport for the core's explicitly injected web proxy.

#[cfg(not(target_arch = "wasm32"))]
fictionet::cfg_web_proxy! {
    mod client;
    pub use client::Client;
}
