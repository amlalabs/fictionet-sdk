//! Code the example worlds share: the JSON Lines log, the projection of
//! network events into it, header lookup, the Python backend's startup, the
//! quick-start world's sites, and hyper on simulated connections.

pub mod backend_process;
pub mod events;
pub mod headers;
pub mod hyper_io;
pub mod log;

#[cfg(not(target_arch = "wasm32"))]
fictionet::cfg_std! {
    pub mod web_world;
}
