//! Code the example worlds share: the JSON Lines log, the projection of
//! network events into it, header lookup, enum names, the Docker worlds'
//! command line, the quick-start world's sites, and hyper on simulated
//! connections.

pub mod args;
pub mod events;
pub mod headers;
pub mod hyper_io;
pub mod log;
pub mod names;

#[cfg(not(target_arch = "wasm32"))]
fictionet::cfg_std! {
    pub mod web_world;
    pub mod zscaler;
}
