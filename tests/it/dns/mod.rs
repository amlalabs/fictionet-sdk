//! The DNS engines in `services::dns`, driven directly with no runtime.
//! The internet presets run on a simulated network.

mod authority;
mod internet;
mod memory;
mod resolver;
mod zone;
