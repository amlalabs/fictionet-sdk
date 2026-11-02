//! The DNS engines in `services::dns`, driven directly with no runtime.
//! The internet presets run on a simulated network. The acceptance tests
//! resolve through a seeded test internet in memory, on packets, and from
//! recordings, and probe it the way an agent with `dig` would.

mod authority;
mod cache;
mod internet;
mod memory;
mod probes;
mod resolver;
mod signed;
mod slices;
mod zone;
