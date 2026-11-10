//! Explicit TCP context and deterministic socket scheduling.

mod context;
#[cfg(test)]
#[path = "../tests/interface/mod.rs"]
mod interface;
mod socket_set;

pub use self::context::{Config, Context, InitialSeq};
#[cfg(test)]
pub(crate) use self::interface::Interface;
pub use self::socket_set::{SocketHandle, SocketSet};
