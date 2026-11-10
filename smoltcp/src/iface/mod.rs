//! Explicit TCP context and deterministic socket scheduling.

mod context;
mod socket_set;

pub use self::context::{Config, Context, InitialSeq};
pub use self::socket_set::{SocketHandle, SocketSet};
