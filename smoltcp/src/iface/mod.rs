//! TCP packet dispatch over an in-memory IP device.

mod interface;
mod socket_set;

pub use self::interface::{Config, InitialSeq, Interface, InterfaceInner as Context, PollResult};
pub use self::socket_set::{SocketHandle, SocketSet};
