//! The [relay protocol](crate::proto): its messages, and the
//! local transport, a Unix `SOCK_SEQPACKET` socket with one message per
//! datagram.
//!
//! Shared by [`listen`](crate::listen) and the `fictionet attach` binary.
//! Not part of the public API: it is public only so that the binary can use
//! it, and may change at any time.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

pub use crate::packet_queue::PacketQueue;

mod wire;
pub use wire::*;

/// Unix `SOCK_SEQPACKET` sockets: the local transport.
pub mod unix;

/// A blocking observer: connects to a world socket with an `observe`
/// hello, sends requests, and reads replies. Used by `fictionet observe`,
/// `fictionet dashboard`, and tests.
pub mod observer;
