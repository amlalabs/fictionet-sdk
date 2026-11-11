//! One network interface taken over through native XDP and an AF_XDP
//! socket in copy mode, built for the second ENA on an EC2 instance.
//!
//! [`XdpSocket::open`] checks the interface is not the management path,
//! sets it to MTU 1500 and one combined channel, and attaches a six-
//! instruction XDP program ([`program`]) that redirects every frame on
//! queue 0 to the socket and drops frames with no socket. Nothing is
//! pinned: the program, map, link and socket are file descriptors of the
//! process, so when the process exits, crashes included, the program comes
//! off the interface. [`crate::raw::RawPump`] runs the socket on a thread
//! and hands frames to a world's [`crate::raw::RawAttachment`].
//!
//! The eBPF bytecode, ring arithmetic, frame accounting and startup checks
//! are tested in-process. Loading the program and binding the socket need
//! the instance; see the crate README.

mod bpf;
mod datapath;
pub mod interface;
pub mod program;
pub(crate) mod pump;
mod ring;
mod socket;

use std::fmt;
use std::io;

pub use bpf::Rejected;
pub use interface::{Channels, Driver, InterfaceName, Refusal};
pub use socket::XdpSocket;

/// What [`XdpSocket::open`] attached. The attach mode is always native
/// (driver) XDP and the socket is always in copy mode: open fails rather
/// than settle for anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attached {
    pub interface: InterfaceName,
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub driver: Driver,
    pub mtu: u32,
    /// The receive queue the socket is bound to.
    pub queue: u32,
    pub channels: Channels,
}

/// The socket's loss counters, from `XDP_STATISTICS`, since it was bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XskStatistics {
    /// Frames dropped for any reason other than a full RX ring, a
    /// fill ring with no buffer among them.
    pub rx_dropped: u64,
    /// Frames dropped because the RX ring was full.
    pub rx_ring_full: u64,
    /// Times the kernel found the fill ring empty.
    pub rx_fill_ring_empty: u64,
    /// Invalid descriptors on the RX ring.
    pub rx_invalid: u64,
    /// Invalid descriptors the process put on the TX ring.
    pub tx_invalid: u64,
}

impl XskStatistics {
    /// Received frames the socket lost before the process saw them.
    pub fn rx_lost(&self) -> u64 {
        self.rx_dropped.saturating_add(self.rx_ring_full)
    }
}

/// The part of [`XdpSocket::open`] that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    ReadInterface,
    SetMtu,
    SetChannels,
    Umem,
    Socket,
    Rings,
    Bind,
    Map,
    Attach,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadInterface => "reading the interface",
            Self::SetMtu => "setting the MTU",
            Self::SetChannels => "setting one combined channel",
            Self::Umem => "registering the UMEM",
            Self::Socket => "creating the AF_XDP socket",
            Self::Rings => "mapping the AF_XDP rings",
            Self::Bind => "binding the socket in copy mode",
            Self::Map => "creating the socket map",
            Self::Attach => "attaching native XDP",
        })
    }
}

/// Why the interface was not taken over.
#[derive(Debug)]
pub enum OpenError {
    /// The startup checks refused the interface.
    Refused(Vec<Refusal>),
    /// The interface already has an XDP program or link. It is left alone.
    Occupied,
    /// The verifier refused the program.
    Rejected(Rejected),
    /// A system call failed.
    Io { stage: Stage, source: io::Error },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusals) => {
                f.write_str("refusing the interface:")?;
                for refusal in refusals {
                    write!(f, " {refusal};")?;
                }
                Ok(())
            }
            Self::Occupied => f.write_str("the interface already has an XDP program"),
            Self::Rejected(rejected) => write!(
                f,
                "the kernel refused the XDP program: {}; verifier log: {}",
                rejected.error, rejected.log
            ),
            Self::Io { stage, source } => write!(f, "{stage}: {source}"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Rejected(rejected) => Some(&rejected.error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod device;
