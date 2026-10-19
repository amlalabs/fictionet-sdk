//! IPv4, IPv6, and TCP packet parsing and construction.
//!
//! `Packet` types read and write fields in byte slices. `Repr` types validate
//! headers and emit them. Check packet lengths before reading fields; use
//! unchecked packet wrappers on output buffers before emitting headers.

mod field {
    pub(super) type Field = core::ops::Range<usize>;
}
mod ip;
mod ipv4;
mod ipv6;
mod tcp;

use core::fmt;

pub use self::ip::{
    Address as IpAddress, Endpoint as IpEndpoint, ListenEndpoint as IpListenEndpoint,
};
pub(crate) use self::ip::{Protocol as IpProtocol, Repr as IpRepr, Version as IpVersion};
pub(crate) use self::ipv4::AddressExt as Ipv4AddressExt;
pub use self::ipv4::Packet as Ipv4Packet;
pub(crate) use self::ipv4::{
    Address as Ipv4Address, HEADER_LEN as IPV4_HEADER_LEN, Repr as Ipv4Repr,
};
pub(crate) use self::ipv6::AddressExt as Ipv6AddressExt;
pub(crate) use self::ipv6::{
    Address as Ipv6Address, HEADER_LEN as IPV6_HEADER_LEN, Packet as Ipv6Packet, Repr as Ipv6Repr,
};
pub use self::tcp::{Packet as TcpPacket, Repr as TcpRepr, TcpTimestampGenerator};

pub(crate) use self::tcp::{
    Control as TcpControl, HEADER_LEN as TCP_HEADER_LEN, SeqNumber as TcpSeqNumber,
    TcpTimestampRepr,
};

/// Parsing a packet failed.
///
/// Either it is malformed, or it is not supported by smoltcp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire::Error")
    }
}

pub type Result<T> = core::result::Result<T, Error>;
