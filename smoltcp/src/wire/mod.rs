//! IPv4, IPv6, and TCP packet parsing and construction.
//!
//! `Packet` types read and write fields in byte slices. `Repr` types validate
//! headers and emit them. Check packet lengths before reading fields; use
//! unchecked packet wrappers on output buffers before emitting headers.

mod field {
    pub type Field = core::ops::Range<usize>;
}
mod ip;
mod ipv4;
mod ipv6;
mod tcp;

use core::fmt;

pub use self::ip::{
    Address as IpAddress, Cidr as IpCidr, Endpoint as IpEndpoint,
    ListenEndpoint as IpListenEndpoint, Protocol as IpProtocol, Repr as IpRepr,
    Version as IpVersion, checksum,
};
pub(crate) use self::ipv4::AddressExt as Ipv4AddressExt;
pub use self::ipv4::{
    Address as Ipv4Address, Cidr as Ipv4Cidr, HEADER_LEN as IPV4_HEADER_LEN,
    MIN_MTU as IPV4_MIN_MTU, Packet as Ipv4Packet, Repr as Ipv4Repr,
};
pub(crate) use self::ipv6::AddressExt as Ipv6AddressExt;
pub use self::ipv6::{
    Address as Ipv6Address, Cidr as Ipv6Cidr, HEADER_LEN as IPV6_HEADER_LEN,
    MIN_MTU as IPV6_MIN_MTU, Packet as Ipv6Packet, Repr as Ipv6Repr,
};
pub use self::tcp::{
    Control as TcpControl, HEADER_LEN as TCP_HEADER_LEN, Packet as TcpPacket, Repr as TcpRepr,
    SeqNumber as TcpSeqNumber, TcpOption, TcpTimestampGenerator, TcpTimestampRepr,
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
