/*! Low-level packet access and construction.

The `wire` module deals with the packet *representation*. It provides two levels
of functionality.

 * First, it provides functions to extract fields from sequences of octets,
   and to insert fields into sequences of octets. This happens `Packet` family of
   structures, e.g. [Ipv4Packet].
 * Second, in cases where the space of valid field values is much smaller than the space
   of possible field values, it provides a compact, high-level representation
   of packet data that can be parsed from and emitted into a sequence of octets.
   This happens through the `Repr` family of structs and enums, e.g. [Ipv4Repr].

[Ipv4Packet]: struct.Ipv4Packet.html
[Ipv4Repr]: struct.Ipv4Repr.html

The functions in the `wire` module are designed for use together with `-Cpanic=abort`.

The `Packet` family of data structures guarantees that, if the `Packet::check_len()` method
returned `Ok(())`, then no accessor or setter method will panic; however, the guarantee
provided by `Packet::check_len()` may no longer hold after changing certain fields,
which are listed in the documentation for the specific packet.

The `Packet::new_checked` method is a shorthand for a combination of `Packet::new_unchecked`
and `Packet::check_len`.
When parsing untrusted input, it is *necessary* to use `Packet::new_checked()`;
so long as the buffer is not modified, no accessor will fail.
When emitting output, though, it is *incorrect* to use `Packet::new_checked()`;
the length check is likely to succeed on a zeroed buffer, but fail on a buffer
filled with data from a previous packet, such as when reusing buffers, resulting
in nondeterministic panics with some network devices but not others.
The buffer length for emission is not calculated by the `Packet` layer.

In the `Repr` family of data structures, the `Repr::parse()` method never panics
as long as `Packet::new_checked()` (or `Packet::check_len()`) has succeeded, and
the `Repr::emit()` method never panics as long as the underlying buffer is exactly
`Repr::buffer_len()` octets long.

# Examples

To emit an IP packet header into an octet buffer, and then parse it back:

```rust
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::*;
let repr = Ipv4Repr {
    src_addr:    Ipv4Address::new(10, 0, 0, 1),
    dst_addr:    Ipv4Address::new(10, 0, 0, 2),
    next_header: IpProtocol::Tcp,
    payload_len: 10,
    hop_limit:   64,
};
let mut buffer = vec![0; repr.buffer_len() + repr.payload_len];
{ // emission
    let mut packet = Ipv4Packet::new_unchecked(&mut buffer);
    repr.emit(&mut packet, &ChecksumCapabilities::default());
}
{ // parsing
    let packet = Ipv4Packet::new_checked(&buffer)
                            .expect("truncated packet");
    let parsed = Ipv4Repr::parse(&packet, &ChecksumCapabilities::default())
                          .expect("malformed packet");
    assert_eq!(repr, parsed);
}
```
*/

mod field {
    pub type Field = ::core::ops::Range<usize>;
}

pub mod pretty_print;

mod icmp;

mod icmpv4;

mod icmpv6;

pub(crate) mod ip;

pub(crate) mod ipv4;

pub(crate) mod ipv6;

mod ipv6ext_header;

mod ipv6fragment;

mod ipv6hbh;

mod ipv6option;

mod tcp;
mod udp;

use core::fmt;

use crate::phy::Medium;

pub use self::pretty_print::PrettyPrinter;

pub use self::ip::checksum;
pub use self::ip::{
    Address as IpAddress, Cidr as IpCidr, Endpoint as IpEndpoint,
    ListenEndpoint as IpListenEndpoint, Protocol as IpProtocol, Repr as IpRepr,
    Version as IpVersion,
};

pub use self::ipv4::{
    Address as Ipv4Address, Cidr as Ipv4Cidr, HEADER_LEN as IPV4_HEADER_LEN, Key as Ipv4FragKey,
    MIN_MTU as IPV4_MIN_MTU, MULTICAST_ALL_ROUTERS as IPV4_MULTICAST_ALL_ROUTERS,
    MULTICAST_ALL_SYSTEMS as IPV4_MULTICAST_ALL_SYSTEMS, Packet as Ipv4Packet, Repr as Ipv4Repr,
};

pub(crate) use self::ipv4::AddressExt as Ipv4AddressExt;

pub use self::ipv6::{
    Address as Ipv6Address, Cidr as Ipv6Cidr, HEADER_LEN as IPV6_HEADER_LEN,
    LINK_LOCAL_ALL_NODES as IPV6_LINK_LOCAL_ALL_NODES,
    LINK_LOCAL_ALL_ROUTERS as IPV6_LINK_LOCAL_ALL_ROUTERS, MIN_MTU as IPV6_MIN_MTU,
    Packet as Ipv6Packet, Repr as Ipv6Repr,
};

pub(crate) use self::ipv6::{AddressExt as Ipv6AddressExt, MulticastScope as Ipv6MulticastScope};

pub use self::ipv6option::{
    FailureType as Ipv6OptionFailureType, Ipv6Option, Ipv6OptionsIterator, Repr as Ipv6OptionRepr,
    RouterAlert as Ipv6OptionRouterAlert, Type as Ipv6OptionType,
};

pub use self::ipv6ext_header::{Header as Ipv6ExtHeader, Repr as Ipv6ExtHeaderRepr};

pub use self::ipv6fragment::{Header as Ipv6FragmentHeader, Repr as Ipv6FragmentRepr};

pub use self::ipv6hbh::{Header as Ipv6HopByHopHeader, Repr as Ipv6HopByHopRepr};

pub use self::icmpv4::{
    DstUnreachable as Icmpv4DstUnreachable, Message as Icmpv4Message, Packet as Icmpv4Packet,
    ParamProblem as Icmpv4ParamProblem, Redirect as Icmpv4Redirect, Repr as Icmpv4Repr,
    TimeExceeded as Icmpv4TimeExceeded,
};

pub use self::icmpv6::{
    DstUnreachable as Icmpv6DstUnreachable, Message as Icmpv6Message, Packet as Icmpv6Packet,
    ParamProblem as Icmpv6ParamProblem, Repr as Icmpv6Repr, TimeExceeded as Icmpv6TimeExceeded,
};

pub use self::icmp::Repr as IcmpRepr;

pub use self::udp::{HEADER_LEN as UDP_HEADER_LEN, Packet as UdpPacket, Repr as UdpRepr};

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

/// Address marker for an IP device without a hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HardwareAddress {
    #[default]
    Ip,
}

impl HardwareAddress {
    #[inline]
    pub(crate) fn medium(&self) -> Medium {
        match self {
            HardwareAddress::Ip => Medium::Ip,
        }
    }
}

impl core::fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HardwareAddress::Ip => write!(f, "no hardware addr"),
        }
    }
}
