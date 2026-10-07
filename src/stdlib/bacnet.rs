//! BACnet/IP: reading and writing BVLC messages, NPDUs, APDUs and
//! application-tagged values, with no I/O.
//!
//! BACnet is how building automation talks: thermostats, air handlers,
//! chillers, lighting panels and door controllers report their readings and
//! take commands over it. BACnet/IP carries each message in one UDP
//! datagram, usually on port 47808 (0xBAC0). This module follows ASHRAE
//! Standard 135, Clause 6 (the network layer), Clause 20 (encoding) and
//! Annex J (BACnet/IP).
//!
//! A datagram has three layers, and each has a type here:
//!
//! - [`Bvlc`]: the BACnet Virtual Link Control header. It says whether the
//!   datagram is a unicast, a broadcast, a broadcast forwarded by a BBMD, or
//!   one of the BBMD's own table messages.
//! - [`Npdu`]: the network layer. It holds the priority, whether a reply
//!   is expected, and the source and destination networks when a router
//!   carries the message between BACnet networks.
//! - [`Apdu`]: the application layer. It is a request, an
//!   acknowledgment, an error, a reject or an abort. Each carries a service
//!   choice and that service's body.
//!
//! Service bodies are built from tagged values. [`Value`] reads and writes
//! the application-tagged primitives, and [`Tag`] reads any tag header,
//! including context tags and the opening and closing tags of constructed
//! data. The Who-Is and I-Am services, which a client uses to find devices,
//! are read and written in full by [`WhoIs`] and [`IAm`]. Every other
//! service body is kept as raw bytes. World code walks its fields with
//! [`ContextValue::read`], [`Tags`] and [`Values`]. Repeated application
//! values can use [`Stream<Values>`](fictionet::stdlib::codec::Stream).
//!
//! Nothing here reads a socket. A world that plays a BACnet device reads
//! each datagram from its UDP socket, passes it to [`Bvlc::parse`], reads
//! the NPDU and APDU inside, and sends back the bytes of its answer. Which
//! objects and properties the device has, and what they hold, is up to
//! world code. BACnet/IP runs over UDP, one message per datagram, so there
//! is no transport stream to assemble.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Writers refuse values that exceed limits or would change when read.
//! The destination stays unchanged on error.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::bacnet::{Apdu, Bvlc, IAm, Npdu, ObjectId, Segmentation, WhoIs, unconfirmed};
//!
//! // A Who-Is with no range, broadcast by a workstation to port 47808.
//! let datagram = [0x81, 0x0b, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08];
//! let bvlc = Bvlc::parse(&datagram).unwrap();
//! let npdu = Npdu::parse(bvlc.npdu().unwrap()).unwrap();
//! let apdu = Apdu::parse(npdu.apdu().unwrap()).unwrap();
//! let Apdu::UnconfirmedRequest { service, data } = &apdu else { panic!("not unconfirmed") };
//! assert_eq!(*service, unconfirmed::WHO_IS);
//! let who_is = WhoIs::parse(data).unwrap();
//!
//! // Device 1234 answers, since a Who-Is with no range asks every device.
//! assert!(who_is.matches(1234));
//! let i_am = IAm {
//!     device: ObjectId::device(1234),
//!     max_apdu: 1476,
//!     segmentation: Segmentation::NoSegmentation,
//!     vendor: 260,
//! };
//! let reply = Bvlc::OriginalBroadcastNpdu(npdu.reply(i_am.to_apdu().unwrap().to_bytes().unwrap()).to_bytes().unwrap());
//! assert_eq!(
//!     reply.to_bytes().unwrap(),
//!     [
//!         0x81, 0x0b, 0x00, 0x15, // BVLC: broadcast, 21 bytes in all
//!         0x01, 0x00, // NPDU: version 1, no addresses, normal priority
//!         0x10, 0x00, // APDU: unconfirmed request, I-Am
//!         0xc4, 0x02, 0x00, 0x04, 0xd2, // device 1234
//!         0x22, 0x05, 0xc4, // max APDU 1476
//!         0x91, 0x03, // no segmentation
//!         0x22, 0x01, 0x04, // vendor 260
//!     ]
//! );
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire, Reader, Truncated, Trailing};

use std::net::{Ipv4Addr, SocketAddrV4};

/// The UDP port BACnet/IP devices listen on, 0xBAC0.
pub const PORT: u16 = 47808;
/// The first byte of every BVLC header: BACnet/IP (Annex J).
pub const BVLC_TYPE: u8 = 0x81;
/// The length of the BVLC header: type, function and a 2-byte length.
pub const BVLC_HEADER_LEN: usize = 4;
/// The longest datagram read or written here: the most a UDP datagram over
/// IPv4 can carry. Readers and writers refuse larger values even when
/// they would fit the BVLC length field.
pub const MAX_MESSAGE: usize = 65_507;
/// The NPDU protocol version: always 1.
pub const NPDU_VERSION: u8 = 1;
/// The longest station address an NPDU can carry. Its length is one byte.
pub const MAX_MAC_LEN: usize = 255;
/// The longest APDU a BACnet/IP device can accept (max-APDU code 5).
pub const MAX_APDU: usize = 1476;
/// The longest contents of one tagged value read or written here. Longer
/// values are refused by [`Value::parse`] and [`Value::write`].
pub const MAX_VALUE_LEN: usize = MAX_MESSAGE;
/// The highest object instance number: 22 bits. The value 4194303 also
/// means "no instance" in some properties.
pub const MAX_INSTANCE: u32 = 0x3f_ffff;
/// The highest object type number: 10 bits.
pub const MAX_OBJECT_TYPE: u16 = 0x3ff;

/// BVLC function codes (Annex J.2).
pub mod function {
    #![allow(missing_docs)]
    pub const RESULT: u8 = 0x00;
    pub const WRITE_BROADCAST_DISTRIBUTION_TABLE: u8 = 0x01;
    pub const READ_BROADCAST_DISTRIBUTION_TABLE: u8 = 0x02;
    pub const READ_BROADCAST_DISTRIBUTION_TABLE_ACK: u8 = 0x03;
    pub const FORWARDED_NPDU: u8 = 0x04;
    pub const REGISTER_FOREIGN_DEVICE: u8 = 0x05;
    pub const READ_FOREIGN_DEVICE_TABLE: u8 = 0x06;
    pub const READ_FOREIGN_DEVICE_TABLE_ACK: u8 = 0x07;
    pub const DELETE_FOREIGN_DEVICE_TABLE_ENTRY: u8 = 0x08;
    pub const DISTRIBUTE_BROADCAST_TO_NETWORK: u8 = 0x09;
    pub const ORIGINAL_UNICAST_NPDU: u8 = 0x0a;
    pub const ORIGINAL_BROADCAST_NPDU: u8 = 0x0b;
    pub const SECURE_BVLL: u8 = 0x0c;
}

/// BVLC-Result codes (Annex J.2.1): 0 for success, or which request a BBMD
/// refused.
pub mod result {
    #![allow(missing_docs)]
    pub const SUCCESSFUL_COMPLETION: u16 = 0x0000;
    pub const WRITE_BROADCAST_DISTRIBUTION_TABLE_NAK: u16 = 0x0010;
    pub const READ_BROADCAST_DISTRIBUTION_TABLE_NAK: u16 = 0x0020;
    pub const REGISTER_FOREIGN_DEVICE_NAK: u16 = 0x0030;
    pub const READ_FOREIGN_DEVICE_TABLE_NAK: u16 = 0x0040;
    pub const DELETE_FOREIGN_DEVICE_TABLE_ENTRY_NAK: u16 = 0x0050;
    pub const DISTRIBUTE_BROADCAST_TO_NETWORK_NAK: u16 = 0x0060;
}

/// Confirmed service choices (Clause 21, BACnetConfirmedServiceChoice).
pub mod confirmed {
    #![allow(missing_docs)]
    pub const ACKNOWLEDGE_ALARM: u8 = 0;
    pub const CONFIRMED_COV_NOTIFICATION: u8 = 1;
    pub const CONFIRMED_EVENT_NOTIFICATION: u8 = 2;
    pub const GET_ALARM_SUMMARY: u8 = 3;
    pub const GET_ENROLLMENT_SUMMARY: u8 = 4;
    pub const SUBSCRIBE_COV: u8 = 5;
    pub const ATOMIC_READ_FILE: u8 = 6;
    pub const ATOMIC_WRITE_FILE: u8 = 7;
    pub const ADD_LIST_ELEMENT: u8 = 8;
    pub const REMOVE_LIST_ELEMENT: u8 = 9;
    pub const CREATE_OBJECT: u8 = 10;
    pub const DELETE_OBJECT: u8 = 11;
    pub const READ_PROPERTY: u8 = 12;
    pub const READ_PROPERTY_MULTIPLE: u8 = 14;
    pub const WRITE_PROPERTY: u8 = 15;
    pub const WRITE_PROPERTY_MULTIPLE: u8 = 16;
    pub const DEVICE_COMMUNICATION_CONTROL: u8 = 17;
    pub const CONFIRMED_PRIVATE_TRANSFER: u8 = 18;
    pub const CONFIRMED_TEXT_MESSAGE: u8 = 19;
    pub const REINITIALIZE_DEVICE: u8 = 20;
    pub const READ_RANGE: u8 = 26;
    pub const SUBSCRIBE_COV_PROPERTY: u8 = 28;
    pub const GET_EVENT_INFORMATION: u8 = 29;
}

/// Unconfirmed service choices (Clause 21,
/// BACnetUnconfirmedServiceChoice).
pub mod unconfirmed {
    #![allow(missing_docs)]
    pub const I_AM: u8 = 0;
    pub const I_HAVE: u8 = 1;
    pub const UNCONFIRMED_COV_NOTIFICATION: u8 = 2;
    pub const UNCONFIRMED_EVENT_NOTIFICATION: u8 = 3;
    pub const UNCONFIRMED_PRIVATE_TRANSFER: u8 = 4;
    pub const UNCONFIRMED_TEXT_MESSAGE: u8 = 5;
    pub const TIME_SYNCHRONIZATION: u8 = 6;
    pub const WHO_HAS: u8 = 7;
    pub const WHO_IS: u8 = 8;
    pub const UTC_TIME_SYNCHRONIZATION: u8 = 9;
    pub const WRITE_GROUP: u8 = 10;
}

/// Some object type numbers (Clause 21, BACnetObjectType).
pub mod object_type {
    #![allow(missing_docs)]
    pub const ANALOG_INPUT: u16 = 0;
    pub const ANALOG_OUTPUT: u16 = 1;
    pub const ANALOG_VALUE: u16 = 2;
    pub const BINARY_INPUT: u16 = 3;
    pub const BINARY_OUTPUT: u16 = 4;
    pub const BINARY_VALUE: u16 = 5;
    pub const DEVICE: u16 = 8;
    pub const FILE: u16 = 10;
    pub const MULTI_STATE_INPUT: u16 = 13;
    pub const MULTI_STATE_OUTPUT: u16 = 14;
    pub const MULTI_STATE_VALUE: u16 = 19;
}

/// Application tag numbers (Clause 20.2.1.4).
pub mod tag {
    #![allow(missing_docs)]
    pub const NULL: u8 = 0;
    pub const BOOLEAN: u8 = 1;
    pub const UNSIGNED: u8 = 2;
    pub const SIGNED: u8 = 3;
    pub const REAL: u8 = 4;
    pub const DOUBLE: u8 = 5;
    pub const OCTET_STRING: u8 = 6;
    pub const CHARACTER_STRING: u8 = 7;
    pub const BIT_STRING: u8 = 8;
    pub const ENUMERATED: u8 = 9;
    pub const DATE: u8 = 10;
    pub const TIME: u8 = 11;
    pub const OBJECT_IDENTIFIER: u8 = 12;
}

/// Why bytes are not the BACnet message a reader expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The bytes ended before the message did.
    Truncated,
    /// Bytes were left over after a message of fixed size.
    TrailingBytes,
    /// The BVLC type byte was not 0x81, so this is not BACnet/IP.
    NotBacnetIp(u8),
    /// The BVLC length field did not match the datagram's length, or was
    /// below 4 or above [`MAX_MESSAGE`].
    Length(u16),
    /// The BVLC function code is not one Annex J defines.
    Function(u8),
    /// A BVLC function's data had the wrong length for that function.
    FunctionData(u8),
    /// The NPDU version was not 1.
    Version(u8),
    /// The NPDU had a source address of length 0, which Clause 6.2.2
    /// forbids.
    SourceAddress,
    /// The APDU type is one of the reserved values 8 to 15.
    PduType(u8),
    /// An application tag number from 13 to 15, or an extended tag number
    /// of 255 in any class. All are reserved. Also an extended tag number
    /// below 15, which Clause 20.2.1.2 says goes in the first byte.
    ReservedTag(u8),
    /// An application tag with length code 6 or 7. Only context tags open
    /// or close constructed data.
    ApplicationOpenClose,
    /// A context tag, or an opening or closing tag, where an application
    /// value was expected. It holds the tag number.
    ContextTag(u8),
    /// A value's length does not fit its type, or is above
    /// [`MAX_VALUE_LEN`].
    ValueLength {
        /// The application tag number.
        tag: u8,
        /// The length the tag gave.
        len: u32,
    },
    /// A bit string whose first byte gives more than 7 unused bits, or
    /// unused bits with no bit bytes.
    BitString(u8),
    /// A service body did not hold the fields its service defines, in
    /// order.
    ServiceBody,
    /// A field held a value outside the range its type allows.
    OutOfRange,
    /// A network number Clause 6.2.2.1 does not allow: a destination
    /// network of 0, or a source network of 0 or 0xFFFF.
    Network(u16),
    /// Input longer than [`MAX_MESSAGE`], which no datagram can carry.
    TooLong,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Truncated => f.write_str("message ends early"),
            Error::TrailingBytes => f.write_str("bytes left over after the message"),
            Error::NotBacnetIp(t) => write!(f, "BVLC type {t:#04x}, not 0x81 (BACnet/IP)"),
            Error::Length(n) => write!(f, "BVLC length {n} does not match the datagram"),
            Error::Function(c) => write!(f, "unknown BVLC function {c:#04x}"),
            Error::FunctionData(c) => write!(f, "wrong data length for BVLC function {c:#04x}"),
            Error::Version(v) => write!(f, "NPDU version {v}, not 1"),
            Error::SourceAddress => f.write_str("NPDU source address of length 0"),
            Error::PduType(t) => write!(f, "reserved APDU type {t}"),
            Error::ReservedTag(t) => write!(f, "reserved tag number {t}"),
            Error::ApplicationOpenClose => f.write_str("application tag with an opening or closing length code"),
            Error::ContextTag(t) => write!(f, "context tag {t} where an application value was expected"),
            Error::ValueLength { tag, len } => write!(f, "length {len} does not fit application tag {tag}"),
            Error::BitString(u) => write!(f, "bit string with {u} unused bits"),
            Error::ServiceBody => f.write_str("service body does not match its definition"),
            Error::OutOfRange => f.write_str("value out of range"),
            Error::Network(n) => write!(f, "network number {n} not allowed here"),
            Error::TooLong => f.write_str("input longer than any datagram"),
        }
    }
}

impl std::error::Error for Error {}

/// One entry of a BBMD's broadcast distribution table: a peer BBMD and the
/// mask it broadcasts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BdtEntry {
    /// The peer BBMD's address and port.
    pub address: SocketAddrV4,
    /// The broadcast distribution mask. All ones means "send to the peer
    /// directly".
    pub mask: Ipv4Addr,
}

/// One entry of a BBMD's foreign device table: a device on another subnet
/// that registered to receive broadcasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdtEntry {
    /// The foreign device's address and port.
    pub address: SocketAddrV4,
    /// The time-to-live the device registered with, in seconds.
    pub ttl: u16,
    /// Seconds left before the entry expires. A BBMD adds a 30-second
    /// grace period to the time-to-live.
    pub remaining: u16,
}

/// One BACnet/IP datagram: the BVLC function and what it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bvlc {
    /// 0x00: a BBMD's answer to a request, such as a foreign device
    /// registration or a table write, with a code from [`result`].
    Result(u16),
    /// 0x01: replace a BBMD's broadcast distribution table.
    WriteBdt(Vec<BdtEntry>),
    /// 0x02: ask a BBMD for its broadcast distribution table.
    ReadBdt,
    /// 0x03: a BBMD's broadcast distribution table.
    ReadBdtAck(Vec<BdtEntry>),
    /// 0x04: a broadcast a BBMD passes on, with the address of the device
    /// that first sent it.
    ForwardedNpdu {
        /// The device that sent the original broadcast.
        origin: SocketAddrV4,
        /// The NPDU it sent.
        npdu: Vec<u8>,
    },
    /// 0x05: register with a BBMD as a foreign device, for `ttl` seconds.
    RegisterForeignDevice {
        /// How long the registration lasts, in seconds.
        ttl: u16,
    },
    /// 0x06: ask a BBMD for its foreign device table.
    ReadFdt,
    /// 0x07: a BBMD's foreign device table.
    ReadFdtAck(Vec<FdtEntry>),
    /// 0x08: remove a device from a BBMD's foreign device table.
    DeleteFdtEntry(SocketAddrV4),
    /// 0x09: a foreign device asks its BBMD to broadcast this NPDU.
    DistributeBroadcastToNetwork(Vec<u8>),
    /// 0x0A: an NPDU sent to one device.
    OriginalUnicastNpdu(Vec<u8>),
    /// 0x0B: an NPDU broadcast on the local subnet.
    OriginalBroadcastNpdu(Vec<u8>),
    /// 0x0C: a message secured by BACnet network security (Clause 24),
    /// kept as raw bytes. BACnet/SC (Annex AB) is a different data link
    /// and does not use this header.
    SecureBvll(Vec<u8>),
}

impl Bvlc {
    /// The BVLC function code.
    pub fn function(&self) -> u8 {
        match self {
            Bvlc::Result(_) => function::RESULT,
            Bvlc::WriteBdt(_) => function::WRITE_BROADCAST_DISTRIBUTION_TABLE,
            Bvlc::ReadBdt => function::READ_BROADCAST_DISTRIBUTION_TABLE,
            Bvlc::ReadBdtAck(_) => function::READ_BROADCAST_DISTRIBUTION_TABLE_ACK,
            Bvlc::ForwardedNpdu { .. } => function::FORWARDED_NPDU,
            Bvlc::RegisterForeignDevice { .. } => function::REGISTER_FOREIGN_DEVICE,
            Bvlc::ReadFdt => function::READ_FOREIGN_DEVICE_TABLE,
            Bvlc::ReadFdtAck(_) => function::READ_FOREIGN_DEVICE_TABLE_ACK,
            Bvlc::DeleteFdtEntry(_) => function::DELETE_FOREIGN_DEVICE_TABLE_ENTRY,
            Bvlc::DistributeBroadcastToNetwork(_) => function::DISTRIBUTE_BROADCAST_TO_NETWORK,
            Bvlc::OriginalUnicastNpdu(_) => function::ORIGINAL_UNICAST_NPDU,
            Bvlc::OriginalBroadcastNpdu(_) => function::ORIGINAL_BROADCAST_NPDU,
            Bvlc::SecureBvll(_) => function::SECURE_BVLL,
        }
    }

    /// The NPDU this datagram carries, if its function carries one. Read
    /// it with [`Npdu::parse`].
    pub fn npdu(&self) -> Option<&[u8]> {
        match self {
            Bvlc::ForwardedNpdu { npdu, .. }
            | Bvlc::DistributeBroadcastToNetwork(npdu)
            | Bvlc::OriginalUnicastNpdu(npdu)
            | Bvlc::OriginalBroadcastNpdu(npdu) => Some(npdu),
            _ => None,
        }
    }
}

fn bip_address(b: &[u8]) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(b[0], b[1], b[2], b[3]), be16(b, 4))
}

fn bdt_entry(e: &[u8]) -> BdtEntry {
    BdtEntry { address: bip_address(e), mask: Ipv4Addr::new(e[6], e[7], e[8], e[9]) }
}

fn put_bip_address(out: &mut Vec<u8>, a: SocketAddrV4) {
    out.extend_from_slice(&a.ip().octets());
    out.extend_from_slice(&a.port().to_be_bytes());
}

/// A message's network priority (Clause 6.2.2). Routers pass higher
/// priorities first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Priority {
    /// 0: an ordinary message.
    #[default]
    Normal,
    /// 1: an urgent message.
    Urgent,
    /// 2: a message about critical equipment.
    CriticalEquipment,
    /// 3: a life safety message.
    LifeSafety,
}

impl Priority {
    /// The priority in the low two bits of `bits`.
    pub fn from_bits(bits: u8) -> Priority {
        match bits & 3 {
            0 => Priority::Normal,
            1 => Priority::Urgent,
            2 => Priority::CriticalEquipment,
            _ => Priority::LifeSafety,
        }
    }

    /// The priority's two-bit code.
    pub fn bits(self) -> u8 {
        match self {
            Priority::Normal => 0,
            Priority::Urgent => 1,
            Priority::CriticalEquipment => 2,
            Priority::LifeSafety => 3,
        }
    }
}

/// A station on a BACnet network: the network number and the station's
/// address on that network (a MAC address, for BACnet/IP six bytes of IP
/// address and port).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetAddress {
    /// The network number: 1 to 65534, or 0xFFFF in a destination for
    /// every network. 0 is not a network number.
    pub network: u16,
    /// The station's address. Empty in a destination means a broadcast on
    /// that network. The writer refuses more than [`MAX_MAC_LEN`] bytes.
    pub mac: Vec<u8>,
}

/// Where a routed NPDU is going, and how many more routers may pass it on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    /// The destination network and station.
    pub address: NetAddress,
    /// Decremented by each router. A router drops the message at 0. New
    /// messages start at 255.
    pub hop_count: u8,
}

/// An NPDU's body: an APDU, or a message for the network layer itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NpduBody {
    /// An APDU, unread. Read it with [`Apdu::parse`].
    Apdu(Vec<u8>),
    /// A network layer message, such as Who-Is-Router-To-Network. Its data
    /// is kept as raw bytes.
    Network {
        /// The message type (Clause 6.2.4).
        message_type: u8,
        /// The vendor, for proprietary message types 0x80 and up. It is
        /// written only for those types, as 0 when absent.
        vendor: Option<u16>,
        /// The message's data.
        data: Vec<u8>,
    },
}

/// The network layer header and its body (Clause 6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Npdu {
    /// Where a router should send the message. `None` means the local
    /// network.
    pub destination: Option<Destination>,
    /// The station that first sent the message, set by a router that
    /// passed it on. `None` means a station on the local network. A source
    /// with an empty address is refused by readers and writers.
    pub source: Option<NetAddress>,
    /// Whether the sender expects a reply: set for confirmed requests,
    /// segments of complex acknowledgments, and network layer messages
    /// that expect a reply.
    pub expecting_reply: bool,
    /// The message's priority.
    pub priority: Priority,
    /// What the NPDU carries.
    pub body: NpduBody,
}

impl Npdu {
    /// An NPDU for the local network, carrying `apdu`. It expects a reply
    /// when `apdu` is a confirmed request or a segment of a complex
    /// acknowledgment (Clause 6.2.2, control bit 2).
    pub fn local(apdu: Vec<u8>) -> Npdu {
        Npdu {
            destination: None,
            source: None,
            expecting_reply: apdu_expects_reply(&apdu),
            priority: Priority::Normal,
            body: NpduBody::Apdu(apdu),
        }
    }

    /// The APDU this NPDU carries, if it carries one.
    pub fn apdu(&self) -> Option<&[u8]> {
        match &self.body {
            NpduBody::Apdu(a) => Some(a),
            NpduBody::Network { .. } => None,
        }
    }

    /// An NPDU that answers this one with `apdu`: sent back to the
    /// original source through the router it came from, at the same
    /// priority. It expects a reply only when `apdu` is a confirmed
    /// request or a segment of a complex acknowledgment, as for
    /// [`Npdu::local`].
    pub fn reply(&self, apdu: Vec<u8>) -> Npdu {
        Npdu {
            destination: self.source.clone().map(|address| Destination { address, hop_count: 255 }),
            source: None,
            expecting_reply: apdu_expects_reply(&apdu),
            priority: self.priority,
            body: NpduBody::Apdu(apdu),
        }
    }
}

/// Whether a source network number is allowed: 1 to 65534 (Clause
/// 6.2.2.1).
fn valid_source_network(network: u16) -> bool {
    network != 0 && network != 0xffff
}

/// Whether an NPDU carrying `apdu` expects a reply: a confirmed request,
/// or a segment of a complex acknowledgment (Clause 6.2.2).
fn apdu_expects_reply(apdu: &[u8]) -> bool {
    match apdu.first() {
        Some(&first) => first >> 4 == 0 || (first >> 4 == 3 && first & 0x08 != 0),
        None => false,
    }
}

fn net_address(r: &mut Reader) -> Result<NetAddress, Error> {
    let network = r.u16_be()?;
    let len = r.u8()?;
    Ok(NetAddress { network, mac: r.take(usize::from(len))?.to_vec() })
}

fn put_net_address(out: &mut Vec<u8>, a: &NetAddress) -> Result<(), Error> {
    if a.mac.len() > MAX_MAC_LEN {
        return Err(Error::Unwritable);
    }
    let mac = &a.mac;
    out.extend_from_slice(&a.network.to_be_bytes());
    out.push(mac.len() as u8);
    out.extend_from_slice(mac);
    Ok(())
}

/// The segmentation fields of a segmented confirmed request or complex
/// acknowledgment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// The segment's number, counting from 0 and wrapping at 256.
    pub sequence: u8,
    /// How many segments the sender proposes to send before waiting for a
    /// segment acknowledgment: 1 to 127.
    pub window: u8,
    /// Whether more segments follow this one.
    pub more_follows: bool,
}

/// An application layer message (Clause 20.1). Service bodies are kept as
/// raw bytes; a segment's body is only part of the whole service body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Apdu {
    /// Type 0: a request that expects an answer.
    ConfirmedRequest {
        /// Whether the client can take a segmented answer.
        segmented_response_accepted: bool,
        /// The most segments the client accepts, as a 3-bit code; see
        /// [`max_segments`]. The writer refuses values above 7.
        max_segments: u8,
        /// The longest APDU the client accepts, as a 4-bit code; see
        /// [`max_apdu_octets`]. The writer refuses values above 15.
        max_apdu: u8,
        /// Chosen by the client and copied into the answer.
        invoke_id: u8,
        /// Present when this is one segment of a segmented request.
        segment: Option<Segment>,
        /// The service, from [`confirmed`].
        service: u8,
        /// The service request's body.
        data: Vec<u8>,
    },
    /// Type 1: a request that expects no answer.
    UnconfirmedRequest {
        /// The service, from [`unconfirmed`].
        service: u8,
        /// The service request's body.
        data: Vec<u8>,
    },
    /// Type 2: a confirmed request succeeded, with nothing to return.
    SimpleAck {
        /// The request's invoke ID.
        invoke_id: u8,
        /// The request's service.
        service: u8,
    },
    /// Type 3: a confirmed request succeeded, with data.
    ComplexAck {
        /// The request's invoke ID.
        invoke_id: u8,
        /// Present when this is one segment of a segmented answer.
        segment: Option<Segment>,
        /// The request's service.
        service: u8,
        /// The service acknowledgment's body.
        data: Vec<u8>,
    },
    /// Type 4: acknowledges segments up to `sequence`.
    SegmentAck {
        /// Set when a segment came out of order.
        negative: bool,
        /// Set when the server sent this acknowledgment.
        server: bool,
        /// The invoke ID of the segmented message.
        invoke_id: u8,
        /// The last segment received in order.
        sequence: u8,
        /// How many segments the receiver will take before acknowledging.
        window: u8,
    },
    /// Type 5: a confirmed request failed.
    Error {
        /// The request's invoke ID.
        invoke_id: u8,
        /// The request's service.
        service: u8,
        /// The error's body. For most services it is two enumerated
        /// values, the error class and the error code; read them with
        /// [`Value::parse`].
        data: Vec<u8>,
    },
    /// Type 6: a request was refused because it was malformed.
    Reject {
        /// The request's invoke ID.
        invoke_id: u8,
        /// Why, as a BACnetRejectReason.
        reason: u8,
    },
    /// Type 7: a transaction was stopped.
    Abort {
        /// Set when the server sent the abort.
        server: bool,
        /// The transaction's invoke ID.
        invoke_id: u8,
        /// Why, as a BACnetAbortReason.
        reason: u8,
    },
}

impl Apdu {
    /// The APDU type: the high four bits of its first byte.
    pub fn pdu_type(&self) -> u8 {
        match self {
            Apdu::ConfirmedRequest { .. } => 0,
            Apdu::UnconfirmedRequest { .. } => 1,
            Apdu::SimpleAck { .. } => 2,
            Apdu::ComplexAck { .. } => 3,
            Apdu::SegmentAck { .. } => 4,
            Apdu::Error { .. } => 5,
            Apdu::Reject { .. } => 6,
            Apdu::Abort { .. } => 7,
        }
    }

    /// The invoke ID that ties a confirmed request to its answers. `None`
    /// for an unconfirmed request, which has none.
    pub fn invoke_id(&self) -> Option<u8> {
        match self {
            Apdu::UnconfirmedRequest { .. } => None,
            Apdu::ConfirmedRequest { invoke_id, .. }
            | Apdu::SimpleAck { invoke_id, .. }
            | Apdu::ComplexAck { invoke_id, .. }
            | Apdu::SegmentAck { invoke_id, .. }
            | Apdu::Error { invoke_id, .. }
            | Apdu::Reject { invoke_id, .. }
            | Apdu::Abort { invoke_id, .. } => Some(*invoke_id),
        }
    }

    /// The service choice, for the types that carry one. Confirmed
    /// services are numbered from [`confirmed`] and unconfirmed ones from
    /// [`unconfirmed`]. `None` for segment acknowledgments, rejects and
    /// aborts.
    pub fn service(&self) -> Option<u8> {
        match self {
            Apdu::ConfirmedRequest { service, .. }
            | Apdu::UnconfirmedRequest { service, .. }
            | Apdu::SimpleAck { service, .. }
            | Apdu::ComplexAck { service, .. }
            | Apdu::Error { service, .. } => Some(*service),
            Apdu::SegmentAck { .. } | Apdu::Reject { .. } | Apdu::Abort { .. } => None,
        }
    }

    /// The service body, for the types that carry one. `None` for simple
    /// and segment acknowledgments, rejects and aborts.
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            Apdu::ConfirmedRequest { data, .. }
            | Apdu::UnconfirmedRequest { data, .. }
            | Apdu::ComplexAck { data, .. }
            | Apdu::Error { data, .. } => Some(data),
            _ => None,
        }
    }
}

/// The longest APDU, in bytes, that a 4-bit max-APDU code allows
/// (Clause 20.1.2.5). Codes 6 to 15 are reserved.
pub fn max_apdu_octets(code: u8) -> Option<u16> {
    match code {
        0 => Some(50),
        1 => Some(128),
        2 => Some(206),
        3 => Some(480),
        4 => Some(1024),
        5 => Some(1476),
        _ => None,
    }
}

/// The most segments a 3-bit max-segments code allows (Clause
/// 20.1.2.4). Code 0 leaves it unspecified and code 7 means more than 64,
/// so both give `None`.
pub fn max_segments(code: u8) -> Option<u8> {
    match code {
        1..=6 => Some(1 << code),
        _ => None,
    }
}

/// Whether a tag is an application tag or a context-specific one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// The tag number names the value's type, from [`tag`].
    Application,
    /// The tag number names a field of the enclosing service or
    /// structure.
    Context,
}

/// What follows a tag header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagContent {
    /// That many bytes of contents. For an application Boolean, the length
    /// is the value itself (0 or 1) and no bytes follow.
    Length(u32),
    /// The start of constructed data, ended by a matching
    /// [`TagContent::Closing`].
    Opening,
    /// The end of constructed data.
    Closing,
}

/// A tag header (Clause 20.2.1): the tag number, its class and what
/// follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    /// The tag number. Numbers 15 and up take an extra byte. 255 is
    /// reserved: readers and writers refuse it.
    pub number: u8,
    /// Application or context.
    pub class: Class,
    /// The contents' length, or an opening or closing mark.
    pub content: TagContent,
}

impl Tag {
    /// Reads the tag header at the start of `b`, and how many bytes it
    /// took. It does not check that the contents follow. An extended tag
    /// number of 255, which Clause 20.2.1.2 reserves, is refused, and so is
    /// one below 15, which that clause puts in the first byte.
    fn parse_prefix(b: &[u8]) -> Result<(Tag, usize), Error> {
        let mut r = Reader::new(b);
        let first = r.u8()?;
        let class = if first & 0x08 != 0 { Class::Context } else { Class::Application };
        let mut number = first >> 4;
        if number == 15 {
            number = r.u8()?;
            if number == 255 || number < 15 {
                return Err(Error::ReservedTag(number));
            }
        }
        let content = match (class, first & 0x07) {
            (Class::Context, 6) => TagContent::Opening,
            (Class::Context, 7) => TagContent::Closing,
            (Class::Application, 6 | 7) => return Err(Error::ApplicationOpenClose),
            (_, 5) => TagContent::Length(match r.u8()? {
                254 => u32::from(r.u16_be()?),
                255 => r.u32_be()?,
                n => u32::from(n),
            }),
            (_, n) => TagContent::Length(u32::from(n)),
        };
        Ok((Tag { number, class, content }, r.position()))
    }
}

/// A date (Clause 20.2.12). Any field may be 255 for "unspecified", and
/// newer revisions give the month and day a few more special values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Date {
    /// Years since 1900.
    pub year: u8,
    /// 1 to 12; 13 is odd months and 14 even months.
    pub month: u8,
    /// 1 to 31; 32 is the last day of the month.
    pub day: u8,
    /// 1 is Monday and 7 is Sunday.
    pub weekday: u8,
}

/// A time of day (Clause 20.2.13). Any field may be 255 for
/// "unspecified".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time {
    /// 0 to 23.
    pub hour: u8,
    /// 0 to 59.
    pub minute: u8,
    /// 0 to 59.
    pub second: u8,
    /// 0 to 99.
    pub hundredths: u8,
}

/// An object's identifier: its type and instance number (Clause 20.2.14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectId {
    /// The object type, from [`object_type`]: 0 to [`MAX_OBJECT_TYPE`].
    pub object_type: u16,
    /// The instance number: 0 to [`MAX_INSTANCE`].
    pub instance: u32,
}

impl ObjectId {
    /// The device object with this instance number.
    pub fn device(instance: u32) -> ObjectId {
        ObjectId { object_type: object_type::DEVICE, instance }
    }

    /// The identifier packed in 32 bits: 10 of type, 22 of instance.
    pub fn from_u32(v: u32) -> ObjectId {
        ObjectId { object_type: (v >> 22) as u16, instance: v & MAX_INSTANCE }
    }

    /// The identifier packed in 32 bits. Returns `None` for a type above
    /// [`MAX_OBJECT_TYPE`] or an instance above [`MAX_INSTANCE`].
    pub fn to_u32(self) -> Option<u32> {
        if self.object_type > MAX_OBJECT_TYPE || self.instance > MAX_INSTANCE {
            return None;
        }
        Some(u32::from(self.object_type) << 22 | self.instance)
    }
}

/// A character string: its character set and its bytes in that set
/// (Clause 20.2.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CharString {
    /// The character set: 0 is UTF-8, 1 IBM/Microsoft DBCS, 2 JIS X 0208,
    /// 3 UCS-4, 4 UCS-2 and 5 ISO 8859-1.
    pub charset: u8,
    /// The string's bytes in that character set.
    pub bytes: Vec<u8>,
}

impl CharString {
    /// A UTF-8 string.
    pub fn utf8(s: &str) -> CharString {
        CharString { charset: 0, bytes: s.as_bytes().to_vec() }
    }

    /// The string, if it is UTF-8 and valid.
    pub fn as_str(&self) -> Option<&str> {
        if self.charset == 0 { std::str::from_utf8(&self.bytes).ok() } else { None }
    }
}

/// An application-tagged primitive value (Clause 20.2).
#[derive(Clone, Debug)]
pub enum Value {
    /// Tag 0.
    Null,
    /// Tag 1.
    Boolean(bool),
    /// Tag 2: up to 8 bytes.
    Unsigned(u64),
    /// Tag 3: up to 8 bytes, two's complement.
    Signed(i64),
    /// Tag 4: IEEE 754 single precision.
    Real(f32),
    /// Tag 5: IEEE 754 double precision.
    Double(f64),
    /// Tag 6.
    OctetString(Vec<u8>),
    /// Tag 7.
    CharacterString(CharString),
    /// Tag 8: bits in order, the first in the high bit of the first byte.
    BitString(Vec<bool>),
    /// Tag 9: up to 4 bytes.
    Enumerated(u32),
    /// Tag 10.
    Date(Date),
    /// Tag 11.
    Time(Time),
    /// Tag 12.
    ObjectId(ObjectId),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Real(a), Self::Real(b)) => a.to_bits() == b.to_bits(),
            (Self::Double(a), Self::Double(b)) => a.to_bits() == b.to_bits(),
            (Self::Boolean(a), Self::Boolean(b)) => a == b,
            (Self::Unsigned(a), Self::Unsigned(b)) => a == b,
            (Self::Signed(a), Self::Signed(b)) => a == b,
            (Self::OctetString(a), Self::OctetString(b)) => a == b,
            (Self::CharacterString(a), Self::CharacterString(b)) => a == b,
            (Self::BitString(a), Self::BitString(b)) => a == b,
            (Self::Enumerated(a), Self::Enumerated(b)) => a == b,
            (Self::Date(a), Self::Date(b)) => a == b,
            (Self::Time(a), Self::Time(b)) => a == b,
            (Self::ObjectId(a), Self::ObjectId(b)) => a == b,
            _ => false,
        }
    }
}

impl Value {
    /// Reads the application-tagged value at the start of `b`, and how
    /// many bytes it took. Integers may carry leading zero bytes, as
    /// some devices send them.
    fn parse_prefix(b: &[u8]) -> Result<(Value, usize), Error> {
        let (t, header) = Tag::parse_prefix(b)?;
        let TagContent::Length(len) = t.content else { return Err(Error::ContextTag(t.number)) };
        if t.class == Class::Context {
            return Err(Error::ContextTag(t.number));
        }
        if t.number == tag::BOOLEAN {
            // Clause 20.2.3: the value is the length field itself, never an
            // extended length.
            return match len {
                0 | 1 if header == 1 => Ok((Value::Boolean(len == 1), header)),
                _ => Err(Error::ValueLength { tag: tag::BOOLEAN, len }),
            };
        }
        let (c, end) = contents(b, header, t.number, len)?;
        Ok((Value::from_contents(t.number, c)?, end))
    }

    /// Reads a schema-selected primitive from the input prefix.
    fn parse_context(b: &[u8], number: u8, as_tag: u8) -> Result<(Value, usize), Error> {
        let (t, header) = Tag::parse_prefix(b)?;
        let TagContent::Length(len) = t.content else { return Err(Error::ServiceBody) };
        if t.class != Class::Context || t.number != number {
            return Err(Error::ServiceBody);
        }
        if as_tag > tag::OBJECT_IDENTIFIER {
            return Err(Error::ReservedTag(as_tag));
        }
        let (c, end) = contents(b, header, as_tag, len)?;
        if as_tag == tag::BOOLEAN {
            return match c {
                [0] => Ok((Value::Boolean(false), end)),
                [1] => Ok((Value::Boolean(true), end)),
                [_] => Err(Error::OutOfRange),
                _ => Err(Error::ValueLength { tag: tag::BOOLEAN, len }),
            };
        }
        Ok((Value::from_contents(as_tag, c)?, end))
    }

    /// Reads a value's contents, `c`, as application type `number`. Not
    /// for Booleans, whose encoding depends on the class.
    fn from_contents(number: u8, c: &[u8]) -> Result<Value, Error> {
        // c comes from a tag whose length passed MAX_VALUE_LEN, so it fits.
        let bad = Error::ValueLength { tag: number, len: c.len() as u32 };
        let four = || -> Result<[u8; 4], Error> { c.try_into().map_err(|_| bad) };
        Ok(match number {
            tag::NULL if c.is_empty() => Value::Null,
            tag::UNSIGNED => Value::Unsigned(be_uint(c, 8).ok_or(bad)?),
            tag::SIGNED => Value::Signed(be_int(c).ok_or(bad)?),
            tag::REAL => Value::Real(f32::from_be_bytes(four()?)),
            tag::DOUBLE => Value::Double(f64::from_be_bytes(c.try_into().map_err(|_| bad)?)),
            tag::OCTET_STRING => Value::OctetString(c.to_vec()),
            tag::CHARACTER_STRING => {
                let (&charset, bytes) = c.split_first().ok_or(bad)?;
                Value::CharacterString(CharString { charset, bytes: bytes.to_vec() })
            }
            tag::BIT_STRING => {
                let (&unused, bytes) = c.split_first().ok_or(bad)?;
                if unused > 7 || (bytes.is_empty() && unused != 0) {
                    return Err(Error::BitString(unused));
                }
                let count = bytes.len() * 8 - usize::from(unused);
                Value::BitString((0..count).map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0).collect())
            }
            tag::ENUMERATED => Value::Enumerated(be_uint(c, 4).ok_or(bad)? as u32),
            tag::DATE => {
                let [year, month, day, weekday] = four()?;
                Value::Date(Date { year, month, day, weekday })
            }
            tag::TIME => {
                let [hour, minute, second, hundredths] = four()?;
                Value::Time(Time { hour, minute, second, hundredths })
            }
            tag::OBJECT_IDENTIFIER => Value::ObjectId(ObjectId::from_u32(u32::from_be_bytes(four()?))),
            _ => return Err(bad),
        })
    }

    /// The value's application tag number.
    pub fn tag(&self) -> u8 {
        match self {
            Value::Null => tag::NULL,
            Value::Boolean(_) => tag::BOOLEAN,
            Value::Unsigned(_) => tag::UNSIGNED,
            Value::Signed(_) => tag::SIGNED,
            Value::Real(_) => tag::REAL,
            Value::Double(_) => tag::DOUBLE,
            Value::OctetString(_) => tag::OCTET_STRING,
            Value::CharacterString(_) => tag::CHARACTER_STRING,
            Value::BitString(_) => tag::BIT_STRING,
            Value::Enumerated(_) => tag::ENUMERATED,
            Value::Date(_) => tag::DATE,
            Value::Time(_) => tag::TIME,
            Value::ObjectId(_) => tag::OBJECT_IDENTIFIER,
        }
    }

    fn write_tagged(&self, class: Class, number: u8, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::new();
        let mut c = Vec::new();
        match self {
            Value::Null => {}
            Value::Boolean(v) => c.push(u8::from(*v)),
            Value::Unsigned(v) => c = uint_bytes(*v),
            Value::Signed(v) => c = int_bytes(*v),
            Value::Real(v) => c.extend_from_slice(&v.to_be_bytes()),
            Value::Double(v) => c.extend_from_slice(&v.to_be_bytes()),
            Value::OctetString(v) => {
                if v.len() > MAX_VALUE_LEN {
                    return Err(Error::Unwritable);
                }
                c.extend_from_slice(v);
            },
            Value::CharacterString(s) => {
                c.push(s.charset);
                if s.bytes.len() >= MAX_VALUE_LEN {
                    return Err(Error::Unwritable);
                }
                c.extend_from_slice(&s.bytes);
            }
            Value::BitString(bits) => {
                if bits.len() > (MAX_VALUE_LEN - 1) * 8 {
                    return Err(Error::Unwritable);
                }
                c.push(((8 - bits.len() % 8) % 8) as u8);
                let mut bytes = vec![0u8; bits.len().div_ceil(8)];
                for (i, _) in bits.iter().enumerate().filter(|(_, b)| **b) {
                    bytes[i / 8] |= 0x80 >> (i % 8);
                }
                c.extend_from_slice(&bytes);
            }
            Value::Enumerated(v) => c = uint_bytes(u64::from(*v)),
            Value::Date(d) => c.extend_from_slice(&[d.year, d.month, d.day, d.weekday]),
            Value::Time(t) => c.extend_from_slice(&[t.hour, t.minute, t.second, t.hundredths]),
            Value::ObjectId(id) => {
                if id.object_type > MAX_OBJECT_TYPE || id.instance > MAX_INSTANCE {
                    return Err(Error::Unwritable);
                }
                c.extend_from_slice(&id.to_u32().ok_or(Error::Unwritable)?.to_be_bytes());
            },
        }
        // c is at most MAX_VALUE_LEN long, so it fits in a u32.
        Tag { number, class, content: TagContent::Length(c.len() as u32) }.write(&mut out)?;
        out.extend_from_slice(&c);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

/// BACnetSegmentation: which directions a device can segment messages in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segmentation {
    /// 0: sends and receives segmented messages.
    Both,
    /// 1: sends segmented messages only.
    Transmit,
    /// 2: receives segmented messages only.
    Receive,
    /// 3: neither.
    NoSegmentation,
}

impl Segmentation {
    /// The segmentation for an enumerated value, if it is one of the four.
    pub fn from_code(c: u32) -> Option<Segmentation> {
        match c {
            0 => Some(Segmentation::Both),
            1 => Some(Segmentation::Transmit),
            2 => Some(Segmentation::Receive),
            3 => Some(Segmentation::NoSegmentation),
            _ => None,
        }
    }

    /// The enumerated value.
    pub fn code(self) -> u32 {
        match self {
            Segmentation::Both => 0,
            Segmentation::Transmit => 1,
            Segmentation::Receive => 2,
            Segmentation::NoSegmentation => 3,
        }
    }
}

/// The Who-Is service (Clause 16.10): which devices should answer with an
/// I-Am.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WhoIs {
    /// The lowest and highest device instance that should answer, both
    /// included. `None` asks every device. Limits above [`MAX_INSTANCE`]
    /// are refused by the writer.
    pub range: Option<(u32, u32)>,
}

impl WhoIs {
    /// Whether the device with this instance number should answer.
    pub fn matches(&self, instance: u32) -> bool {
        match self.range {
            None => true,
            Some((low, high)) => low <= instance && instance <= high,
        }
    }

    /// The unconfirmed request that carries this Who-Is.
    pub fn to_apdu(&self) -> Result<Apdu, Error> {
        Ok(Apdu::UnconfirmedRequest { service: unconfirmed::WHO_IS, data: self.to_bytes()? })
    }
}

/// The I-Am service (Clause 16.10): a device announces itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IAm {
    /// The device's object identifier. Its type must be
    /// [`object_type::DEVICE`]: [`IAm::parse`] refuses any other, and
    /// [`IAm::write`] writes the type as Device whatever it holds.
    pub device: ObjectId,
    /// The longest APDU the device accepts, in bytes.
    pub max_apdu: u32,
    /// Which directions the device can segment messages in.
    pub segmentation: Segmentation,
    /// The device's vendor identifier, assigned by ASHRAE.
    pub vendor: u16,
}

impl IAm {
    /// The unconfirmed request that carries this I-Am.
    pub fn to_apdu(&self) -> Result<Apdu, Error> {
        Ok(Apdu::UnconfirmedRequest { service: unconfirmed::I_AM, data: self.to_bytes()? })
    }
}

/// The `len` bytes of contents after a tag header of `header` bytes, and
/// where they end. `number` is the application type, checked for range.
fn contents(b: &[u8], header: usize, number: u8, len: u32) -> Result<(&[u8], usize), Error> {
    if number > tag::OBJECT_IDENTIFIER {
        return Err(Error::ReservedTag(number));
    }
    let bad = Error::ValueLength { tag: number, len };
    let n = usize::try_from(len).map_err(|_| bad)?;
    if n > MAX_VALUE_LEN {
        return Err(bad);
    }
    let end = header.checked_add(n).ok_or(bad)?;
    Ok((b.get(header..end).ok_or(Error::Truncated)?, end))
}

/// Reads a context tag numbered `number` holding an unsigned integer.
fn context_unsigned(b: &[u8], number: u8) -> Result<(u64, usize), Error> {
    let (t, header) = Tag::parse_prefix(b)?;
    let TagContent::Length(len) = t.content else { return Err(Error::ServiceBody) };
    if t.class != Class::Context || t.number != number {
        return Err(Error::ServiceBody);
    }
    let n = usize::try_from(len).map_err(|_| Error::ServiceBody)?;
    let end = header.checked_add(n).ok_or(Error::Truncated)?;
    let c = b.get(header..end).ok_or(Error::Truncated)?;
    Ok((be_uint(c, 8).ok_or(Error::ServiceBody)?, end))
}

/// A big-endian unsigned integer of 1 to `max` bytes.
fn be_uint(c: &[u8], max: usize) -> Option<u64> {
    if c.is_empty() || c.len() > max {
        return None;
    }
    Some(c.iter().fold(0u64, |v, &b| v << 8 | u64::from(b)))
}

/// A big-endian two's complement integer of 1 to 8 bytes.
fn be_int(c: &[u8]) -> Option<i64> {
    let (&first, _) = c.split_first()?;
    if c.len() > 8 {
        return None;
    }
    let start = if first & 0x80 != 0 { -1i64 } else { 0 };
    Some(c.iter().fold(start, |v, &b| v << 8 | i64::from(b)))
}

/// The shortest big-endian bytes of `v`, at least one.
fn uint_bytes(v: u64) -> Vec<u8> {
    let n = (8 - v.leading_zeros() as usize / 8).max(1);
    v.to_be_bytes()[8 - n..].to_vec()
}

/// The shortest two's complement bytes of `v`, at least one.
fn int_bytes(v: i64) -> Vec<u8> {
    let n = (1..=8).find(|&n| (v >> (8 * n - 1)) == 0 || (v >> (8 * n - 1)) == -1).unwrap_or(8);
    v.to_be_bytes()[8 - n..].to_vec()
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

impl Wire for Tag {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one tag header without its contents. Refuses trailing bytes,
    /// extended tag numbers below 15 or equal to 255, and application opening or closing tags.
    fn parse(b: &[u8]) -> Result<Tag, Error> {
        let (value, used) = Self::parse_prefix(b)?;
        if used != b.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(value)
    }

    /// Appends a tag header without its contents. Refuses tag number 255 and
    /// application opening or closing tags. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.number == 255 || (self.class == Class::Application && !matches!(self.content, TagContent::Length(_))) {
            return Err(Error::Unwritable);
        }
        let mut out = Vec::new();
        let number = self.number;
        let nibble = number.min(15);
        let (class, lvt, extended) = match self.content {
            TagContent::Opening => (0x08, 6, None),
            TagContent::Closing => (0x08, 7, None),
            TagContent::Length(n) => {
                let class = if self.class == Class::Context { 0x08 } else { 0 };
                if n <= 4 { (class, n as u8, None) } else { (class, 5, Some(n)) }
            }
        };
        out.push(nibble << 4 | class | lvt);
        if number >= 15 {
            out.push(number);
        }
        match extended {
            None => {}
            Some(n) if n <= 253 => out.push(n as u8),
            Some(n) if n <= 0xffff => {
                out.push(254);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            Some(n) => {
                out.push(255);
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Value {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one application-tagged value. Integers may include leading zero bytes.
    /// Refuses context tags, reserved types, invalid lengths and trailing bytes.
    fn parse(b: &[u8]) -> Result<Value, Error> {
        let (value, used) = Self::parse_prefix(b)?;
        if used != b.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(value)
    }

    /// Appends an application value. Refuses strings or bit strings above [`MAX_VALUE_LEN`]
    /// and object identifiers outside their field ranges. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if let Value::Boolean(v) = self {
            let t = Tag { number: tag::BOOLEAN, class: Class::Application, content: TagContent::Length(u32::from(*v)) };
            return t.write(dst);
        }
        self.write_tagged(Class::Application, self.tag(), dst)
    }
}

impl Wire for Bvlc {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one datagram. The BVLC length field must match the datagram's
    /// length, so `b` must be the whole datagram and nothing else.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Bvlc, Error> {
        if b.len() < BVLC_HEADER_LEN {
            return Err(Error::Truncated);
        }
        if b[0] != BVLC_TYPE {
            return Err(Error::NotBacnetIp(b[0]));
        }
        let code = b[1];
        let length = be16(b, 2);
        let n = usize::from(length);
        if !(BVLC_HEADER_LEN..=MAX_MESSAGE).contains(&n) || n != b.len() {
            return Err(Error::Length(length));
        }
        let data = &b[BVLC_HEADER_LEN..];
        let exact = |n: usize| if data.len() == n { Ok(()) } else { Err(Error::FunctionData(code)) };
        let table = |size: usize| {
            if data.len().is_multiple_of(size) { Ok(data.chunks_exact(size)) } else { Err(Error::FunctionData(code)) }
        };
        Ok(match code {
            function::RESULT => {
                exact(2)?;
                Bvlc::Result(be16(data, 0))
            }
            function::WRITE_BROADCAST_DISTRIBUTION_TABLE => Bvlc::WriteBdt(table(10)?.map(bdt_entry).collect()),
            function::READ_BROADCAST_DISTRIBUTION_TABLE => {
                exact(0)?;
                Bvlc::ReadBdt
            }
            function::READ_BROADCAST_DISTRIBUTION_TABLE_ACK => Bvlc::ReadBdtAck(table(10)?.map(bdt_entry).collect()),
            function::FORWARDED_NPDU => {
                if data.len() < 6 {
                    return Err(Error::FunctionData(code));
                }
                Bvlc::ForwardedNpdu { origin: bip_address(data), npdu: data[6..].to_vec() }
            }
            function::REGISTER_FOREIGN_DEVICE => {
                exact(2)?;
                Bvlc::RegisterForeignDevice { ttl: be16(data, 0) }
            }
            function::READ_FOREIGN_DEVICE_TABLE => {
                exact(0)?;
                Bvlc::ReadFdt
            }
            function::READ_FOREIGN_DEVICE_TABLE_ACK => Bvlc::ReadFdtAck(
                table(10)?
                    .map(|e| FdtEntry { address: bip_address(e), ttl: be16(e, 6), remaining: be16(e, 8) })
                    .collect(),
            ),
            function::DELETE_FOREIGN_DEVICE_TABLE_ENTRY => {
                exact(6)?;
                Bvlc::DeleteFdtEntry(bip_address(data))
            }
            function::DISTRIBUTE_BROADCAST_TO_NETWORK => Bvlc::DistributeBroadcastToNetwork(data.to_vec()),
            function::ORIGINAL_UNICAST_NPDU => Bvlc::OriginalUnicastNpdu(data.to_vec()),
            function::ORIGINAL_BROADCAST_NPDU => Bvlc::OriginalBroadcastNpdu(data.to_vec()),
            function::SECURE_BVLL => Bvlc::SecureBvll(data.to_vec()),
            c => return Err(Error::Function(c)),
        })
    }

    /// Appends one BVLC message. Refuses oversized bodies and tables. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let room = MAX_MESSAGE - BVLC_HEADER_LEN;
        let mut out = vec![BVLC_TYPE, self.function(), 0, 0];
        match self {
            Bvlc::Result(code) => out.extend_from_slice(&code.to_be_bytes()),
            Bvlc::WriteBdt(entries) | Bvlc::ReadBdtAck(entries) => {
                if entries.len() > room / 10 {
                    return Err(Error::Unwritable);
                }
                for e in entries {
                    put_bip_address(&mut out, e.address);
                    out.extend_from_slice(&e.mask.octets());
                }
            }
            Bvlc::ForwardedNpdu { origin, npdu } => {
                put_bip_address(&mut out, *origin);
                if npdu.len() > room - 6 {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(npdu);
            }
            Bvlc::RegisterForeignDevice { ttl } => out.extend_from_slice(&ttl.to_be_bytes()),
            Bvlc::ReadBdt | Bvlc::ReadFdt => {}
            Bvlc::ReadFdtAck(entries) => {
                if entries.len() > room / 10 {
                    return Err(Error::Unwritable);
                }
                for e in entries {
                    put_bip_address(&mut out, e.address);
                    out.extend_from_slice(&e.ttl.to_be_bytes());
                    out.extend_from_slice(&e.remaining.to_be_bytes());
                }
            }
            Bvlc::DeleteFdtEntry(address) => put_bip_address(&mut out, *address),
            Bvlc::DistributeBroadcastToNetwork(data)
            | Bvlc::OriginalUnicastNpdu(data)
            | Bvlc::OriginalBroadcastNpdu(data)
            | Bvlc::SecureBvll(data) => {
                if data.len() > room {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
            },
        }
        let len = out.len() as u16; // At most MAX_MESSAGE, which fits.
        out[2..4].copy_from_slice(&len.to_be_bytes());
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Npdu {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an NPDU. The body runs to the end of `b`.
    /// Refuses input above [`MAX_MESSAGE`] with [`Error::TooLong`] first,
    /// then malformed network fields or incomplete input.
    fn parse(b: &[u8]) -> Result<Npdu, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let mut r = Reader::new(b);
        let version = r.u8()?;
        if version != NPDU_VERSION {
            return Err(Error::Version(version));
        }
        let control = r.u8()?;
        let destination = if control & 0x20 != 0 {
            let a = net_address(&mut r)?;
            if a.network == 0 {
                return Err(Error::Network(0));
            }
            Some(a)
        } else {
            None
        };
        let source = if control & 0x08 != 0 {
            let a = net_address(&mut r)?;
            if !valid_source_network(a.network) {
                return Err(Error::Network(a.network));
            }
            if a.mac.is_empty() {
                return Err(Error::SourceAddress);
            }
            Some(a)
        } else {
            None
        };
        let destination = match destination {
            Some(address) => Some(Destination { address, hop_count: r.u8()? }),
            None => None,
        };
        let body = if control & 0x80 != 0 {
            let message_type = r.u8()?;
            let vendor = if message_type >= 0x80 { Some(r.u16_be()?) } else { None };
            NpduBody::Network { message_type, vendor, data: r.rest().to_vec() }
        } else {
            NpduBody::Apdu(r.rest().to_vec())
        };
        Ok(Npdu {
            destination,
            source,
            expecting_reply: control & 0x04 != 0,
            priority: Priority::from_bits(control),
            body,
        })
    }

    /// Appends the NPDU and body. Refuses oversized addresses, empty source addresses,
    /// out-of-range network message fields and oversized bodies. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let source = self.source.as_ref();
        let destination = self.destination.as_ref();
        let mut control = self.priority.bits();
        if matches!(self.body, NpduBody::Network { .. }) {
            control |= 0x80;
        }
        if destination.is_some() {
            control |= 0x20;
        }
        if source.is_some() {
            control |= 0x08;
        }
        if self.expecting_reply {
            control |= 0x04;
        }
        let mut out = vec![NPDU_VERSION, control];
        if let Some(d) = destination {
            put_net_address(&mut out, &d.address)?;
        }
        if let Some(s) = source {
            put_net_address(&mut out, s)?;
        }
        if let Some(d) = destination {
            out.push(d.hop_count);
        }
        match &self.body {
            NpduBody::Apdu(a) => {
                if a.len() > MAX_MESSAGE {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(a);
            },
            NpduBody::Network { message_type, vendor, data } => {
                if data.len() > MAX_MESSAGE {
                    return Err(Error::Unwritable);
                }
                out.push(*message_type);
                if *message_type >= 0x80 {
                    out.extend_from_slice(&vendor.unwrap_or(0).to_be_bytes());
                }
                out.extend_from_slice(data);
            }
        }
        if out.len() > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Apdu {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an APDU. Service bodies run to the end of `b`. Simple
    /// acknowledgments, segment acknowledgments, rejects and aborts have a
    /// fixed size, and bytes after them are an error. Reserved bits are
    /// ignored. Refuses input above [`MAX_MESSAGE`] with [`Error::TooLong`]
    /// first, then malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Apdu, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let mut r = Reader::new(b);
        let first = r.u8()?;
        let segment = |r: &mut Reader| -> Result<Option<Segment>, Error> {
            if first & 0x08 == 0 {
                return Ok(None);
            }
            Ok(Some(Segment { sequence: r.u8()?, window: r.u8()?, more_follows: first & 0x04 != 0 }))
        };
        let apdu = match first >> 4 {
            0 => {
                let limits = r.u8()?;
                let invoke_id = r.u8()?;
                let segment = segment(&mut r)?;
                Apdu::ConfirmedRequest {
                    segmented_response_accepted: first & 0x02 != 0,
                    max_segments: (limits >> 4) & 0x07,
                    max_apdu: limits & 0x0f,
                    invoke_id,
                    segment,
                    service: r.u8()?,
                    data: r.rest().to_vec(),
                }
            }
            1 => Apdu::UnconfirmedRequest { service: r.u8()?, data: r.rest().to_vec() },
            2 => Apdu::SimpleAck { invoke_id: r.u8()?, service: r.u8()? },
            3 => {
                let invoke_id = r.u8()?;
                let segment = segment(&mut r)?;
                Apdu::ComplexAck { invoke_id, segment, service: r.u8()?, data: r.rest().to_vec() }
            }
            4 => Apdu::SegmentAck {
                negative: first & 0x02 != 0,
                server: first & 0x01 != 0,
                invoke_id: r.u8()?,
                sequence: r.u8()?,
                window: r.u8()?,
            },
            5 => Apdu::Error { invoke_id: r.u8()?, service: r.u8()?, data: r.rest().to_vec() },
            6 => Apdu::Reject { invoke_id: r.u8()?, reason: r.u8()? },
            7 => Apdu::Abort { server: first & 0x01 != 0, invoke_id: r.u8()?, reason: r.u8()? },
            t => return Err(Error::PduType(t)),
        };
        r.finish()?;
        Ok(apdu)
    }

    /// Appends the complete APDU. Refuses fields outside their bit widths and bodies
    /// above [`MAX_MESSAGE`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let head = self.pdu_type() << 4;
        let seg_bits = |s: &Option<Segment>| match s {
            Some(s) => 0x08 | if s.more_follows { 0x04 } else { 0 },
            None => 0,
        };
        let put_segment = |out: &mut Vec<u8>, s: &Option<Segment>| {
            if let Some(s) = s {
                out.extend_from_slice(&[s.sequence, s.window]);
            }
        };
        let mut out = Vec::new();
        match self {
            Apdu::ConfirmedRequest {
                segmented_response_accepted,
                max_segments,
                max_apdu,
                invoke_id,
                segment,
                service,
                data,
            } => {
                let sa = if *segmented_response_accepted { 0x02 } else { 0 };
                out.push(head | seg_bits(segment) | sa);
                out.push((max_segments & 0x07) << 4 | (max_apdu & 0x0f));
                out.push(*invoke_id);
                put_segment(&mut out, segment);
                out.push(*service);
                if data.len() > MAX_MESSAGE {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
            }
            Apdu::UnconfirmedRequest { service, data } => {
                out.extend_from_slice(&[head, *service]);
                if data.len() > MAX_MESSAGE {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
            }
            Apdu::SimpleAck { invoke_id, service } => out.extend_from_slice(&[head, *invoke_id, *service]),
            Apdu::ComplexAck { invoke_id, segment, service, data } => {
                out.extend_from_slice(&[head | seg_bits(segment), *invoke_id]);
                put_segment(&mut out, segment);
                out.push(*service);
                if data.len() > MAX_MESSAGE {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
            }
            Apdu::SegmentAck { negative, server, invoke_id, sequence, window } => {
                let flags = if *negative { 0x02 } else { 0 } | if *server { 0x01 } else { 0 };
                out.extend_from_slice(&[head | flags, *invoke_id, *sequence, *window]);
            }
            Apdu::Error { invoke_id, service, data } => {
                out.extend_from_slice(&[head, *invoke_id, *service]);
                if data.len() > MAX_MESSAGE {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(data);
            }
            Apdu::Reject { invoke_id, reason } => out.extend_from_slice(&[head, *invoke_id, *reason]),
            Apdu::Abort { server, invoke_id, reason } => {
                out.extend_from_slice(&[head | if *server { 0x01 } else { 0 }, *invoke_id, *reason]);
            }
        }
        if out.len() > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for WhoIs {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a Who-Is body: empty, or context tags 0 and 1 each holding an
    /// unsigned device instance.
    /// Refuses malformed or trailing input.
    fn parse(data: &[u8]) -> Result<WhoIs, Error> {
        if data.is_empty() {
            return Ok(WhoIs { range: None });
        }
        let (low, used) = context_unsigned(data, 0)?;
        let rest = &data[used..];
        let (high, used) = context_unsigned(rest, 1)?;
        if used != rest.len() {
            return Err(Error::TrailingBytes);
        }
        if low > u64::from(MAX_INSTANCE) || high > u64::from(MAX_INSTANCE) {
            return Err(Error::OutOfRange);
        }
        Ok(WhoIs { range: Some((low as u32, high as u32)) })
    }

    /// Appends both instance limits, or an empty body for an unrestricted query.
    /// Refuses instance limits above [`MAX_INSTANCE`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::new();
        if let Some((low, high)) = self.range {
            for (number, v) in [(0, low), (1, high)] {
                if v > MAX_INSTANCE {
                    return Err(Error::Unwritable);
                }
                Value::Unsigned(u64::from(v)).write_tagged(Class::Context, number, &mut out)?;
            }
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for IAm {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an I-Am body: an object identifier, an unsigned, an
    /// enumerated and an unsigned, all application-tagged.
    /// Refuses malformed or trailing input.
    fn parse(data: &[u8]) -> Result<IAm, Error> {
        let mut values = [Value::Null, Value::Null, Value::Null, Value::Null];
        let mut at = 0;
        for v in &mut values {
            let (value, used) = Value::parse_prefix(data.get(at..).unwrap_or(&[]))?;
            *v = value;
            at += used;
        }
        if at != data.len() {
            return Err(Error::TrailingBytes);
        }
        match values {
            [Value::ObjectId(device), Value::Unsigned(max_apdu), Value::Enumerated(seg), Value::Unsigned(vendor)] => {
                if device.object_type != object_type::DEVICE {
                    return Err(Error::OutOfRange);
                }
                Ok(IAm {
                    device,
                    max_apdu: u32::try_from(max_apdu).map_err(|_| Error::OutOfRange)?,
                    segmentation: Segmentation::from_code(seg).ok_or(Error::OutOfRange)?,
                    vendor: u16::try_from(vendor).map_err(|_| Error::OutOfRange)?,
                })
            }
            _ => Err(Error::ServiceBody),
        }
    }

    /// Appends the four I-Am fields. Refuses a non-device object identifier or an
    /// instance above [`MAX_INSTANCE`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::new();
        Value::ObjectId(self.device).write(&mut out)?;
        Value::Unsigned(u64::from(self.max_apdu)).write(&mut out)?;
        Value::Enumerated(self.segmentation.code()).write(&mut out)?;
        Value::Unsigned(u64::from(self.vendor)).write(&mut out)?;
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

/// A context-tagged primitive whose tag number and application type come from its service.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextValue<const TYPE: u8> {
    /// The context tag number.
    pub number: u8,
    /// The primitive value.
    pub value: Value,
}

impl<const TYPE: u8> ContextValue<TYPE> {
    /// Reads one primitive from the start of `b` with context tag `number`.
    /// Returns the value and its byte count. Refuses a different context
    /// number with [`Error::ServiceBody`], reserved types, opening or closing
    /// tags, and invalid or incomplete values. Later fields are left unread.
    pub fn read(b: &[u8], number: u8) -> Result<(Self, usize), Error> {
        let (value, used) = Value::parse_context(b, number, TYPE)?;
        Ok((Self { number, value }, used))
    }
}

/// A stateless reader of tag headers, including opening and closing tags.
/// It consumes only the header. Read its contents using the service schema.
#[derive(Clone, Copy, Debug, Default)]
pub struct Tags;

impl Decode for Tags {
    type Item = Tag;
    type Error = Error;
    const NAME: &'static str = "BACnet tag";

    /// A tag header needs at most seven bytes.
    fn capacity(&self) -> usize {
        7
    }

    /// Reads one header. Refuses reserved tag numbers and application
    /// opening or closing tags. An incomplete header needs more bytes.
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Tag>, Error> {
        match Tag::parse_prefix(input) {
            Ok((tag, used)) => Ok(Step::Item(tag, used)),
            Err(Error::Truncated) => Ok(Step::Need),
            Err(error) => Err(error),
        }
    }
}

/// A stateless reader of application-tagged primitive values.
/// Context fields use [`ContextValue::read`]; constructed tags use [`Tags`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Values;

impl Decode for Values {
    type Item = Value;
    type Error = Error;
    const NAME: &'static str = "BACnet primitive";

    /// The largest value contents plus the largest tag header.
    fn capacity(&self) -> usize {
        MAX_VALUE_LEN + 7
    }

    /// Reads one primitive. Refuses context tags, reserved types and invalid
    /// or oversized values. An incomplete value needs more bytes.
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Value>, Error> {
        match Value::parse_prefix(input) {
            Ok((value, used)) => Ok(Step::Item(value, used)),
            Err(Error::Truncated) => Ok(Step::Need),
            Err(error) => Err(error),
        }
    }
}

impl<const TYPE: u8> Wire for ContextValue<TYPE> {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one context-tagged primitive as application type TYPE.
    /// Keeps its context number. A context Boolean holds one byte, 0 or 1.
    /// Refuses reserved types, application tags, opening or closing tags,
    /// invalid values and trailing bytes.
    ///
    /// ~~~
    /// use fictionet::stdlib::codec::Wire;
    /// use fictionet::stdlib::bacnet::{ContextValue, Value, tag};
    /// let property = ContextValue::<{ tag::ENUMERATED }>::parse(&[0x19, 0x55]).unwrap();
    /// assert_eq!(property.number, 1);
    /// assert_eq!(property.value, Value::Enumerated(85));
    /// ~~~
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let (tag, _) = Tag::parse_prefix(b)?;
        let (value, used) = Self::read(b, tag.number)?;
        if used != b.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(value)
    }

    /// Appends one context value. Refuses an invalid tag, a different type or oversized contents.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if TYPE != self.value.tag() {
            return Err(Error::Unwritable);
        }
        self.value.write_tagged(Class::Context, self.number, out)
    }
}

/// Application-tagged values in one bounded service body.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ValueList(
    /// Application values in wire order.
    pub Vec<Value>,
);

impl Wire for ValueList {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads values until the input ends. Refuses invalid or incomplete values
    /// and input above [`MAX_MESSAGE`].
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let mut values = Vec::new();
        let mut at = 0;
        while at < b.len() {
            let (v, used) = Value::parse_prefix(&b[at..])?;
            values.push(v);
            at += used;
        }
        Ok(Self(values))
    }

    /// Appends all values. Refuses unwritable values or a body above [`MAX_MESSAGE`].
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.0.len() > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        let mut out = Vec::new();
        for value in &self.0 {
            value.write(&mut out)?;
            if out.len() > MAX_MESSAGE {
                return Err(Error::Unwritable);
            }
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl From<Truncated> for Error {
    #[inline]
    fn from(_: Truncated) -> Self { Error::Truncated }
}

impl From<Trailing> for Error {
    #[inline]
    fn from(_: Trailing) -> Self { Error::TrailingBytes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Lcg, contract};

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn value(bytes: &[u8]) -> Value {
        Value::parse(bytes).unwrap()
    }

    // Encoding examples from ASHRAE 135, Clause 20.2.

    #[test]
    fn primitive_value_examples() {
        let cases = [
            ("00", Value::Null),
            ("10", Value::Boolean(false)),
            ("11", Value::Boolean(true)),
            ("21 48", Value::Unsigned(72)),
            ("31 48", Value::Signed(72)),
            ("44 42900000", Value::Real(72.0)),
            ("55 08 4052000000000000", Value::Double(72.0)),
            ("63 1234FF", Value::OctetString(vec![0x12, 0x34, 0xff])),
            ("82 03 A8", Value::BitString(vec![true, false, true, false, true])),
            ("91 00", Value::Enumerated(0)),
            ("A4 5B011804", Value::Date(Date { year: 91, month: 1, day: 24, weekday: 4 })),
            ("B4 11232D11", Value::Time(Time { hour: 17, minute: 35, second: 45, hundredths: 17 })),
            ("C4 00C0000F", Value::ObjectId(ObjectId { object_type: object_type::BINARY_INPUT, instance: 15 })),
        ];
        for (bytes, v) in cases {
            let bytes = hex(bytes);
            assert_eq!(value(&bytes), v, "{bytes:02x?}");
            assert_eq!(v.to_bytes().unwrap(), bytes, "{v:?}");
        }
        let s = hex("75 19 00 546869732069732061204241436E657420737472696E6721");
        let v = value(&s);
        let Value::CharacterString(cs) = &v else { panic!() };
        assert_eq!(cs.as_str(), Some("This is a BACnet string!"));
        assert_eq!(Value::CharacterString(CharString::utf8("This is a BACnet string!")).to_bytes().unwrap(), s);
    }

    #[test]
    fn integers_take_their_shortest_form() {
        let cases: [(i64, &str); 8] = [
            (0, "31 00"),
            (-1, "31 FF"),
            (127, "31 7F"),
            (128, "32 0080"),
            (-128, "31 80"),
            (-129, "32 FF7F"),
            (i64::MIN, "35 08 8000000000000000"),
            (i64::MAX, "35 08 7FFFFFFFFFFFFFFF"),
        ];
        for (n, bytes) in cases {
            assert_eq!(Value::Signed(n).to_bytes().unwrap(), hex(bytes), "{n}");
            assert_eq!(value(&hex(bytes)), Value::Signed(n));
        }
        assert_eq!(Value::Unsigned(0).to_bytes().unwrap(), [0x21, 0]);
        assert_eq!(Value::Unsigned(256).to_bytes().unwrap(), [0x22, 1, 0]);
        assert_eq!(Value::Unsigned(u64::MAX).to_bytes().unwrap(), hex("25 08 FFFFFFFFFFFFFFFF"));
        assert_eq!(Value::Enumerated(u32::MAX).to_bytes().unwrap(), hex("94 FFFFFFFF"));
        // Leading zero bytes are read.
        assert_eq!(value(&[0x23, 0, 0, 5]), Value::Unsigned(5));
    }

    #[test]
    fn tags() {
        // Extended tag number and the three extended length forms.
        let cases = [
            (Tag { number: 20, class: Class::Context, content: TagContent::Length(2) }, "FA 14"),
            (Tag { number: 6, class: Class::Application, content: TagContent::Length(5) }, "65 05"),
            (Tag { number: 6, class: Class::Application, content: TagContent::Length(254) }, "65 FE 00FE"),
            (Tag { number: 6, class: Class::Application, content: TagContent::Length(65_536) }, "65 FF 00010000"),
            (Tag { number: 3, class: Class::Context, content: TagContent::Opening }, "3E"),
            (Tag { number: 3, class: Class::Context, content: TagContent::Closing }, "3F"),
        ];
        for (t, bytes) in cases {
            let bytes = hex(bytes);
            let mut out = Vec::new();
            t.write(&mut out).unwrap();
            assert_eq!(out, bytes, "{t:?}");
            assert_eq!(Tag::parse(&bytes), Ok(t));
            for n in 0..bytes.len() {
                assert_eq!(Tag::parse(&bytes[..n]), Err(Error::Truncated));
            }
        }
        assert_eq!(Tag::parse(&[0x26]), Err(Error::ApplicationOpenClose));
        assert_eq!(Tag::parse(&[0x27]), Err(Error::ApplicationOpenClose));
    }

    #[test]
    fn extended_tag_number_255_is_reserved() {
        // Clause 20.2.1.2: the extended tag number octet runs 15 to 254;
        // B'11111111' is reserved by ASHRAE.
        assert_eq!(
            Tag::parse(&[0xf9, 0xff, 0x00]),
            Err(Error::ReservedTag(255))
        );
        assert_eq!(Tag::parse(&[0xfe, 0xff]), Err(Error::ReservedTag(255)));
        assert_eq!(
            Tag::parse(&[0xf9, 0xfe]),
            Ok(Tag {
                number: 254,
                class: Class::Context,
                content: TagContent::Length(1)
            })
        );
        // The writer never writes the reserved number.
        let mut out = Vec::new();
        assert_eq!(Tag { number: 255, class: Class::Context, content: TagContent::Opening }.write(&mut out), Err(Error::Unwritable));
        assert!(out.is_empty());
    }

    #[test]
    fn bad_values() {
        assert_eq!(Value::parse(&[]), Err(Error::Truncated));
        assert_eq!(Value::parse(&[0x09, 0]), Err(Error::ContextTag(0)));
        assert_eq!(Value::parse(&[0x3e]), Err(Error::ContextTag(3)));
        assert_eq!(Value::parse(&[0xd0]), Err(Error::ReservedTag(13)));
        assert_eq!(Value::parse(&[0xf0, 40]), Err(Error::ReservedTag(40)));
        assert_eq!(
            Value::parse(&[0x12]),
            Err(Error::ValueLength { tag: 1, len: 2 })
        );
        assert_eq!(
            Value::parse(&[0x01, 0]),
            Err(Error::ValueLength { tag: 0, len: 1 })
        );
        assert_eq!(
            Value::parse(&[0x20]),
            Err(Error::ValueLength { tag: 2, len: 0 })
        );
        assert_eq!(
            Value::parse(&hex("25 09 000000000000000001")),
            Err(Error::ValueLength { tag: 2, len: 9 })
        );
        assert_eq!(
            Value::parse(&hex("95 05 0000000001")),
            Err(Error::ValueLength { tag: 9, len: 5 })
        );
        assert_eq!(
            Value::parse(&hex("43 000000")),
            Err(Error::ValueLength { tag: 4, len: 3 })
        );
        assert_eq!(
            Value::parse(&hex("54 00000000")),
            Err(Error::ValueLength { tag: 5, len: 4 })
        );
        assert_eq!(
            Value::parse(&hex("A3 000000")),
            Err(Error::ValueLength { tag: 10, len: 3 })
        );
        assert_eq!(
            Value::parse(&[0x70]),
            Err(Error::ValueLength { tag: 7, len: 0 })
        );
        assert_eq!(
            Value::parse(&[0x80]),
            Err(Error::ValueLength { tag: 8, len: 0 })
        );
        assert_eq!(Value::parse(&[0x82, 8, 0]), Err(Error::BitString(8)));
        assert_eq!(Value::parse(&[0x81, 1]), Err(Error::BitString(1)));
        assert_eq!(Value::parse(&[0x81, 0]), Ok(Value::BitString(vec![])));
        // A length past the limit, and one past the bytes.
        assert_eq!(
            Value::parse(&hex("65 FF FFFFFFFF")),
            Err(Error::ValueLength {
                tag: 6,
                len: u32::MAX
            })
        );
        assert_eq!(Value::parse(&hex("63 0102")), Err(Error::Truncated));
        assert_eq!(ValueList::parse(&hex("21 01 21")).map(|values| values.0), Err(Error::Truncated));
        assert_eq!(ValueList::parse(&hex("21 01 10")).map(|values| values.0), Ok(vec![Value::Unsigned(1), Value::Boolean(false)]));
    }

    #[test]
    fn writers_refuse_long_strings() {
        for value in [
            Value::OctetString(vec![7; MAX_VALUE_LEN + 10]),
            Value::BitString(vec![true; MAX_VALUE_LEN * 8]),
            Value::CharacterString(CharString { charset: 5, bytes: vec![b'a'; MAX_VALUE_LEN] }),
            Value::ObjectId(ObjectId { object_type: 5000, instance: u32::MAX }),
        ] {
            contract::check_wire_value(&value);
            assert_eq!(value.to_bytes(), Err(Error::Unwritable));
        }
        // Bit strings of every length up to 17 round trip.
        for n in 0..17 {
            let bits: Vec<bool> = (0..n).map(|i| i % 3 == 0).collect();
            assert_eq!(value(&Value::BitString(bits.clone()).to_bytes().unwrap()), Value::BitString(bits));
        }
    }

    // Who-Is and I-Am.

    #[test]
    fn who_is() {
        let all = WhoIs::parse(&[]).unwrap();
        assert_eq!(all, WhoIs { range: None });
        assert!(all.matches(0) && all.matches(MAX_INSTANCE));
        assert_eq!(all.to_bytes().unwrap(), []);
        let some = WhoIs { range: Some((3, 300)) };
        let bytes = some.to_bytes().unwrap();
        assert_eq!(bytes, [0x09, 3, 0x1a, 0x01, 0x2c]);
        assert_eq!(WhoIs::parse(&bytes), Ok(some));
        assert!(some.matches(3) && some.matches(300) && !some.matches(2) && !some.matches(301));
        // Only one limit, the limits swapped, application tags, extra bytes.
        assert_eq!(WhoIs::parse(&[0x09, 3]), Err(Error::Truncated));
        assert_eq!(WhoIs::parse(&[0x19, 3, 0x09, 4]), Err(Error::ServiceBody));
        assert_eq!(WhoIs::parse(&[0x21, 3, 0x29, 4]), Err(Error::ServiceBody));
        assert_eq!(WhoIs::parse(&[0x09, 3, 0x19, 4, 0]), Err(Error::TrailingBytes));
        assert_eq!(WhoIs::parse(&[0x0e]), Err(Error::ServiceBody));
        assert_eq!(WhoIs::parse(&[0x08, 0x19, 1]), Err(Error::ServiceBody));
        // An instance past 22 bits.
        assert_eq!(WhoIs::parse(&[0x09, 0, 0x1b, 0x40, 0, 0]), Err(Error::OutOfRange));
        let big = WhoIs { range: Some((0, u32::MAX)) };
        contract::check_wire_value(&big);
        assert_eq!(big.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn i_am() {
        let bytes = hex("C4 02000001 22 05C4 91 00 21 0F");
        let i_am = IAm::parse(&bytes).unwrap();
        assert_eq!(
            i_am,
            IAm { device: ObjectId::device(1), max_apdu: 1476, segmentation: Segmentation::Both, vendor: 15 }
        );
        assert_eq!(i_am.to_bytes().unwrap(), bytes);
        for n in 0..bytes.len() {
            assert!(IAm::parse(&bytes[..n]).is_err(), "{n} bytes");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(IAm::parse(&extra), Err(Error::TrailingBytes));
        // Fields of the wrong type or out of range.
        assert_eq!(IAm::parse(&hex("21 01 22 05C4 91 00 21 0F")), Err(Error::ServiceBody));
        assert_eq!(IAm::parse(&hex("C4 02000001 22 05C4 91 04 21 0F")), Err(Error::OutOfRange));
        assert_eq!(IAm::parse(&hex("C4 02000001 22 05C4 91 00 23 010000")), Err(Error::OutOfRange));
        assert_eq!(IAm::parse(&hex("C4 02000001 25 05 0100000000 91 00 21 0F")), Err(Error::OutOfRange));
        for s in [Segmentation::Both, Segmentation::Transmit, Segmentation::Receive, Segmentation::NoSegmentation] {
            assert_eq!(Segmentation::from_code(s.code()), Some(s));
        }
    }

    // APDUs, from ASHRAE 135 Annex F.

    #[test]
    fn npdu_refuses_oversized_input_first() {
        let mut bytes = vec![0; MAX_MESSAGE + 1];
        bytes[0] = NPDU_VERSION;
        assert_eq!(Npdu::parse(&bytes), Err(Error::TooLong));
        contract::check_wire::<Npdu>(&bytes);
        bytes[0] = 0xff;
        assert_eq!(Npdu::parse(&bytes), Err(Error::TooLong));
        contract::check_wire::<Npdu>(&bytes);
    }

    #[test]
    fn apdu_refuses_oversized_input_first() {
        let mut bytes = vec![0; MAX_MESSAGE + 1];
        bytes[..2].copy_from_slice(&[0x10, unconfirmed::WHO_IS]);
        assert_eq!(Apdu::parse(&bytes), Err(Error::TooLong));
        contract::check_wire::<Apdu>(&bytes);
        bytes[0] = 0xff;
        assert_eq!(Apdu::parse(&bytes), Err(Error::TooLong));
        contract::check_wire::<Apdu>(&bytes);
    }

    #[test]
    fn prefix_readers_obey_bounded_decode_contracts() {
        use fictionet::stdlib::codec::test_support::decode_all;
        let tags = [0x3e, 0x3f, 0xf9, 15];
        contract::check_decode_with_alloc_limit(|| Tags, &tags, 2 * Tags.capacity());
        assert_eq!(decode_all(|| Tags, &tags).0.len(), 3);
        let values = ValueList(vec![Value::Real(72.3), Value::Unsigned(85)]);
        let bytes = values.to_bytes().unwrap();
        contract::check_decode_with_alloc_limit(|| Values, &bytes, 2 * Values.capacity());
        assert_eq!(decode_all(|| Values, &bytes), (values.0, None));
        let oversized = [0x65, 255, 0xff, 0xff, 0xff, 0xff];
        contract::check_decode_with_alloc_limit(|| Values, &oversized, 2 * Values.capacity());
        assert!(Values.decode(&oversized, false).is_err());
    }

    #[test]
    fn read_property_example() {
        // F.3.5: ReadProperty of Analog Input 5's Present_Value.
        let req = hex("00 00 01 0C 0C 00000005 19 55");
        let apdu = Apdu::parse(&req).unwrap();
        let Apdu::ConfirmedRequest { max_apdu, invoke_id, service, data, segment, .. } = &apdu else { panic!() };
        assert_eq!((*max_apdu, *invoke_id, *service, *segment), (0, 1, confirmed::READ_PROPERTY, None));
        assert_eq!(max_apdu_octets(*max_apdu), Some(50));
        assert_eq!(apdu.to_bytes().unwrap(), req);
        // Read each context field using the service's schema.
        let (id, used) = ContextValue::<{ tag::OBJECT_IDENTIFIER }>::read(data, 0).unwrap();
        assert_eq!(id.value, Value::ObjectId(ObjectId { object_type: object_type::ANALOG_INPUT, instance: 5 }));
        let (property, next) = ContextValue::<{ tag::ENUMERATED }>::read(&data[used..], 1).unwrap();
        assert_eq!(property.value, Value::Enumerated(85));
        assert_eq!(used + next, data.len());

        // The answer: 72.3 between opening and closing tag 3.
        let ack = hex("30 01 0C 0C 00000005 19 55 3E 44 4290999A 3F");
        let apdu = Apdu::parse(&ack).unwrap();
        let Apdu::ComplexAck { invoke_id: 1, segment: None, service: 12, data } = &apdu else { panic!() };
        let (read_id, mut at) = ContextValue::<{ tag::OBJECT_IDENTIFIER }>::read(data, 0).unwrap();
        assert_eq!(read_id, id);
        let (read_property, used) = ContextValue::<{ tag::ENUMERATED }>::read(&data[at..], 1).unwrap();
        assert_eq!(read_property, property);
        at += used;
        let Step::Item(opening, used) = Tags.decode(&data[at..], true).unwrap() else { panic!() };
        assert_eq!(opening, Tag { number: 3, class: Class::Context, content: TagContent::Opening });
        at += used;
        let Step::Item(value, used) = Values.decode(&data[at..], true).unwrap() else { panic!() };
        assert_eq!(value, Value::Real(72.3));
        at += used;
        let Step::Item(closing, used) = Tags.decode(&data[at..], true).unwrap() else { panic!() };
        assert_eq!(closing, Tag { number: 3, class: Class::Context, content: TagContent::Closing });
        assert_eq!(at + used, data.len());
        assert_eq!(apdu.to_bytes().unwrap(), ack);
    }

    #[test]
    fn every_apdu_type() {
        let seg = Some(Segment { sequence: 2, window: 4, more_follows: true });
        let cases = [
            (
                Apdu::ConfirmedRequest {
                    segmented_response_accepted: true,
                    max_segments: 4,
                    max_apdu: 5,
                    invoke_id: 9,
                    segment: seg,
                    service: confirmed::WRITE_PROPERTY,
                    data: vec![1, 2],
                },
                "0E 45 09 02 04 0F 0102",
            ),
            (Apdu::UnconfirmedRequest { service: unconfirmed::WHO_IS, data: vec![] }, "10 08"),
            (Apdu::SimpleAck { invoke_id: 9, service: 15 }, "20 09 0F"),
            (Apdu::ComplexAck { invoke_id: 9, segment: seg, service: 12, data: vec![3] }, "3C 09 02 04 0C 03"),
            (Apdu::SegmentAck { negative: true, server: true, invoke_id: 9, sequence: 2, window: 4 }, "43 09 02 04"),
            (Apdu::Error { invoke_id: 9, service: 12, data: hex("91 01 91 1F") }, "50 09 0C 91 01 91 1F"),
            (Apdu::Reject { invoke_id: 9, reason: 4 }, "60 09 04"),
            (Apdu::Abort { server: true, invoke_id: 9, reason: 5 }, "71 09 05"),
        ];
        for (apdu, bytes) in cases {
            let bytes = hex(bytes);
            assert_eq!(apdu.to_bytes().unwrap(), bytes, "{apdu:?}");
            assert_eq!(Apdu::parse(&bytes), Ok(apdu.clone()));
            // Every prefix short of the fixed header is refused.
            let header = bytes.len() - apdu_data_len(&apdu);
            for n in 0..header {
                assert_eq!(Apdu::parse(&bytes[..n]), Err(Error::Truncated), "{apdu:?} {n}");
            }
        }
        // Error class and code read as values.
        let Apdu::Error { data, .. } = Apdu::parse(&hex("50 09 0C 91 01 91 1F")).unwrap() else { panic!() };
        assert_eq!(ValueList::parse(&data).map(|values| values.0), Ok(vec![Value::Enumerated(1), Value::Enumerated(31)]));
        assert_eq!(Apdu::parse(&[0x80, 0]), Err(Error::PduType(8)));
        assert_eq!(Apdu::parse(&[0xf0]), Err(Error::PduType(15)));
        assert_eq!(Apdu::parse(&hex("20 09 0F 00")), Err(Error::TrailingBytes));
        assert_eq!(Apdu::parse(&hex("71 09 05 00")), Err(Error::TrailingBytes));
        assert_eq!(max_segments(0), None);
        assert_eq!(max_segments(4), Some(16));
        assert_eq!(max_segments(7), None);
        assert_eq!(max_apdu_octets(5), Some(1476));
        assert_eq!(max_apdu_octets(6), None);
    }

    fn apdu_data_len(a: &Apdu) -> usize {
        match a {
            Apdu::ConfirmedRequest { data, .. }
            | Apdu::UnconfirmedRequest { data, .. }
            | Apdu::ComplexAck { data, .. }
            | Apdu::Error { data, .. } => data.len(),
            _ => 0,
        }
    }

    // NPDUs.

    #[test]
    fn npdu_examples() {
        // A global broadcast I-Am: destination network 0xFFFF, no address,
        // hop count 255.
        let bytes = hex("01 20 FFFF 00 FF 10 00");
        let npdu = Npdu::parse(&bytes).unwrap();
        assert_eq!(
            npdu.destination,
            Some(Destination { address: NetAddress { network: 0xffff, mac: vec![] }, hop_count: 255 })
        );
        assert_eq!(npdu.source, None);
        assert_eq!(npdu.apdu(), Some(&[0x10, 0x00][..]));
        assert_eq!(npdu.to_bytes().unwrap(), bytes);

        // A routed request from MS/TP station 5 on network 2, expecting a
        // reply at urgent priority.
        let bytes = hex("01 0D 0002 01 05 00 05 01 0C");
        let npdu = Npdu::parse(&bytes).unwrap();
        assert_eq!(npdu.source, Some(NetAddress { network: 2, mac: vec![5] }));
        assert!(npdu.expecting_reply);
        assert_eq!(npdu.priority, Priority::Urgent);
        assert_eq!(npdu.to_bytes().unwrap(), bytes);
        // The reply goes back to that station through the router.
        let reply = npdu.reply(vec![0x20, 0x01, 0x0c]);
        assert_eq!(reply.to_bytes().unwrap(), hex("01 21 0002 01 05 FF 20 01 0C"));

        // Both addresses: destination fields, source fields, then the hop
        // count.
        let bytes = hex("01 2B 0003 02 AABB 0002 01 05 07 10 08");
        let npdu = Npdu::parse(&bytes).unwrap();
        assert_eq!(npdu.destination.as_ref().unwrap().hop_count, 7);
        assert_eq!(npdu.destination.as_ref().unwrap().address.mac, [0xaa, 0xbb]);
        assert_eq!(npdu.priority, Priority::LifeSafety);
        assert_eq!(npdu.to_bytes().unwrap(), bytes);
        for n in 0..bytes.len() - 2 {
            assert!(Npdu::parse(&bytes[..n]).is_err(), "{n} bytes");
        }

        // A network layer message: Who-Is-Router-To-Network, and a
        // proprietary one with its vendor.
        let bytes = hex("01 80 00");
        let npdu = Npdu::parse(&bytes).unwrap();
        assert_eq!(npdu.body, NpduBody::Network { message_type: 0, vendor: None, data: vec![] });
        assert_eq!(npdu.apdu(), None);
        assert_eq!(npdu.to_bytes().unwrap(), bytes);
        let bytes = hex("01 80 80 0104 AA");
        let npdu = Npdu::parse(&bytes).unwrap();
        assert_eq!(npdu.body, NpduBody::Network { message_type: 0x80, vendor: Some(260), data: vec![0xaa] });
        assert_eq!(npdu.to_bytes().unwrap(), bytes);
        assert_eq!(Npdu::parse(&hex("01 80 80 01")), Err(Error::Truncated));
    }

    #[test]
    fn bad_npdus() {
        assert_eq!(Npdu::parse(&[]), Err(Error::Truncated));
        assert_eq!(Npdu::parse(&[1]), Err(Error::Truncated));
        assert_eq!(Npdu::parse(&[2, 0]), Err(Error::Version(2)));
        assert_eq!(Npdu::parse(&hex("01 08 0002 00 10 08")), Err(Error::SourceAddress));
        assert_eq!(Npdu::parse(&hex("01 20 0002 03 0102")), Err(Error::Truncated));
        // An empty source cannot be written.
        let n = Npdu { source: Some(NetAddress { network: 2, mac: vec![] }), ..Npdu::local(vec![0x10, 0x08]) };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        // Addresses above 255 bytes cannot be written.
        let n = Npdu {
            destination: Some(Destination { address: NetAddress { network: 1, mac: vec![9; 300] }, hop_count: 1 }),
            ..Npdu::local(vec![])
        };
        contract::check_wire_value(&n);
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        // A vendor on a standard message type is not written.
        let n =
            Npdu { body: NpduBody::Network { message_type: 1, vendor: Some(5), data: vec![] }, ..Npdu::local(vec![]) };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        for p in 0..4 {
            assert_eq!(Priority::from_bits(p).bits(), p);
        }
    }

    // BVLC, from ASHRAE 135 Annex J.

    #[test]
    fn bvlc_functions() {
        let a = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), PORT);
        let b = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 47809);
        let cases = [
            (Bvlc::Result(result::REGISTER_FOREIGN_DEVICE_NAK), "81 00 0006 0030"),
            (
                Bvlc::WriteBdt(vec![BdtEntry { address: a, mask: Ipv4Addr::new(255, 255, 255, 255) }]),
                "81 01 000E C0A8010A BAC0 FFFFFFFF",
            ),
            (Bvlc::ReadBdt, "81 02 0004"),
            (Bvlc::ReadBdtAck(vec![]), "81 03 0004"),
            (Bvlc::ForwardedNpdu { origin: b, npdu: hex("01 00 10 08") }, "81 04 000E 0A000001 BAC1 01001008"),
            (Bvlc::RegisterForeignDevice { ttl: 60 }, "81 05 0006 003C"),
            (Bvlc::ReadFdt, "81 06 0004"),
            (
                Bvlc::ReadFdtAck(vec![FdtEntry { address: b, ttl: 60, remaining: 85 }]),
                "81 07 000E 0A000001 BAC1 003C 0055",
            ),
            (Bvlc::DeleteFdtEntry(b), "81 08 000A 0A000001 BAC1"),
            (Bvlc::DistributeBroadcastToNetwork(hex("01 00 10 08")), "81 09 0008 01001008"),
            (Bvlc::OriginalUnicastNpdu(hex("01 04 00 05 01 0C")), "81 0A 000A 010400050 10C"),
            (Bvlc::OriginalBroadcastNpdu(hex("01 00 10 08")), "81 0B 0008 01001008"),
            (Bvlc::SecureBvll(vec![1, 2, 3]), "81 0C 0007 010203"),
        ];
        for (bvlc, bytes) in cases {
            let bytes = hex(bytes);
            assert_eq!(bvlc.to_bytes().unwrap(), bytes, "{bvlc:?}");
            assert_eq!(Bvlc::parse(&bytes), Ok(bvlc.clone()));
            for n in 0..bytes.len() {
                assert!(Bvlc::parse(&bytes[..n]).is_err(), "{bvlc:?} {n}");
            }
        }
        assert_eq!(Bvlc::OriginalUnicastNpdu(vec![1]).npdu(), Some(&[1][..]));
        assert_eq!(Bvlc::ForwardedNpdu { origin: a, npdu: vec![2] }.npdu(), Some(&[2][..]));
        assert_eq!(Bvlc::ReadBdt.npdu(), None);
    }

    #[test]
    fn bad_bvlc() {
        assert_eq!(Bvlc::parse(&[0x81, 0x0b, 0]), Err(Error::Truncated));
        assert_eq!(Bvlc::parse(&hex("82 0B 0004")), Err(Error::NotBacnetIp(0x82)));
        assert_eq!(Bvlc::parse(&hex("81 0B 0005")), Err(Error::Length(5)));
        assert_eq!(Bvlc::parse(&hex("81 0B 0003 00")), Err(Error::Length(3)));
        assert_eq!(Bvlc::parse(&hex("81 0B 0004 00")), Err(Error::Length(4)));
        assert_eq!(Bvlc::parse(&hex("81 0D 0004")), Err(Error::Function(0x0d)));
        assert_eq!(Bvlc::parse(&hex("81 00 0005 00")), Err(Error::FunctionData(0)));
        assert_eq!(Bvlc::parse(&hex("81 01 0005 00")), Err(Error::FunctionData(1)));
        assert_eq!(Bvlc::parse(&hex("81 02 0005 00")), Err(Error::FunctionData(2)));
        assert_eq!(Bvlc::parse(&hex("81 04 0009 0A00000 1BA")), Err(Error::FunctionData(4)));
        assert_eq!(Bvlc::parse(&hex("81 07 0005 00")), Err(Error::FunctionData(7)));
        assert_eq!(Bvlc::parse(&hex("81 08 0005 00")), Err(Error::FunctionData(8)));
        let mut long = hex("81 0A FFFF");
        long.resize(0xffff, 0);
        assert_eq!(Bvlc::parse(&long), Err(Error::Length(0xffff)));
        let a = SocketAddrV4::new(Ipv4Addr::LOCALHOST, PORT);
        let entry = FdtEntry { address: a, ttl: 1, remaining: 2 };
        for value in [
            Bvlc::OriginalUnicastNpdu(vec![0; 70_000]),
            Bvlc::ForwardedNpdu { origin: a, npdu: vec![0; 70_000] },
            Bvlc::ReadFdtAck(vec![entry; 7000]),
        ] {
            contract::check_wire_value(&value);
            assert_eq!(value.to_bytes(), Err(Error::Unwritable));
        }
    }

    #[test]
    fn errors_display() {
        let all = [
            Error::Truncated,
            Error::TrailingBytes,
            Error::NotBacnetIp(1),
            Error::Length(2),
            Error::Function(3),
            Error::FunctionData(4),
            Error::Version(5),
            Error::SourceAddress,
            Error::PduType(8),
            Error::ReservedTag(13),
            Error::ApplicationOpenClose,
            Error::ContextTag(2),
            Error::ValueLength { tag: 4, len: 3 },
            Error::BitString(9),
            Error::ServiceBody,
            Error::OutOfRange,
            Error::Network(0),
            Error::TooLong,
        ];
        for e in all {
            let s = e.to_string();
            assert!(!s.is_empty());
            let _: &dyn std::error::Error = &e;
        }
    }

    #[test]
    fn object_id_packing_refuses_out_of_range_fields() {
        let last = ObjectId {
            object_type: MAX_OBJECT_TYPE,
            instance: MAX_INSTANCE,
        };
        assert_eq!(last.to_u32(), Some(u32::MAX));
        assert_eq!(ObjectId::from_u32(last.to_u32().unwrap()), last);
        for id in [
            ObjectId {
                object_type: MAX_OBJECT_TYPE + 1,
                ..last
            },
            ObjectId {
                instance: MAX_INSTANCE + 1,
                ..last
            },
        ] {
            assert_eq!(id.to_u32(), None);
            let value = Value::ObjectId(id);
            contract::check_wire_value(&value);
            assert_eq!(value.to_bytes(), Err(Error::Unwritable));
        }
    }

    #[test]
    fn context_tagged_values() {
        // ReadProperty's request body, written and read field by field.
        let ai5 = ObjectId { object_type: object_type::ANALOG_INPUT, instance: 5 };
        let mut body = Vec::new();
        ContextValue::<{ tag::OBJECT_IDENTIFIER }> { number: 0, value: Value::ObjectId(ai5) }.write(&mut body).unwrap();
        ContextValue::<{ tag::ENUMERATED }> { number: 1, value: Value::Enumerated(85) }.write(&mut body).unwrap();
        assert_eq!(body, hex("0C 00000005 19 55"));
        let (id, used) = ContextValue::<{ tag::OBJECT_IDENTIFIER }>::read(&body, 0).unwrap();
        assert_eq!(id.value, Value::ObjectId(ai5));
        assert_eq!(
            ContextValue::<{ tag::ENUMERATED }>::parse(&body[used..]),
            Ok(ContextValue {
                number: 1,
                value: Value::Enumerated(85)
            })
        );
        // A context Boolean holds one byte (Clause 20.2.3).
        assert_eq!(Value::Boolean(true).to_bytes().unwrap(), [0x11]);
        let mut out = Vec::new();
        ContextValue::<{ tag::BOOLEAN }> { number: 2, value: Value::Boolean(true) }.write(&mut out).unwrap();
        assert_eq!(out, [0x29, 0x01]);
        assert_eq!(
            ContextValue::<{ tag::BOOLEAN }>::parse(&out),
            Ok(ContextValue {
                number: 2,
                value: Value::Boolean(true)
            })
        );
        assert_eq!(
            ContextValue::<{ tag::BOOLEAN }>::parse(&[0x29, 0x02]),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            ContextValue::<{ tag::BOOLEAN }>::parse(&[0x28]),
            Err(Error::ValueLength { tag: 1, len: 0 })
        );
        // The wrong number, an application tag, an opening tag, a reserved type.
        assert_eq!(ContextValue::<{ tag::ENUMERATED }>::read(&[0x19, 0x55], 0), Err(Error::ServiceBody));
        assert_eq!(ContextValue::<{ tag::ENUMERATED }>::parse(&[0x19, 0x55]).unwrap().number, 1);
        assert_eq!(
            ContextValue::<{ tag::ENUMERATED }>::parse(&[0x91, 0x55]),
            Err(Error::ServiceBody)
        );
        assert_eq!(
            ContextValue::<{ tag::NULL }>::parse(&[0x3e]),
            Err(Error::ServiceBody)
        );
        assert_eq!(
            ContextValue::<13>::parse(&[0x19, 0x55]),
            Err(Error::ReservedTag(13))
        );
        assert_eq!(
            ContextValue::<{ tag::ENUMERATED }>::parse(&[0x1a, 0x55]),
            Err(Error::Truncated)
        );
        assert_eq!(
            ContextValue::<{ tag::ENUMERATED }>::parse(&[]),
            Err(Error::Truncated)
        );
        // Extended context tag numbers.
        let mut out = Vec::new();
        ContextValue::<{ tag::UNSIGNED }> { number: 40, value: Value::Unsigned(300) }.write(&mut out).unwrap();
        assert_eq!(out, hex("FA 28 012C"));
        assert_eq!(
            ContextValue::<{ tag::UNSIGNED }>::parse(&out),
            Ok(ContextValue {
                number: 40,
                value: Value::Unsigned(300)
            })
        );
        // Who-Is writes its limits the same way.
        assert_eq!(WhoIs { range: Some((3, 300)) }.to_bytes().unwrap(), hex("09 03 1A 012C"));
    }

    #[test]
    fn apdu_accessors() {
        let req = Apdu::parse(&hex("00 05 07 0C 0C 00000005 19 55")).unwrap();
        assert_eq!((req.invoke_id(), req.service()), (Some(7), Some(confirmed::READ_PROPERTY)));
        assert_eq!(req.data(), Some(&hex("0C 00000005 19 55")[..]));
        // Answer with the request's invoke ID and service.
        let ack = Apdu::SimpleAck { invoke_id: req.invoke_id().unwrap(), service: req.service().unwrap() };
        assert_eq!(ack.to_bytes().unwrap(), [0x20, 7, 12]);
        assert_eq!(ack.data(), None);
        let who = WhoIs { range: None }.to_apdu().unwrap();
        assert_eq!((who.invoke_id(), who.service(), who.data()), (None, Some(unconfirmed::WHO_IS), Some(&[][..])));
        let abort = Apdu::Abort { server: true, invoke_id: 3, reason: 4 };
        assert_eq!((abort.invoke_id(), abort.service()), (Some(3), None));
        let r = Apdu::Reject { invoke_id: 2, reason: 1 };
        assert_eq!((r.invoke_id(), r.service(), r.data()), (Some(2), None, None));
    }

    #[test]
    fn module_doc_example() {
        // The example at the top of this file, run here as well.
        let datagram = [0x81, 0x0b, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08];
        let bvlc = Bvlc::parse(&datagram).unwrap();
        let npdu = Npdu::parse(bvlc.npdu().unwrap()).unwrap();
        let apdu = Apdu::parse(npdu.apdu().unwrap()).unwrap();
        let Apdu::UnconfirmedRequest { service, data } = &apdu else { panic!("not unconfirmed") };
        assert_eq!(*service, unconfirmed::WHO_IS);
        assert!(WhoIs::parse(data).unwrap().matches(1234));
        let i_am = IAm {
            device: ObjectId::device(1234),
            max_apdu: 1476,
            segmentation: Segmentation::NoSegmentation,
            vendor: 260,
        };
        let reply = Bvlc::OriginalBroadcastNpdu(npdu.reply(i_am.to_apdu().unwrap().to_bytes().unwrap()).to_bytes().unwrap());
        assert_eq!(reply.to_bytes().unwrap(), hex("810B0015 0100 1000 C4020004D2 2205C4 9103 220104"));
    }

    // Findings from review: each case below failed before its fix.

    #[test]
    fn value_lists_are_bounded() {
        // 16 MiB of Null tags would have made 16 million values.
        assert_eq!(ValueList::parse(&vec![0; MAX_MESSAGE + 1]).map(|values| values.0), Err(Error::TooLong));
        assert_eq!(ValueList::parse(&vec![0; MAX_MESSAGE]).map(|values| values.0).map(|v| v.len()), Ok(MAX_MESSAGE));
    }

    #[test]
    fn expecting_reply_follows_the_apdu() {
        // A confirmed GetAlarmSummary request expects a reply.
        assert!(Npdu::local(hex("00 05 01 03")).expecting_reply);
        assert_eq!(Npdu::local(hex("00 05 01 03")).to_bytes().unwrap(), hex("01 04 00 05 01 03"));
        // A segment of a complex acknowledgment does too; a whole one does not.
        assert!(Npdu::local(hex("38 01 00 04 0C")).expecting_reply);
        assert!(!Npdu::local(hex("30 01 0C")).expecting_reply);
        assert!(!Npdu::local(hex("10 08")).expecting_reply);
        assert!(!Npdu::local(vec![]).expecting_reply);
        let request = Npdu::parse(&hex("01 0C 0002 01 05 00 05 01 0C")).unwrap();
        assert!(request.reply(hex("38 01 00 04 0C")).expecting_reply);
        assert!(!request.reply(hex("20 01 0C")).expecting_reply);
    }

    #[test]
    fn network_numbers_follow_clause_6_2_2_1() {
        // DNET 1 to 65535, SNET 1 to 65534.
        assert_eq!(Npdu::parse(&hex("01 20 0000 00 FF 10 08")), Err(Error::Network(0)));
        assert_eq!(Npdu::parse(&hex("01 08 FFFF 01 01 10 08")), Err(Error::Network(0xffff)));
        assert_eq!(Npdu::parse(&hex("01 08 0000 01 01 10 08")), Err(Error::Network(0)));
        assert!(Npdu::parse(&hex("01 08 FFFE 01 01 10 08")).is_ok());
        assert!(Npdu::parse(&hex("01 20 FFFF 00 FF 10 08")).is_ok());
        // Writers leave such addresses out, so a reply never turns a
        // source of 0xFFFF into a global broadcast.
        let n = Npdu { source: Some(NetAddress { network: 0xffff, mac: vec![1] }), ..Npdu::local(hex("10 08")) };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        let n = Npdu {
            destination: Some(Destination { address: NetAddress { network: 0, mac: vec![] }, hop_count: 255 }),
            ..Npdu::local(hex("10 08"))
        };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&n);
    }

    #[test]
    fn oversized_strings_are_refused_without_splitting_characters() {
        for text in [
            "a".repeat(MAX_VALUE_LEN - 2) + "é",
            "a".repeat(MAX_VALUE_LEN - 3) + "\u{1F600}",
        ] {
            let value = Value::CharacterString(CharString::utf8(&text));
            contract::check_wire_value(&value);
            assert_eq!(value.to_bytes(), Err(Error::Unwritable));
        }
        for charset in [3, 4] {
            let value = Value::CharacterString(CharString { charset, bytes: vec![0; MAX_VALUE_LEN + 8] });
            contract::check_wire_value(&value);
            assert_eq!(value.to_bytes(), Err(Error::Unwritable));
        }
    }

    #[test]
    fn i_am_names_a_device() {
        // Clause 16.10: the I-Am identifier is a Device object.
        assert_eq!(IAm::parse(&hex("C4 00000001 22 05C4 91 03 21 0F")), Err(Error::OutOfRange));
        let i_am = IAm {
            device: ObjectId { object_type: object_type::ANALOG_INPUT, instance: 1 },
            max_apdu: 1476,
            segmentation: Segmentation::NoSegmentation,
            vendor: 15,
        };
        contract::check_wire_value(&i_am);
        assert_eq!(i_am.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn forbidden_tag_forms() {
        // Clause 20.2.1.2: tag numbers 0 to 14 go in the first byte.
        assert_eq!(Tag::parse(&hex("F9 01 00")), Err(Error::ReservedTag(1)));
        assert_eq!(Tag::parse(&hex("F9 0E 00")), Err(Error::ReservedTag(14)));
        assert!(Tag::parse(&hex("F9 0F")).is_ok());
        // Clause 20.2.3: an application Boolean is its length field alone.
        assert_eq!(
            Value::parse(&hex("15 00")),
            Err(Error::ValueLength {
                tag: tag::BOOLEAN,
                len: 0
            })
        );
        assert_eq!(
            Value::parse(&hex("15 01")),
            Err(Error::ValueLength {
                tag: tag::BOOLEAN,
                len: 1
            })
        );
        assert_eq!(Value::parse(&hex("10")), Ok(Value::Boolean(false)));
    }

    // Random input.

    /// Reads `b` every way this module can, checking that what reads also
    /// writes and reads back the same.
    fn check(b: &[u8]) {
        contract::check_wire::<Tag>(b);
        contract::check_wire::<Value>(b);
        contract::check_wire::<ValueList>(b);
        contract::check_wire::<Bvlc>(b);
        contract::check_wire::<Npdu>(b);
        contract::check_wire::<Apdu>(b);
        contract::check_wire::<WhoIs>(b);
        contract::check_wire::<IAm>(b);

        if let Ok(v) = Bvlc::parse(b) {
            assert_eq!(v.to_bytes().unwrap(), b);
        }
        if let Ok(n) = Npdu::parse(b) {
            assert_eq!(Npdu::parse(&n.to_bytes().unwrap()), Ok(n));
        }
        if let Ok(a) = Apdu::parse(b) {
            assert_eq!(Apdu::parse(&a.to_bytes().unwrap()), Ok(a));
        }
        if let Ok(values) = ValueList::parse(b).map(|values| values.0) {
            let mut once = Vec::new();
            values.iter().for_each(|v| v.write(&mut once).unwrap());
            let again = ValueList::parse(&once).map(|values| values.0).unwrap();
            let mut twice = Vec::new();
            again.iter().for_each(|v| v.write(&mut twice).unwrap());
            assert_eq!(once, twice);
        }
        if let Ok(t) = Tag::parse(b) {
            let mut out = Vec::new();
            t.write(&mut out).unwrap();
            assert_eq!(Tag::parse(&out), Ok(t));
        }
        if let Ok(w) = WhoIs::parse(b) {
            assert_eq!(WhoIs::parse(&w.to_bytes().unwrap()), Ok(w));
        }
        if let Ok(i) = IAm::parse(b) {
            assert_eq!(IAm::parse(&i.to_bytes().unwrap()), Ok(i));
        }
        contract::check_wire::<ContextValue<0>>(b);
        contract::check_wire::<ContextValue<1>>(b);
        contract::check_wire::<ContextValue<2>>(b);
        contract::check_wire::<ContextValue<3>>(b);
        contract::check_wire::<ContextValue<4>>(b);
        contract::check_wire::<ContextValue<5>>(b);
        contract::check_wire::<ContextValue<6>>(b);
        contract::check_wire::<ContextValue<7>>(b);
        contract::check_wire::<ContextValue<8>>(b);
        contract::check_wire::<ContextValue<9>>(b);
        contract::check_wire::<ContextValue<10>>(b);
        contract::check_wire::<ContextValue<11>>(b);
        contract::check_wire::<ContextValue<12>>(b);
    }

    /// Passes `b` to every reader one byte at a time: each prefix in turn,
    /// as a datagram arriving short would be.
    fn check_prefixes(b: &[u8]) {
        for n in 0..=b.len() {
            check(&b[..n]);
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut rng = Lcg::new(0x5eed);
        for _ in 0..4000 {
            let b = rng.bytes(64);
            check(&b);
            // The same bytes behind a valid BVLC and NPDU header.
            let mut d = vec![0x81, 0x0a, 0, 0, 0x01, b.first().copied().unwrap_or(0) & 0x2f];
            d.extend_from_slice(&b);
            let len = d.len() as u16;
            d[2..4].copy_from_slice(&len.to_be_bytes());
            check(&d);
            if let Ok(bvlc) = Bvlc::parse(&d) {
                let _ = bvlc.npdu().map(Npdu::parse);
            }
        }
        // Small values from a valid tag nibble, to reach every value type,
        // and the same as context tags.
        for _ in 0..4000 {
            let mut b = rng.bytes(12);
            if let Some(first) = b.first_mut() {
                *first &= 0xc7;
            }
            check(&b);
            if let Some(first) = b.first_mut() {
                *first |= 0x08;
            }
            check(&b);
        }
    }

    #[test]
    fn units_reject_incomplete_prefixes() {
        let mut rng = Lcg::new(0xb4c0);
        for _ in 0..300 {
            // Random bytes, each prefix in turn.
            check_prefixes(&rng.bytes(40));
            // A valid datagram: BVLC, a routed NPDU, a confirmed request
            // with a random body. No prefix is a whole datagram, and every
            // prefix of the NPDU and APDU reads or fails without a panic.
            let r = rng.next() as u8;
            let segment =
                (r & 1 != 0).then(|| Segment { sequence: (rng.next() as u8), window: (rng.next() as u8), more_follows: r & 2 != 0 });
            let apdu = Apdu::ConfirmedRequest {
                segmented_response_accepted: r & 4 != 0,
                max_segments: r % 8,
                max_apdu: r % 16,
                invoke_id: (rng.next() as u8),
                segment,
                service: (rng.next() as u8),
                data: rng.bytes(20),
            };
            let source = NetAddress { network: 1 + u16::from(rng.next() as u8), mac: rng.bytes(6) };
            let npdu = Npdu {
                destination: (r & 8 != 0).then(|| Destination {
                    address: NetAddress { network: 0xffff, mac: rng.bytes(3) },
                    hop_count: (rng.next() as u8),
                }),
                source: (!source.mac.is_empty()).then_some(source),
                expecting_reply: true,
                priority: Priority::from_bits(r >> 4),
                body: NpduBody::Apdu(apdu.to_bytes().unwrap()),
            };
            let bvlc = Bvlc::OriginalUnicastNpdu(npdu.to_bytes().unwrap());
            let bytes = bvlc.to_bytes().unwrap();
            assert_eq!(Bvlc::parse(&bytes), Ok(bvlc));
            check_prefixes(&bytes);
            for n in 0..bytes.len() {
                assert!(Bvlc::parse(&bytes[..n]).is_err(), "{n} of {bytes:02x?}");
            }
            let nb = npdu.to_bytes().unwrap();
            assert_eq!(Npdu::parse(&nb), Ok(npdu.clone()));
            check_prefixes(&nb);
            let ab = apdu.to_bytes().unwrap();
            assert_eq!(Apdu::parse(&ab), Ok(apdu));
            check_prefixes(&ab);
            // Values, application and context tagged, one byte at a time.
            let i_am = IAm {
                device: ObjectId::device(rng.index(MAX_INSTANCE as usize + 1) as u32),
                max_apdu: u32::from(rng.next() as u8) << 4,
                segmentation: Segmentation::from_code(u32::from(r % 4)).unwrap(),
                vendor: u16::from(rng.next() as u8),
            };
            let ib = i_am.to_bytes().unwrap();
            check_prefixes(&ib);
            for n in 0..ib.len() {
                assert!(IAm::parse(&ib[..n]).is_err());
            }
            let mut encoded = Vec::new();
            ContextValue::<{ tag::UNSIGNED }> { number: r % 40, value: Value::Unsigned(u64::from(rng.next() as u8) << (r % 56)) }.write(&mut encoded).unwrap();
            check_prefixes(&encoded);
            for n in 0..encoded.len() {
                assert!(ContextValue::<{ tag::UNSIGNED }>::parse(&encoded[..n]).is_err());
            }
        }
    }

    #[test]
    fn random_values_round_trip() {
        let mut rng = Lcg::new(42);
        for _ in 0..3000 {
            let r = rng.next() as u8;
            let mut wide = [0u8; 8];
            wide.iter_mut().for_each(|w| *w = rng.next() as u8);
            let n = u64::from_be_bytes(wide) >> (r % 64);
            let v = match r % 13 {
                0 => Value::Null,
                1 => Value::Boolean(r & 0x10 != 0),
                2 => Value::Unsigned(n),
                3 => Value::Signed(n as i64),
                4 => Value::Real(f32::from_bits(n as u32)),
                5 => Value::Double(f64::from_bits(n)),
                6 => Value::OctetString(rng.bytes(300)),
                7 => Value::CharacterString(CharString { charset: r % 6, bytes: rng.bytes(40) }),
                8 => Value::BitString(rng.bytes(30).iter().map(|b| b & 1 == 1).collect()),
                9 => Value::Enumerated(n as u32),
                10 => Value::Date(Date { year: wide[0], month: wide[1], day: wide[2], weekday: wide[3] }),
                11 => Value::Time(Time { hour: wide[0], minute: wide[1], second: wide[2], hundredths: wide[3] }),
                _ => Value::ObjectId(ObjectId::from_u32(n as u32)),
            };
            let bytes = v.to_bytes().unwrap();
            let back = Value::parse(&bytes).unwrap();
            assert_eq!(back.to_bytes().unwrap(), bytes);
            if !matches!(v, Value::Real(_) | Value::Double(_)) {
                assert_eq!(back, v);
            }
            for k in 0..bytes.len() {
                assert!(Value::parse(&bytes[..k]).is_err(), "{v:?} {k}");
            }
            // The same value under a context tag.
            let number = rng.index(255) as u8;
            macro_rules! context {
                ($typ:expr) => {{
                    let context = ContextValue::<{ $typ }> { number, value: v.clone() };
                    contract::check_wire_value(&context);
                    let bytes = context.to_bytes().unwrap();
                    assert_eq!(ContextValue::<{ $typ }>::parse(&bytes), Ok(context));
                }};
            }
            match v.tag() {
                tag::NULL => context!(tag::NULL),
                tag::BOOLEAN => context!(tag::BOOLEAN),
                tag::UNSIGNED => context!(tag::UNSIGNED),
                tag::SIGNED => context!(tag::SIGNED),
                tag::REAL => context!(tag::REAL),
                tag::DOUBLE => context!(tag::DOUBLE),
                tag::OCTET_STRING => context!(tag::OCTET_STRING),
                tag::CHARACTER_STRING => context!(tag::CHARACTER_STRING),
                tag::BIT_STRING => context!(tag::BIT_STRING),
                tag::ENUMERATED => context!(tag::ENUMERATED),
                tag::DATE => context!(tag::DATE),
                tag::TIME => context!(tag::TIME),
                tag::OBJECT_IDENTIFIER => context!(tag::OBJECT_IDENTIFIER),
                _ => unreachable!(),
            }
        }
    }
}
