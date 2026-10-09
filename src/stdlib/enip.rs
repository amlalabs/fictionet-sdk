//! EtherNet/IP and CIP: reading and writing the encapsulation layer, the
//! common packet format and CIP message router messages, with no I/O.
//!
//! `Packet` and typed CIP bodies implement `Wire`, and `codec::Frames<Packet>`
//! decodes encapsulation packets. There is no registration or I/O connection
//! state machine, device `Service`, or live transport. CIP object behavior
//! belongs to the caller.
//!
//! EtherNet/IP carries the Common Industrial Protocol (CIP) over ordinary
//! networks. A client opens a TCP connection to a device on port 44818,
//! registers a session, and then sends CIP messages inside an
//! encapsulation envelope; connected traffic also runs over UDP on port
//! 2222. Every device speaks CIP objects: an object has a class, an
//! instance and attributes, and a client reads and writes them by a path.
//! This module follows the public ODVA EtherNet/IP and CIP specifications
//! and the Wireshark `enip` and `cip` dissectors. All multi-byte fields
//! are little-endian.
//!
//! Nothing here reads a socket. A world that plays a device pushes the
//! bytes it reads from a [`tcp`](fictionet::stdlib::tcp) connection to a
//! [`Stream<codec::Frames<Packet>>`](fictionet::stdlib::codec::Stream), gets [`Packet`]s back,
//! checks each one with [`Packet::check`], reads its command, and for the
//! data commands reads the [`SendData`] envelope, its [`Cpf`] items and
//! the [`MessageRequest`] inside. It writes replies with the same types,
//! starting from [`Packet::reply`], and answers a list-identity request
//! with an [`Identity`]. Which objects exist, and what their attributes
//! hold, is up to world code.
//!
//! Every reader checks lengths and bounds, because the agent can send any
//! bytes it likes. The encapsulation layer accepts any command code and
//! any length, so [`Packet::parse_prefix`] only ever asks for more bytes and the
//! stream never loses its place; the CIP readers return an [`Error`]
//! when bytes do not form the structure they name. Every writer returns
//! an [`Error`] instead of writing a value its reader would refuse
//! or read back as something else, so nothing is cut short in silence.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::enip::{
//!     Command, Cpf, CpfItem, MessageRequest, Packet, PathSegment, SendData, item, service,
//! };
//!
//! // A client with a session asks the identity object for one attribute
//! // with Get_Attribute_Single: class 1, instance 1, attribute 7.
//! let request = MessageRequest::get_attribute(1, 1, 7);
//! // The CIP message rides inside an unconnected data item.
//! let send = SendData {
//!     interface_handle: 0,
//!     timeout: 0,
//!     cpf: Cpf {
//!         items: vec![
//!             CpfItem::null_address(),
//!             CpfItem { type_id: item::UNCONNECTED_DATA, data: request.to_bytes().unwrap() },
//!         ],
//!     },
//! };
//! let packet = Packet {
//!     command: Command::SendRRData,
//!     session_handle: 1,
//!     status: 0,
//!     sender_context: [0; 8],
//!     options: 0,
//!     data: send.to_bytes().unwrap(),
//! };
//! let bytes = packet.to_bytes().unwrap();
//!
//! // A world playing the device reads the packet back off the wire.
//! let (back, used) = Packet::parse_prefix(&bytes).unwrap();
//! assert_eq!(used, bytes.len());
//! assert_eq!(back.check(), Ok(()));
//! assert_eq!(back.command, Command::SendRRData);
//! let send = SendData::parse(&back.data).unwrap();
//! let request = MessageRequest::parse(&send.cpf.items[1].data).unwrap();
//! assert_eq!(request.service, service::GET_ATTRIBUTE_SINGLE);
//! assert_eq!(request.path[0], PathSegment::Class(1));
//! ```

use core::convert::Infallible;
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Wire, le16, le32};

/// The TCP port EtherNet/IP devices listen on.
pub const PORT: u16 = 44818;
/// The UDP port connected (class 0/1) traffic uses.
pub const UDP_PORT: u16 = 2222;
/// The length of the encapsulation header, before its data.
pub const HEADER_LEN: usize = 24;
/// The longest encapsulation packet, header included: 65535 bytes
/// (EtherNet/IP Volume 2, section 2-3.1).
pub const MAX_PACKET: usize = u16::MAX as usize;
/// The most data an encapsulation packet may carry: [`MAX_PACKET`] less
/// the header, 65511 bytes. The length field can name more; a packet that
/// does fails [`Packet::check`].
pub const MAX_DATA: usize = MAX_PACKET - HEADER_LEN;
/// The input capacity of [`codec::Frames<Packet>`](fictionet::stdlib::codec::Frames): 65559 bytes, including the header
/// and every data length the 16-bit length field can name.
/// This exceeds [`MAX_PACKET`] so framing can consume an oversized packet.
/// [`Packet::check`] then reports the protocol length error.
pub const PACKETS_CAPACITY: usize = HEADER_LEN + u16::MAX as usize;
/// The most items one [`Cpf`] may hold.
pub const MAX_CPF_ITEMS: usize = 64;
/// The most bytes one EPATH may hold, set by the word-counted path size.
pub const MAX_PATH_BYTES: usize = 2 * u8::MAX as usize;
/// The most segments one EPATH may hold. Every segment takes at least one
/// word, so this follows from [`MAX_PATH_BYTES`].
pub const MAX_PATH_SEGMENTS: usize = MAX_PATH_BYTES / 2;
/// The most bytes a port segment's link address may hold.
pub const MAX_LINK_ADDRESS: usize = u8::MAX as usize;
/// The most words of additional status a [`MessageResponse`] may hold.
pub const MAX_ADDITIONAL_STATUS: usize = u8::MAX as usize;
/// The most bytes of a word-counted field: a Forward Open or Forward Close
/// reply's application reply, or a simple data or network segment's data.
pub const MAX_WORD_COUNTED: usize = 2 * u8::MAX as usize;
/// The protocol version a [`RegisterSession`] names.
pub const PROTOCOL_VERSION: u16 = 1;
/// The bit added to a CIP service code in a reply.
pub const REPLY_FLAG: u8 = 0x80;
/// The most bytes an ANSI extended symbol segment's name may hold, set by
/// its one-byte length.
pub const MAX_SYMBOL: usize = u8::MAX as usize;
/// The most bytes an [`Identity`]'s product name may hold: the identity
/// object's product name is at most 32 characters (CIP Volume 1, section
/// 5-2.2.1.7).
pub const MAX_PRODUCT_NAME: usize = 32;

/// The encapsulation commands this module reads and writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Command {
    /// A no-operation, used to keep a connection alive.
    Nop,
    /// Ask every device on the network to name its services.
    ListServices,
    /// Ask every device to name itself.
    ListIdentity,
    /// Ask a device to name its interfaces.
    ListInterfaces,
    /// Open a session; the reply carries the session handle.
    RegisterSession,
    /// Close a session.
    UnRegisterSession,
    /// Send one request and wait for its reply (unconnected messaging).
    SendRRData,
    /// Send one connected message (no reply at this layer).
    SendUnitData,
    /// Any other command code. [`Command::from_code`] never puts a code
    /// named above here, and [`Wire::write`] refuses one that is.
    Other(u16),
}

impl Command {
    /// The command's code.
    pub fn code(self) -> u16 {
        match self {
            Command::Nop => 0x0000,
            Command::ListServices => 0x0004,
            Command::ListIdentity => 0x0063,
            Command::ListInterfaces => 0x0064,
            Command::RegisterSession => 0x0065,
            Command::UnRegisterSession => 0x0066,
            Command::SendRRData => 0x006f,
            Command::SendUnitData => 0x0070,
            Command::Other(c) => c,
        }
    }

    /// The command for `code`.
    pub fn from_code(code: u16) -> Command {
        match code {
            0x0000 => Command::Nop,
            0x0004 => Command::ListServices,
            0x0063 => Command::ListIdentity,
            0x0064 => Command::ListInterfaces,
            0x0065 => Command::RegisterSession,
            0x0066 => Command::UnRegisterSession,
            0x006f => Command::SendRRData,
            0x0070 => Command::SendUnitData,
            c => Command::Other(c),
        }
    }
}

/// One EtherNet/IP packet: the encapsulation header's fields and the data
/// it carries. The header's length is worked out from the data, so it is
/// not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// What the packet is for.
    pub command: Command,
    /// The session handle the server gave at registration, echoed on every
    /// later packet of the session.
    pub session_handle: u32,
    /// The status: 0 in a request, and the result in a reply.
    pub status: u32,
    /// Eight bytes the client chooses and the server echoes, so it can
    /// match replies to requests.
    pub sender_context: [u8; 8],
    /// The options flags. A sender sets them to 0, and a receiver drops a
    /// packet whose options are not 0 (Volume 2, section 2-3.7).
    pub options: u32,
    /// The command's data. Its meaning depends on the command; for the
    /// data commands it is a [`SendData`] envelope.
    pub data: Vec<u8>,
}

impl Packet {
    /// Reads the packet at the start of `b`. It returns `None` if `b` holds
    /// only part of one, and otherwise the packet and how many bytes of `b`
    /// it took. Any command code and any length the header names are
    /// taken, so the stream keeps its place; [`Packet::check`] says whether
    /// the packet is one a receiver should act on.
    pub fn parse_prefix(b: &[u8]) -> Option<(Packet, usize)> {
        if b.len() < HEADER_LEN {
            return None;
        }
        let length = usize::from(le16(b, 2)?);
        let end = HEADER_LEN.checked_add(length)?;
        if b.len() < end {
            return None;
        }
        let mut sender_context = [0u8; 8];
        sender_context.copy_from_slice(&b[12..20]);
        let packet = Packet {
            command: Command::from_code(le16(b, 0)?),
            session_handle: le32(b, 4)?,
            status: le32(b, 8)?,
            sender_context,
            options: le32(b, 20)?,
            data: b[HEADER_LEN..end].to_vec(),
        };
        Some((packet, end))
    }

    /// Whether a receiver should act on this packet. A packet with more
    /// than [`MAX_DATA`] bytes of data is [`Error::TooLong`]; a
    /// device may answer it with
    /// [`INVALID_LENGTH`](encap_status::INVALID_LENGTH). A packet whose
    /// options are not 0 is [`Error::Options`], and the receiver
    /// drops it without a reply (Volume 2, section 2-3.7).
    pub fn check(&self) -> Result<(), Error> {
        if self.options != 0 {
            return Err(Error::Options);
        }
        if self.data.len() > MAX_DATA {
            return Err(Error::TooLong);
        }
        Ok(())
    }

    /// A reply to this packet: the same command, session handle and sender
    /// context, options 0, and the given encapsulation status (one of the
    /// codes in [`encap_status`]) and data.
    pub fn reply(&self, status: u32, data: Vec<u8>) -> Packet {
        Packet {
            command: self.command,
            session_handle: self.session_handle,
            status,
            sender_context: self.sender_context,
            options: 0,
            data,
        }
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one packet that passes [`Packet::check`].
    /// [`Packet::parse_prefix`] accepts nonzero options and every
    /// length the header can name, so a receiver can apply its own policy.
    /// Returns [`Error::Truncated`] for an incomplete packet,
    /// [`Error::Trailing`] for extra bytes, [`Error::Options`]
    /// for nonzero options, and [`Error::TooLong`] above [`MAX_DATA`].
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let (packet, used) = Self::parse_prefix(b).ok_or(Error::Truncated)?;
        if used != b.len() {
            return Err(Error::Trailing);
        }
        packet.check()?;
        Ok(packet)
    }

    /// The packet's bytes: the header, then the data. Data longer than
    /// [`MAX_DATA`] is [`Error::TooLong`], options other than 0 are
    /// [`Error::Options`], and a [`Command::Other`] holding a code
    /// with a name of its own is [`Error::Unwritable`], since it would
    /// read back as that name.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.data.len() > MAX_DATA {
            return Err(Error::TooLong);
        }
        if self.options != 0 {
            return Err(Error::Options);
        }
        let code = self.command.code();
        if Command::from_code(code) != self.command {
            return Err(Error::Unwritable);
        }
        dst.reserve(HEADER_LEN + self.data.len());
        dst.extend_from_slice(&code.to_le_bytes());
        dst.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        dst.extend_from_slice(&self.session_handle.to_le_bytes());
        dst.extend_from_slice(&self.status.to_le_bytes());
        dst.extend_from_slice(&self.sender_context);
        dst.extend_from_slice(&self.options.to_le_bytes());
        dst.extend_from_slice(&self.data);
        Ok(())
    }
}

fictionet::prefixed! {
    /// Reads encapsulation packets without holding input bytes.
    ///
    /// Framing accepts every command, option word, and 16-bit data length.
    /// Use [`Packet::check`] to decide whether to act on each packet.
    /// [`Stream::new`](fictionet::stdlib::codec::Stream::new) holds at most [`PACKETS_CAPACITY`]
    /// bytes (65559), including room for lengths above [`MAX_DATA`].
    /// Partial packets return [`fictionet::stdlib::codec::Step::Need`], including at EOF, when the stream
    /// reports truncation.
    Packet => (Packet, Infallible, ());
    name = "EtherNet/IP";
    default {  }
    normalize(limit) { limit }
    capacity(_limit) { PACKETS_CAPACITY }

    /// Reads a packet prefix, returning [`fictionet::stdlib::codec::Step::Need`] while incomplete.
    /// Accepts all header fields and never returns an error. Use
    /// [`Packet::check`] for protocol limits and options.
    #[inline]
    fn parse_prefix(
        input: &[u8],
        _limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        Ok(Packet::parse_prefix(input))
    }
}

/// Why bytes do not form the structure a reader named, or why a value
/// cannot be written. A writer returns one of these rather than write
/// bytes its reader would refuse or read back as another value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// More bytes were needed than were there.
    Truncated,
    /// A count or length ran past one of this module's named limits, or
    /// a list or a byte string to write is longer than its length field
    /// or one of those limits allows.
    TooLong,
    /// Bytes were left over after a structure that should fill its slice.
    Trailing,
    /// An EPATH segment used a type this module does not read.
    UnknownSegment(u8),
    /// An EPATH segment was the right type but malformed, or its fields do
    /// not form a segment of its type.
    BadSegment,
    /// The service code's [`REPLY_FLAG`] bit was set in a request, or clear
    /// in a reply. A writer refuses a request or reply whose service code
    /// has it set; it adds the bit to a reply itself.
    ReplyFlag,
    /// A packet's options were not 0, so the receiver drops it.
    Options,
    /// A [`SendData`] envelope did not start with an address item and a
    /// data item, or a known address item had the wrong length.
    Items,
    /// Bytes counted in 16-bit words were an odd number.
    OddLength,
    /// A [`Command::Other`] held a code that has a name of its own.
    Unwritable,
}

fictionet::error_display!(Error, f, {
    Error::Truncated => f.write_str("ran out of bytes"),
    Error::TooLong => f.write_str("a count or length is past a limit"),
    Error::Trailing => f.write_str("bytes left over"),
    Error::UnknownSegment(t) => write!(f, "EPATH segment type {t:#04x} not read"),
    Error::BadSegment => f.write_str("malformed EPATH segment"),
    Error::ReplyFlag => f.write_str("service reply bit does not match the message"),
    Error::Options => f.write_str("encapsulation options are not zero"),
    Error::Items => f.write_str("send-data items are not an address item and a data item"),
    Error::OddLength => f.write_str("word-counted bytes are an odd number"),
    Error::Unwritable => f.write_str("value cannot be written without changing it"),
});

/// The data of a [`RegisterSession`](Command::RegisterSession) request or
/// reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterSession {
    /// The encapsulation protocol version; [`PROTOCOL_VERSION`] today.
    pub protocol_version: u16,
    /// The options flags, usually 0.
    pub options: u16,
}

/// The encapsulation status codes a reply's [`Packet::status`] carries.
pub mod encap_status {
    /// The command succeeded.
    pub const SUCCESS: u32 = 0x0000;
    /// The command code is not one the receiver knows.
    pub const INVALID_COMMAND: u32 = 0x0001;
    /// The receiver has no memory left to handle the command.
    pub const INSUFFICIENT_MEMORY: u32 = 0x0002;
    /// The data of the command is malformed.
    pub const INCORRECT_DATA: u32 = 0x0003;
    /// The session handle is not one the receiver gave out.
    pub const INVALID_SESSION_HANDLE: u32 = 0x0064;
    /// The length in the header does not fit the command.
    pub const INVALID_LENGTH: u32 = 0x0065;
    /// The receiver does not speak the requested protocol version.
    pub const UNSUPPORTED_PROTOCOL: u32 = 0x0069;
}

/// The common packet format item type codes.
pub mod item {
    /// Null address (0x0000).
    pub const NULL_ADDRESS: u16 = 0x0000;
    /// ListIdentity response (0x000c).
    pub const LIST_IDENTITY_RESPONSE: u16 = 0x000c;
    /// Connection-based address (0x00a1).
    pub const CONNECTED_ADDRESS: u16 = 0x00a1;
    /// Connected transport packet (0x00b1).
    pub const CONNECTED_DATA: u16 = 0x00b1;
    /// Unconnected message (0x00b2).
    pub const UNCONNECTED_DATA: u16 = 0x00b2;
    /// ListServices response (0x0100).
    pub const LIST_SERVICES_RESPONSE: u16 = 0x0100;
    /// Socket address, originator to target (0x8000).
    pub const SOCKET_ADDRESS_O_T: u16 = 0x8000;
    /// Socket address, target to originator (0x8001).
    pub const SOCKET_ADDRESS_T_O: u16 = 0x8001;
    /// Sequenced address (0x8002).
    pub const SEQUENCED_ADDRESS: u16 = 0x8002;
}

/// One item of the common packet format: a type code and its bytes. The
/// bytes' meaning depends on the type; address items are usually short or
/// empty, and data items carry a CIP message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpfItem {
    /// The item type, one of the codes in [`item`].
    pub type_id: u16,
    /// The item's bytes, without the type and length.
    pub data: Vec<u8>,
}

impl CpfItem {
    /// A null address item, which an unconnected request uses to say it has
    /// no address.
    pub fn null_address() -> CpfItem {
        CpfItem {
            type_id: item::NULL_ADDRESS,
            data: Vec::new(),
        }
    }
}

/// The common packet format: a count and that many [`CpfItem`]s. It fills
/// the data of a [`SendData`] envelope, where an address item comes first
/// and a data item second, and the data of the list replies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cpf {
    /// The items, in order.
    pub items: Vec<CpfItem>,
}

/// The identity a device gives in a [`ListIdentity`](Command::ListIdentity)
/// reply. It fills a [`CpfItem`] of type
/// [`LIST_IDENTITY_RESPONSE`](item::LIST_IDENTITY_RESPONSE), the one item
/// of the reply's [`Cpf`]. The socket address fields are big-endian on the
/// wire, unlike everything else here. Parsing ignores the eight reserved
/// socket-address bytes. Writing always emits zeros for them, so a
/// non-canonical input may re-encode to different bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    /// The encapsulation protocol version; [`PROTOCOL_VERSION`] today.
    pub protocol_version: u16,
    /// The socket address family, 2 (IPv4).
    pub socket_family: u16,
    /// The TCP port the device listens on, usually [`PORT`].
    pub socket_port: u16,
    /// The device's IPv4 address.
    pub socket_address: [u8; 4],
    /// The vendor identifier.
    pub vendor_id: u16,
    /// The device type, such as 0x0e for a programmable logic controller.
    pub device_type: u16,
    /// The product code.
    pub product_code: u16,
    /// The major and minor revision, in that order.
    pub revision: [u8; 2],
    /// The identity object's status word.
    pub status: u16,
    /// The device's serial number.
    pub serial_number: u32,
    /// The product name, at most [`MAX_PRODUCT_NAME`] bytes.
    pub product_name: Vec<u8>,
    /// The device state; 0xff when the device does not say.
    pub state: u8,
}

/// The bytes of an [`Identity`] before its product name.
const IDENTITY_FIXED: usize = 32;

/// The data of a [`SendRRData`](Command::SendRRData) or
/// [`SendUnitData`](Command::SendUnitData) packet: a handle, a timeout and
/// the common packet format. The items start with an address item and a
/// data item (Volume 2, section 2-6.1); more items may follow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendData {
    /// The interface handle, 0 for CIP.
    pub interface_handle: u32,
    /// In a SendRRData request, how many seconds the target lets the
    /// operation run before it gives up; 0 means the encapsulation layer
    /// sets no timeout of its own and leaves timing to the encapsulated
    /// protocol. A SendUnitData packet sets it to 0.
    pub timeout: u16,
    /// The items carrying the message.
    pub cpf: Cpf,
}

/// Whether `items` start with an address item and a data item, and each
/// address item of a known kind has its fixed length.
fn send_items_ok(items: &[CpfItem]) -> bool {
    let [address, data, ..] = items else {
        return false;
    };
    let address_len = match address.type_id {
        item::NULL_ADDRESS => 0,
        item::CONNECTED_ADDRESS => 4,
        item::SEQUENCED_ADDRESS => 8,
        _ => return false,
    };
    address.data.len() == address_len
        && matches!(data.type_id, item::CONNECTED_DATA | item::UNCONNECTED_DATA)
}

/// One segment of a CIP path (EPATH). A path names an object by class,
/// instance and attribute, and may route through ports to reach a device.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PathSegment {
    /// A logical class identifier. Class identifiers have no 32-bit form
    /// (CIP Volume 1, appendix C-1.4.2).
    Class(u16),
    /// A logical instance identifier.
    Instance(u32),
    /// A logical member identifier, such as an array element.
    Member(u32),
    /// A logical attribute identifier. Attribute identifiers have no
    /// 32-bit form.
    Attribute(u16),
    /// A logical connection point, which names an assembly's input or
    /// output in an I/O Forward Open path.
    ConnectionPoint(u32),
    /// An electronic key (key format 4), which names the device the
    /// originator expects to find at the end of a connection path.
    ElectronicKey {
        /// The vendor identifier.
        vendor_id: u16,
        /// The device type.
        device_type: u16,
        /// The product code.
        product_code: u16,
        /// The major revision. Its top bit is the compatibility bit.
        major_revision: u8,
        /// The minor revision.
        minor_revision: u8,
    },
    /// A port, with the link address that reaches the next device.
    Port {
        /// The port number; 1 is usually the backplane.
        port: u16,
        /// The link address at that port, such as a one-byte slot number,
        /// at most [`MAX_LINK_ADDRESS`] bytes.
        link: Vec<u8>,
    },
    /// An ANSI extended symbol segment (type 0x91): a tag name, as
    /// controllers that address data by name use. The name is at most
    /// [`MAX_SYMBOL`] bytes.
    Symbol(Vec<u8>),
    /// A simple data segment (type 0x80): data a Forward Open's connection
    /// path carries to the target, such as an assembly's configuration. It
    /// is a whole number of words, at most [`MAX_WORD_COUNTED`] bytes.
    Data(Vec<u8>),
    /// A network segment (types 0x40 to 0x5f), such as the production
    /// inhibit time (0x43). A type with bit 0x10 clear carries exactly one
    /// byte of data; a type with it set carries a word count and that many
    /// words, at most [`MAX_WORD_COUNTED`] bytes.
    Network {
        /// The segment's first byte, 0x40 to 0x5f.
        segment_type: u8,
        /// The segment's data, without the type and word count.
        data: Vec<u8>,
    },
}

/// The logical segment type bits, after the top three bits say "logical".
const LOGICAL_CLASS: u8 = 0;
const LOGICAL_INSTANCE: u8 = 1;
const LOGICAL_MEMBER: u8 = 2;
const LOGICAL_CONNECTION_POINT: u8 = 3;
const LOGICAL_ATTRIBUTE: u8 = 4;
const LOGICAL_SPECIAL: u8 = 5;
/// The first byte of an electronic key segment: logical, special, format 0.
const ELECTRONIC_KEY: u8 = 0x34;
/// The key format of the electronic key this module reads.
const KEY_FORMAT: u8 = 4;
/// The length of an electronic key segment of key format 4.
const ELECTRONIC_KEY_LEN: usize = 10;
/// The first byte of an ANSI extended symbol segment.
const ANSI_SYMBOL: u8 = 0x91;
/// The first byte of a simple data segment.
const SIMPLE_DATA: u8 = 0x80;
/// The top three bits of a network segment's first byte.
const NETWORK: u8 = 0x40;
/// The bit of a network segment's type that says a word count follows.
const NETWORK_WORDS: u8 = 0x10;

impl PathSegment {
    /// The bytes of this one segment, appended to `out`. Each segment is an
    /// even number of bytes, so a whole path is a whole number of words.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            PathSegment::Class(v) => write_logical(out, LOGICAL_CLASS, u32::from(*v)),
            PathSegment::Instance(v) => write_logical(out, LOGICAL_INSTANCE, *v),
            PathSegment::Member(v) => write_logical(out, LOGICAL_MEMBER, *v),
            PathSegment::Attribute(v) => write_logical(out, LOGICAL_ATTRIBUTE, u32::from(*v)),
            PathSegment::ConnectionPoint(v) => write_logical(out, LOGICAL_CONNECTION_POINT, *v),
            PathSegment::ElectronicKey {
                vendor_id,
                device_type,
                product_code,
                major_revision,
                minor_revision,
            } => {
                out.push(ELECTRONIC_KEY);
                out.push(KEY_FORMAT);
                out.extend_from_slice(&vendor_id.to_le_bytes());
                out.extend_from_slice(&device_type.to_le_bytes());
                out.extend_from_slice(&product_code.to_le_bytes());
                out.push(*major_revision);
                out.push(*minor_revision);
            }
            PathSegment::Port { port, link } => {
                if link.len() > MAX_LINK_ADDRESS {
                    return Err(Error::TooLong);
                }
                let extended = link.len() != 1;
                let nibble = if *port <= 0x0e { *port as u8 } else { 0x0f };
                let start = out.len();
                out.push(if extended { 0x10 } else { 0 } | nibble);
                if extended {
                    out.push(link.len() as u8);
                }
                if *port > 0x0e {
                    out.extend_from_slice(&port.to_le_bytes());
                }
                out.extend_from_slice(link);
                if !(out.len() - start).is_multiple_of(2) {
                    out.push(0);
                }
            }
            PathSegment::Symbol(name) => {
                if name.len() > MAX_SYMBOL {
                    return Err(Error::TooLong);
                }
                out.push(ANSI_SYMBOL);
                out.push(name.len() as u8);
                out.extend_from_slice(name);
                if !name.len().is_multiple_of(2) {
                    out.push(0);
                }
            }
            PathSegment::Data(data) => {
                out.push(SIMPLE_DATA);
                write_words(out, data)?;
            }
            PathSegment::Network { segment_type, data } => {
                if segment_type & 0xe0 != NETWORK {
                    return Err(Error::BadSegment);
                }
                out.push(*segment_type);
                if segment_type & NETWORK_WORDS == 0 {
                    let [byte] = data[..] else {
                        return Err(Error::BadSegment);
                    };
                    out.push(byte);
                } else {
                    write_words(out, data)?;
                }
            }
        }
        Ok(())
    }
}

/// Appends a word count byte and `data`, which must be a whole number of
/// words that the count can name.
fn write_words(out: &mut Vec<u8>, data: &[u8]) -> Result<(), Error> {
    if !data.len().is_multiple_of(2) {
        return Err(Error::OddLength);
    }
    if data.len() > MAX_WORD_COUNTED {
        return Err(Error::TooLong);
    }
    out.push((data.len() / 2) as u8);
    out.extend_from_slice(data);
    Ok(())
}

/// Appends a logical segment: an 8-, 16- or 32-bit value, whichever is
/// smallest, with a pad byte before the wider two.
fn write_logical(out: &mut Vec<u8>, logical_type: u8, value: u32) {
    let base = 0x20 | (logical_type << 2);
    if value <= 0xff {
        out.push(base);
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(base | 1);
        out.push(0);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else {
        out.push(base | 2);
        out.push(0);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Reads a word count byte at `b[i + 1]` and the words after it, and
/// returns them and where the segment ends.
fn read_words(b: &[u8], i: usize) -> Result<(Vec<u8>, usize), Error> {
    let count = *b.get(i + 1).ok_or(Error::Truncated)?;
    let start = i + 2;
    let end = start + 2 * usize::from(count);
    if end > b.len() {
        return Err(Error::Truncated);
    }
    Ok((b[start..end].to_vec(), end))
}

/// Reads a whole EPATH that fills `b`.
fn parse_path(b: &[u8]) -> Result<Vec<PathSegment>, Error> {
    let mut segments = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if segments.len() >= MAX_PATH_SEGMENTS {
            return Err(Error::TooLong);
        }
        let t = b[i];
        match t & 0xe0 {
            0x20 => {
                let logical_type = (t >> 2) & 0x07;
                if logical_type == LOGICAL_SPECIAL {
                    if t != ELECTRONIC_KEY {
                        return Err(Error::UnknownSegment(t));
                    }
                    let end = i.checked_add(ELECTRONIC_KEY_LEN).ok_or(Error::TooLong)?;
                    if end > b.len() {
                        return Err(Error::Truncated);
                    }
                    if b[i + 1] != KEY_FORMAT {
                        return Err(Error::BadSegment);
                    }
                    segments.push(PathSegment::ElectronicKey {
                        vendor_id: le16(b, i + 2).ok_or(Error::Truncated)?,
                        device_type: le16(b, i + 4).ok_or(Error::Truncated)?,
                        product_code: le16(b, i + 6).ok_or(Error::Truncated)?,
                        major_revision: b[i + 8],
                        minor_revision: b[i + 9],
                    });
                    i = end;
                    continue;
                }
                let (value, used) = match t & 0x03 {
                    0 => {
                        if i + 2 > b.len() {
                            return Err(Error::Truncated);
                        }
                        (u32::from(b[i + 1]), 2)
                    }
                    1 => {
                        if i + 4 > b.len() {
                            return Err(Error::Truncated);
                        }
                        (u32::from(le16(b, i + 2).ok_or(Error::Truncated)?), 4)
                    }
                    2 => {
                        if i + 6 > b.len() {
                            return Err(Error::Truncated);
                        }
                        (le32(b, i + 2).ok_or(Error::Truncated)?, 6)
                    }
                    _ => return Err(Error::BadSegment),
                };
                // Class and attribute identifiers have no 32-bit form, so
                // theirs are 8 or 16 bits and fit a u16.
                let narrow = || u16::try_from(value).map_err(|_| Error::BadSegment);
                let segment = match logical_type {
                    LOGICAL_CLASS => PathSegment::Class(narrow()?),
                    LOGICAL_ATTRIBUTE => PathSegment::Attribute(narrow()?),
                    LOGICAL_INSTANCE => PathSegment::Instance(value),
                    LOGICAL_MEMBER => PathSegment::Member(value),
                    LOGICAL_CONNECTION_POINT => PathSegment::ConnectionPoint(value),
                    _ => return Err(Error::UnknownSegment(t)),
                };
                if used == 6 && matches!(segment, PathSegment::Class(_) | PathSegment::Attribute(_))
                {
                    return Err(Error::BadSegment);
                }
                segments.push(segment);
                i += used;
            }
            0x00 => {
                let extended = t & 0x10 != 0;
                let nibble = t & 0x0f;
                let mut j = i + 1;
                let link_len = if extended {
                    if j >= b.len() {
                        return Err(Error::Truncated);
                    }
                    let n = usize::from(b[j]);
                    j += 1;
                    n
                } else {
                    1
                };
                let port = if nibble == 0x0f {
                    if j + 2 > b.len() {
                        return Err(Error::Truncated);
                    }
                    let p = le16(b, j).ok_or(Error::Truncated)?;
                    j += 2;
                    p
                } else {
                    u16::from(nibble)
                };
                if j + link_len > b.len() {
                    return Err(Error::Truncated);
                }
                let link = b[j..j + link_len].to_vec();
                j += link_len;
                if (j - i) % 2 != 0 {
                    if j >= b.len() {
                        return Err(Error::Truncated);
                    }
                    j += 1;
                }
                segments.push(PathSegment::Port { port, link });
                i = j;
            }
            NETWORK => {
                if t & NETWORK_WORDS == 0 {
                    let byte = *b.get(i + 1).ok_or(Error::Truncated)?;
                    segments.push(PathSegment::Network {
                        segment_type: t,
                        data: vec![byte],
                    });
                    i += 2;
                } else {
                    let (data, end) = read_words(b, i)?;
                    segments.push(PathSegment::Network {
                        segment_type: t,
                        data,
                    });
                    i = end;
                }
            }
            0x80 if t == SIMPLE_DATA => {
                let (data, end) = read_words(b, i)?;
                segments.push(PathSegment::Data(data));
                i = end;
            }
            0x80 if t == ANSI_SYMBOL => {
                if i + 2 > b.len() {
                    return Err(Error::Truncated);
                }
                let len = usize::from(b[i + 1]);
                // The name is padded to a whole number of words.
                let padded = len + len % 2;
                let start = i + 2;
                if start + padded > b.len() {
                    return Err(Error::Truncated);
                }
                segments.push(PathSegment::Symbol(b[start..start + len].to_vec()));
                i = start + padded;
            }
            _ => return Err(Error::UnknownSegment(t)),
        }
    }
    Ok(segments)
}

/// Writes an EPATH. A path longer than [`MAX_PATH_BYTES`], which the word
/// count byte cannot name, is [`Error::TooLong`].
fn write_path(segments: &[PathSegment]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for segment in segments {
        segment.write(&mut out)?;
        if out.len() > MAX_PATH_BYTES {
            return Err(Error::TooLong);
        }
    }
    Ok(out)
}

/// A CIP message router request: a service, the path to the object, and the
/// service's data. Get/Set Attribute Single and All carry the attribute
/// bytes raw in `data`; Forward Open and Close carry a
/// [`ForwardOpenRequest`] or [`ForwardCloseRequest`] there. The whole
/// request is at most [`MAX_DATA`] bytes, the most a packet can carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRequest {
    /// The service code, one of the codes in [`service`], without the
    /// [`REPLY_FLAG`] bit.
    pub service: u8,
    /// The path to the object the service acts on.
    pub path: Vec<PathSegment>,
    /// The service's request data, if any.
    pub data: Vec<u8>,
}

impl MessageRequest {
    /// Requests one attribute of a class instance with no request data.
    pub fn get_attribute(class: u16, instance: u32, attribute: u16) -> Self {
        Self {
            service: service::GET_ATTRIBUTE_SINGLE,
            path: vec![
                PathSegment::Class(class),
                PathSegment::Instance(instance),
                PathSegment::Attribute(attribute),
            ],
            data: Vec::new(),
        }
    }
}

/// A CIP message router response: the service echoed with the reply bit
/// stripped, a general status, any additional status words, and the
/// service's reply data. The whole response is at most [`MAX_DATA`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageResponse {
    /// The service the reply answers, without the [`REPLY_FLAG`] bit.
    pub service: u8,
    /// The general status; 0 is success, and the codes in [`status`] name
    /// the common failures.
    pub status: u8,
    /// Extra status words, present on some failures.
    pub additional_status: Vec<u16>,
    /// The service's reply data, if any.
    pub data: Vec<u8>,
}

/// The CIP service codes this module names.
pub mod service {
    /// Get_Attributes_All (0x01).
    pub const GET_ATTRIBUTES_ALL: u8 = 0x01;
    /// Set_Attributes_All (0x02).
    pub const SET_ATTRIBUTES_ALL: u8 = 0x02;
    /// Get_Attribute_List (0x03).
    pub const GET_ATTRIBUTE_LIST: u8 = 0x03;
    /// Reset (0x05).
    pub const RESET: u8 = 0x05;
    /// Get_Attribute_Single (0x0e).
    pub const GET_ATTRIBUTE_SINGLE: u8 = 0x0e;
    /// Set_Attribute_Single (0x10).
    pub const SET_ATTRIBUTE_SINGLE: u8 = 0x10;
    /// Forward_Close (0x4e).
    pub const FORWARD_CLOSE: u8 = 0x4e;
    /// Forward_Open (0x54).
    pub const FORWARD_OPEN: u8 = 0x54;
    /// Large_Forward_Open (0x5b).
    pub const LARGE_FORWARD_OPEN: u8 = 0x5b;
}

/// Common CIP general status codes.
pub mod status {
    /// Success (0x00).
    pub const SUCCESS: u8 = 0x00;
    /// Connection failure (0x01).
    pub const CONNECTION_FAILURE: u8 = 0x01;
    /// Resource unavailable (0x02).
    pub const RESOURCE_UNAVAILABLE: u8 = 0x02;
    /// Path segment error (0x04).
    pub const PATH_SEGMENT_ERROR: u8 = 0x04;
    /// Path destination unknown (0x05).
    pub const PATH_DESTINATION_UNKNOWN: u8 = 0x05;
    /// Service not supported (0x08).
    pub const SERVICE_NOT_SUPPORTED: u8 = 0x08;
    /// Invalid attribute value (0x09).
    pub const INVALID_ATTRIBUTE_VALUE: u8 = 0x09;
    /// Attribute not settable (0x0e).
    pub const ATTRIBUTE_NOT_SETTABLE: u8 = 0x0e;
    /// Object does not exist (0x16).
    pub const OBJECT_DOES_NOT_EXIST: u8 = 0x16;
    /// Not enough data (0x13).
    pub const NOT_ENOUGH_DATA: u8 = 0x13;
    /// Attribute not supported (0x14).
    pub const ATTRIBUTE_NOT_SUPPORTED: u8 = 0x14;
    /// Too much data (0x15).
    pub const TOO_MUCH_DATA: u8 = 0x15;
}

/// A Forward Open request body: the connection the originator asks the
/// connection manager to open. It is the `data` of a
/// [`MessageRequest`] whose service is
/// [`FORWARD_OPEN`](service::FORWARD_OPEN).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardOpenRequest {
    /// The priority and tick time, packed as the specification sets out.
    pub priority_time_tick: u8,
    /// The connection timeout, in ticks.
    pub timeout_ticks: u8,
    /// The originator-to-target connection identifier.
    pub o_t_connection_id: u32,
    /// The target-to-originator connection identifier.
    pub t_o_connection_id: u32,
    /// A serial number the originator picks for this connection.
    pub connection_serial: u16,
    /// The originator's vendor identifier.
    pub vendor_id: u16,
    /// The originator's serial number.
    pub originator_serial: u32,
    /// The connection timeout multiplier.
    pub timeout_multiplier: u8,
    /// The originator-to-target requested packet interval, in microseconds.
    pub o_t_rpi: u32,
    /// The originator-to-target network connection parameters.
    pub o_t_params: u16,
    /// The target-to-originator requested packet interval, in microseconds.
    pub t_o_rpi: u32,
    /// The target-to-originator network connection parameters.
    pub t_o_params: u16,
    /// The transport class and trigger byte.
    pub transport_class_trigger: u8,
    /// The path to the target of the connection.
    pub connection_path: Vec<PathSegment>,
}

const FORWARD_OPEN_FIXED: usize = 36;

/// A Forward Open reply body: the connection the manager opened. It is the
/// `data` of a [`MessageResponse`] to a Forward Open on success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardOpenResponse {
    /// The originator-to-target connection identifier.
    pub o_t_connection_id: u32,
    /// The target-to-originator connection identifier.
    pub t_o_connection_id: u32,
    /// The connection serial number, echoed.
    pub connection_serial: u16,
    /// The originator's vendor identifier, echoed.
    pub vendor_id: u16,
    /// The originator's serial number, echoed.
    pub originator_serial: u32,
    /// The originator-to-target actual packet interval, in microseconds.
    pub o_t_api: u32,
    /// The target-to-originator actual packet interval, in microseconds.
    pub t_o_api: u32,
    /// The application reply bytes, a whole number of words, at most
    /// [`MAX_WORD_COUNTED`] bytes.
    pub application_reply: Vec<u8>,
}

const FORWARD_OPEN_REPLY_FIXED: usize = 26;

/// A Forward Close request body. It is the `data` of a [`MessageRequest`]
/// whose service is [`FORWARD_CLOSE`](service::FORWARD_CLOSE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardCloseRequest {
    /// The priority and tick time.
    pub priority_time_tick: u8,
    /// The connection timeout, in ticks.
    pub timeout_ticks: u8,
    /// The connection serial number to close.
    pub connection_serial: u16,
    /// The originator's vendor identifier.
    pub vendor_id: u16,
    /// The originator's serial number.
    pub originator_serial: u32,
    /// The path to the connection's target.
    pub connection_path: Vec<PathSegment>,
}

const FORWARD_CLOSE_FIXED: usize = 12;

/// A Forward Close reply body. It is the `data` of a [`MessageResponse`] to
/// a Forward Close on success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardCloseResponse {
    /// The connection serial number, echoed.
    pub connection_serial: u16,
    /// The originator's vendor identifier, echoed.
    pub vendor_id: u16,
    /// The originator's serial number, echoed.
    pub originator_serial: u32,
    /// The application reply bytes, a whole number of words, at most
    /// [`MAX_WORD_COUNTED`] bytes.
    pub application_reply: Vec<u8>,
}

const FORWARD_CLOSE_REPLY_FIXED: usize = 10;

// Forward Open and Close end in one byte-counted number of 16-bit words.
fn word_tail(b: &[u8], fixed: usize, count_at: usize) -> Result<&[u8], Error> {
    let header = b.get(..fixed).ok_or(Error::Truncated)?;
    let count = usize::from(*header.get(count_at).ok_or(Error::Truncated)?);
    let end = fixed.checked_add(count * 2).ok_or(Error::TooLong)?;
    let tail = b.get(fixed..end).ok_or(Error::Truncated)?;
    if end != b.len() {
        return Err(Error::Trailing);
    }
    Ok(tail)
}

/// `b`, if it is a whole number of words that a word count byte can name.
fn check_words(b: &[u8]) -> Result<&[u8], Error> {
    if !b.len().is_multiple_of(2) {
        return Err(Error::OddLength);
    }
    if b.len() > MAX_WORD_COUNTED {
        return Err(Error::TooLong);
    }
    Ok(b)
}

impl Wire for RegisterSession {
    type ParseError = Error;
    type WriteError = Infallible;

    /// Reads a register-session body: a version and options flags.
    /// Returns [`Error::Truncated`] below four bytes and
    /// [`Error::Trailing`] above four bytes.
    fn parse(b: &[u8]) -> Result<RegisterSession, Error> {
        if b.len() != 4 {
            return Err(if b.len() < 4 {
                Error::Truncated
            } else {
                Error::Trailing
            });
        }
        Ok(RegisterSession {
            protocol_version: le16(b, 0).ok_or(Error::Truncated)?,
            options: le16(b, 2).ok_or(Error::Truncated)?,
        })
    }

    /// The four bytes of a register-session body.
    /// Every version and options word is writable; this method never returns an error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Infallible> {
        let mut out = Vec::with_capacity(4);
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.extend_from_slice(&self.options.to_le_bytes());
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Cpf {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a common packet format that fills `b`. Extra bytes after the
    /// last item are an [`Error::Trailing`], and more than
    /// [`MAX_DATA`] bytes, which no packet can carry, are a
    /// [`Error::TooLong`].
    /// Short headers or item bodies return [`Error::Truncated`].
    /// More than [`MAX_CPF_ITEMS`] items return [`Error::TooLong`].
    fn parse(b: &[u8]) -> Result<Cpf, Error> {
        if b.len() > MAX_DATA {
            return Err(Error::TooLong);
        }
        let mut reader = fictionet::stdlib::codec::Reader::new(b);
        let count = usize::from(reader.u16_le().map_err(|_| Error::Truncated)?);
        if count > MAX_CPF_ITEMS {
            return Err(Error::TooLong);
        }
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let type_id = reader.u16_le().map_err(|_| Error::Truncated)?;
            let len = usize::from(reader.u16_le().map_err(|_| Error::Truncated)?);
            items.push(CpfItem {
                type_id,
                data: reader.take(len).map_err(|_| Error::Truncated)?.to_vec(),
            });
        }
        if !reader.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(Cpf { items })
    }

    /// The bytes of the common packet format. More than [`MAX_CPF_ITEMS`]
    /// items, or more than [`MAX_DATA`] bytes in all, are
    /// [`Error::TooLong`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.items.len() > MAX_CPF_ITEMS {
            return Err(Error::TooLong);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(self.items.len() as u16).to_le_bytes());
        for it in &self.items {
            // Check the sum before appending this item.
            if out
                .len()
                .checked_add(4)
                .and_then(|n| n.checked_add(it.data.len()))
                .is_none_or(|n| n > MAX_DATA)
            {
                return Err(Error::TooLong);
            }
            out.extend_from_slice(&it.type_id.to_le_bytes());
            out.extend_from_slice(&(it.data.len() as u16).to_le_bytes());
            out.extend_from_slice(&it.data);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Identity {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an identity that fills `b`. The eight zero bytes that end the
    /// socket address are not checked. A product name longer than
    /// [`MAX_PRODUCT_NAME`] is an [`Error::TooLong`].
    /// Short fields return [`Error::Truncated`]. Bytes after the
    /// state byte return [`Error::Trailing`].
    fn parse(b: &[u8]) -> Result<Identity, Error> {
        // The fixed part, the name length byte, and the state byte.
        if b.len() < IDENTITY_FIXED + 2 {
            return Err(Error::Truncated);
        }
        let name_len = usize::from(b[IDENTITY_FIXED]);
        if name_len > MAX_PRODUCT_NAME {
            return Err(Error::TooLong);
        }
        let name_start = IDENTITY_FIXED + 1;
        let end = name_start + name_len + 1;
        if end > b.len() {
            return Err(Error::Truncated);
        }
        if end != b.len() {
            return Err(Error::Trailing);
        }
        Ok(Identity {
            protocol_version: le16(b, 0).ok_or(Error::Truncated)?,
            socket_family: u16::from_be_bytes([b[2], b[3]]),
            socket_port: u16::from_be_bytes([b[4], b[5]]),
            socket_address: [b[6], b[7], b[8], b[9]],
            // b[10..18] are the socket address's zero bytes.
            vendor_id: le16(b, 18).ok_or(Error::Truncated)?,
            device_type: le16(b, 20).ok_or(Error::Truncated)?,
            product_code: le16(b, 22).ok_or(Error::Truncated)?,
            revision: [b[24], b[25]],
            status: le16(b, 26).ok_or(Error::Truncated)?,
            serial_number: le32(b, 28).ok_or(Error::Truncated)?,
            product_name: b[name_start..name_start + name_len].to_vec(),
            state: b[end - 1],
        })
    }

    /// The bytes of an identity. A product name longer than
    /// [`MAX_PRODUCT_NAME`] is [`Error::TooLong`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let name = &self.product_name;
        if name.len() > MAX_PRODUCT_NAME {
            return Err(Error::TooLong);
        }
        let mut out = Vec::with_capacity(IDENTITY_FIXED + 2 + name.len());
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.extend_from_slice(&self.socket_family.to_be_bytes());
        out.extend_from_slice(&self.socket_port.to_be_bytes());
        out.extend_from_slice(&self.socket_address);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&self.vendor_id.to_le_bytes());
        out.extend_from_slice(&self.device_type.to_le_bytes());
        out.extend_from_slice(&self.product_code.to_le_bytes());
        out.extend_from_slice(&self.revision);
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&self.serial_number.to_le_bytes());
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.push(self.state);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for SendData {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a send-data envelope that fills `b`. Items that do not start
    /// with an address item and a data item are an [`Error::Items`].
    /// Short fields return [`Error::Truncated`], excess bytes return
    /// [`Error::Trailing`], and excess items or input above [`MAX_DATA`]
    /// return [`Error::TooLong`]. Known address items must have their
    /// fixed lengths or parsing returns [`Error::Items`].
    fn parse(b: &[u8]) -> Result<SendData, Error> {
        if b.len() > MAX_DATA {
            return Err(Error::TooLong);
        }
        if b.len() < 6 {
            return Err(Error::Truncated);
        }
        let cpf = Cpf::parse(&b[6..])?;
        if !send_items_ok(&cpf.items) {
            return Err(Error::Items);
        }
        Ok(SendData {
            interface_handle: le32(b, 0).ok_or(Error::Truncated)?,
            timeout: le16(b, 4).ok_or(Error::Truncated)?,
            cpf,
        })
    }

    /// The bytes of a send-data envelope. Items that do not start with an
    /// address item and a data item are [`Error::Items`], and an
    /// envelope longer than [`MAX_DATA`] is [`Error::TooLong`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if !send_items_ok(&self.cpf.items) {
            return Err(Error::Items);
        }
        let cpf = self.cpf.to_bytes()?;
        if cpf.len() > MAX_DATA - 6 {
            return Err(Error::TooLong);
        }
        dst.reserve(6 + cpf.len());
        dst.extend_from_slice(&self.interface_handle.to_le_bytes());
        dst.extend_from_slice(&self.timeout.to_le_bytes());
        dst.extend_from_slice(&cpf);
        Ok(())
    }
}

impl Wire for MessageRequest {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a message router request. A service code with the
    /// [`REPLY_FLAG`] bit set is a reply, so it is a
    /// [`Error::ReplyFlag`]. More than [`MAX_DATA`] bytes is a
    /// [`Error::TooLong`].
    /// Short headers or paths return [`Error::Truncated`]. Unsupported
    /// path types return [`Error::UnknownSegment`]; malformed segments
    /// return [`Error::BadSegment`]. Path limits return [`Error::TooLong`].
    fn parse(b: &[u8]) -> Result<MessageRequest, Error> {
        if b.len() > MAX_DATA {
            return Err(Error::TooLong);
        }
        if b.len() < 2 {
            return Err(Error::Truncated);
        }
        let service = b[0];
        if service & REPLY_FLAG != 0 {
            return Err(Error::ReplyFlag);
        }
        let path_bytes = usize::from(b[1]) * 2;
        let end = 2usize.checked_add(path_bytes).ok_or(Error::TooLong)?;
        if end > b.len() {
            return Err(Error::Truncated);
        }
        Ok(MessageRequest {
            service,
            path: parse_path(&b[2..end])?,
            data: b[end..].to_vec(),
        })
    }

    /// The bytes of a message router request. A service code with the
    /// [`REPLY_FLAG`] bit set is [`Error::ReplyFlag`], and a path or
    /// a request too long for its length fields is [`Error::TooLong`].
    /// Malformed path fields return [`Error::BadSegment`]. Odd
    /// word-counted path data returns [`Error::OddLength`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.service & REPLY_FLAG != 0 {
            return Err(Error::ReplyFlag);
        }
        let path = write_path(&self.path)?;
        if self.data.len() > MAX_DATA - 2 - path.len() {
            return Err(Error::TooLong);
        }
        let mut out = Vec::with_capacity(2 + path.len() + self.data.len());
        out.push(self.service);
        out.push((path.len() / 2) as u8);
        out.extend_from_slice(&path);
        out.extend_from_slice(&self.data);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for MessageResponse {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a message router response. A service code without the
    /// [`REPLY_FLAG`] bit is a request, so it is a
    /// [`Error::ReplyFlag`]. More than [`MAX_DATA`] bytes is a
    /// [`Error::TooLong`].
    /// Short headers or additional status words return [`Error::Truncated`].
    fn parse(b: &[u8]) -> Result<MessageResponse, Error> {
        if b.len() > MAX_DATA {
            return Err(Error::TooLong);
        }
        if b.len() < 4 {
            return Err(Error::Truncated);
        }
        if b[0] & REPLY_FLAG == 0 {
            return Err(Error::ReplyFlag);
        }
        let service = b[0] & !REPLY_FLAG;
        let status = b[2];
        let extra_words = usize::from(b[3]);
        let extra_bytes = extra_words * 2;
        let end = 4usize.checked_add(extra_bytes).ok_or(Error::TooLong)?;
        if end > b.len() {
            return Err(Error::Truncated);
        }
        let additional_status = (0..extra_words)
            .map(|w| le16(b, 4 + 2 * w).ok_or(Error::Truncated))
            .collect::<Result<_, _>>()?;
        Ok(MessageResponse {
            service,
            status,
            additional_status,
            data: b[end..].to_vec(),
        })
    }

    /// The bytes of a message router response, with the reply bit set. A
    /// service code that already has it is [`Error::ReplyFlag`].
    /// More than [`MAX_ADDITIONAL_STATUS`] words of additional status, or
    /// a response longer than [`MAX_DATA`], is [`Error::TooLong`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.service & REPLY_FLAG != 0 {
            return Err(Error::ReplyFlag);
        }
        let extra = &self.additional_status;
        if extra.len() > MAX_ADDITIONAL_STATUS {
            return Err(Error::TooLong);
        }
        if self.data.len() > MAX_DATA - 4 - 2 * extra.len() {
            return Err(Error::TooLong);
        }
        let mut out = Vec::with_capacity(4 + extra.len() * 2 + self.data.len());
        out.push(self.service | REPLY_FLAG);
        out.push(0);
        out.push(self.status);
        out.push(extra.len() as u8);
        for w in extra {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(&self.data);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for ForwardOpenRequest {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a Forward Open request body.
    /// Short fields return [`Error::Truncated`]; extra bytes return
    /// [`Error::Trailing`]. Unsupported path types return
    /// [`Error::UnknownSegment`], malformed segments return
    /// [`Error::BadSegment`], and path limits return [`Error::TooLong`].
    fn parse(b: &[u8]) -> Result<ForwardOpenRequest, Error> {
        let tail = word_tail(b, FORWARD_OPEN_FIXED, 35)?;
        Ok(ForwardOpenRequest {
            priority_time_tick: b[0],
            timeout_ticks: b[1],
            o_t_connection_id: le32(b, 2).ok_or(Error::Truncated)?,
            t_o_connection_id: le32(b, 6).ok_or(Error::Truncated)?,
            connection_serial: le16(b, 10).ok_or(Error::Truncated)?,
            vendor_id: le16(b, 12).ok_or(Error::Truncated)?,
            originator_serial: le32(b, 14).ok_or(Error::Truncated)?,
            timeout_multiplier: b[18],
            // b[19..22] are three reserved bytes.
            o_t_rpi: le32(b, 22).ok_or(Error::Truncated)?,
            o_t_params: le16(b, 26).ok_or(Error::Truncated)?,
            t_o_rpi: le32(b, 28).ok_or(Error::Truncated)?,
            t_o_params: le16(b, 32).ok_or(Error::Truncated)?,
            transport_class_trigger: b[34],
            connection_path: parse_path(tail)?,
        })
    }

    /// The bytes of a Forward Open request body. A connection path too
    /// long for its word count is [`Error::TooLong`].
    /// Malformed path fields return [`Error::BadSegment`]. Odd
    /// word-counted path data returns [`Error::OddLength`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let path = write_path(&self.connection_path)?;
        let mut out = Vec::with_capacity(FORWARD_OPEN_FIXED + path.len());
        out.push(self.priority_time_tick);
        out.push(self.timeout_ticks);
        out.extend_from_slice(&self.o_t_connection_id.to_le_bytes());
        out.extend_from_slice(&self.t_o_connection_id.to_le_bytes());
        out.extend_from_slice(&self.connection_serial.to_le_bytes());
        out.extend_from_slice(&self.vendor_id.to_le_bytes());
        out.extend_from_slice(&self.originator_serial.to_le_bytes());
        out.push(self.timeout_multiplier);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&self.o_t_rpi.to_le_bytes());
        out.extend_from_slice(&self.o_t_params.to_le_bytes());
        out.extend_from_slice(&self.t_o_rpi.to_le_bytes());
        out.extend_from_slice(&self.t_o_params.to_le_bytes());
        out.push(self.transport_class_trigger);
        out.push((path.len() / 2) as u8);
        out.extend_from_slice(&path);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for ForwardOpenResponse {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a Forward Open reply body.
    /// Short fields or reply data return [`Error::Truncated`].
    /// Bytes beyond the word-counted reply return [`Error::Trailing`].
    fn parse(b: &[u8]) -> Result<ForwardOpenResponse, Error> {
        let tail = word_tail(b, FORWARD_OPEN_REPLY_FIXED, 24)?;
        Ok(ForwardOpenResponse {
            o_t_connection_id: le32(b, 0).ok_or(Error::Truncated)?,
            t_o_connection_id: le32(b, 4).ok_or(Error::Truncated)?,
            connection_serial: le16(b, 8).ok_or(Error::Truncated)?,
            vendor_id: le16(b, 10).ok_or(Error::Truncated)?,
            originator_serial: le32(b, 12).ok_or(Error::Truncated)?,
            o_t_api: le32(b, 16).ok_or(Error::Truncated)?,
            t_o_api: le32(b, 20).ok_or(Error::Truncated)?,
            application_reply: tail.to_vec(),
        })
    }

    /// The bytes of a Forward Open reply body. An application reply of an
    /// odd number of bytes is [`Error::OddLength`], and one longer
    /// than [`MAX_WORD_COUNTED`] is [`Error::TooLong`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let reply = check_words(&self.application_reply)?;
        let mut out = Vec::with_capacity(FORWARD_OPEN_REPLY_FIXED + reply.len());
        out.extend_from_slice(&self.o_t_connection_id.to_le_bytes());
        out.extend_from_slice(&self.t_o_connection_id.to_le_bytes());
        out.extend_from_slice(&self.connection_serial.to_le_bytes());
        out.extend_from_slice(&self.vendor_id.to_le_bytes());
        out.extend_from_slice(&self.originator_serial.to_le_bytes());
        out.extend_from_slice(&self.o_t_api.to_le_bytes());
        out.extend_from_slice(&self.t_o_api.to_le_bytes());
        out.push((reply.len() / 2) as u8);
        out.push(0);
        out.extend_from_slice(reply);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for ForwardCloseRequest {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a Forward Close request body.
    /// Short fields return [`Error::Truncated`]; extra bytes return
    /// [`Error::Trailing`]. Unsupported path types return
    /// [`Error::UnknownSegment`], malformed segments return
    /// [`Error::BadSegment`], and path limits return [`Error::TooLong`].
    fn parse(b: &[u8]) -> Result<ForwardCloseRequest, Error> {
        let tail = word_tail(b, FORWARD_CLOSE_FIXED, 10)?;
        Ok(ForwardCloseRequest {
            priority_time_tick: b[0],
            timeout_ticks: b[1],
            connection_serial: le16(b, 2).ok_or(Error::Truncated)?,
            vendor_id: le16(b, 4).ok_or(Error::Truncated)?,
            originator_serial: le32(b, 6).ok_or(Error::Truncated)?,
            connection_path: parse_path(tail)?,
        })
    }

    /// The bytes of a Forward Close request body. A connection path too
    /// long for its word count is [`Error::TooLong`].
    /// Malformed path fields return [`Error::BadSegment`]. Odd
    /// word-counted path data returns [`Error::OddLength`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let path = write_path(&self.connection_path)?;
        let mut out = Vec::with_capacity(FORWARD_CLOSE_FIXED + path.len());
        out.push(self.priority_time_tick);
        out.push(self.timeout_ticks);
        out.extend_from_slice(&self.connection_serial.to_le_bytes());
        out.extend_from_slice(&self.vendor_id.to_le_bytes());
        out.extend_from_slice(&self.originator_serial.to_le_bytes());
        out.push((path.len() / 2) as u8);
        out.push(0);
        out.extend_from_slice(&path);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for ForwardCloseResponse {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a Forward Close reply body.
    /// Short fields or reply data return [`Error::Truncated`].
    /// Bytes beyond the word-counted reply return [`Error::Trailing`].
    fn parse(b: &[u8]) -> Result<ForwardCloseResponse, Error> {
        let tail = word_tail(b, FORWARD_CLOSE_REPLY_FIXED, 8)?;
        Ok(ForwardCloseResponse {
            connection_serial: le16(b, 0).ok_or(Error::Truncated)?,
            vendor_id: le16(b, 2).ok_or(Error::Truncated)?,
            originator_serial: le32(b, 4).ok_or(Error::Truncated)?,
            application_reply: tail.to_vec(),
        })
    }

    /// The bytes of a Forward Close reply body. An application reply of an
    /// odd number of bytes is [`Error::OddLength`], and one longer
    /// than [`MAX_WORD_COUNTED`] is [`Error::TooLong`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let reply = check_words(&self.application_reply)?;
        let mut out = Vec::with_capacity(FORWARD_CLOSE_REPLY_FIXED + reply.len());
        out.extend_from_slice(&self.connection_serial.to_le_bytes());
        out.extend_from_slice(&self.vendor_id.to_le_bytes());
        out.extend_from_slice(&self.originator_serial.to_le_bytes());
        out.push((reply.len() / 2) as u8);
        out.push(0);
        out.extend_from_slice(reply);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Lcg, Stream, pump};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{self, decode_all};
    use fictionet::stdlib::test_support::{assert_linear, rounds};

    #[test]
    fn register_session_round_trip() {
        let rs = RegisterSession {
            protocol_version: PROTOCOL_VERSION,
            options: 0,
        };
        let bytes = rs.to_bytes().unwrap();
        assert_eq!(bytes, [1, 0, 0, 0]);
        assert_eq!(RegisterSession::parse(&bytes), Ok(rs));
        assert_eq!(RegisterSession::parse(&[1, 0, 0]), Err(Error::Truncated));
        assert_eq!(
            RegisterSession::parse(&[1, 0, 0, 0, 0]),
            Err(Error::Trailing)
        );
    }

    #[test]
    fn packet_header_round_trip() {
        let packet = Packet {
            command: Command::RegisterSession,
            session_handle: 0,
            status: 0,
            sender_context: [1, 2, 3, 4, 5, 6, 7, 8],
            options: 0,
            data: vec![1, 0, 0, 0],
        };
        let bytes = packet.to_bytes().unwrap();
        // Command 0x65, length 4, then handle, status, context, options, data.
        assert_eq!(&bytes[..6], &[0x65, 0x00, 0x04, 0x00, 0x00, 0x00]);
        assert_eq!(bytes.len(), HEADER_LEN + 4);
        let (back, used) = Packet::parse_prefix(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(back, packet);
    }

    #[test]
    fn command_codes_round_trip() {
        for c in 0..=u16::MAX {
            assert_eq!(Command::from_code(c).code(), c);
        }
    }

    #[test]
    fn packet_truncated_prefixes_need_more() {
        let packet = Packet {
            command: Command::SendRRData,
            session_handle: 7,
            status: 0,
            sender_context: [0; 8],
            options: 0,
            data: vec![9, 8, 7],
        };
        let bytes = packet.to_bytes().unwrap();
        for n in 0..bytes.len() {
            assert_eq!(Packet::parse_prefix(&bytes[..n]), None, "{n} bytes");
        }
        assert!(Packet::parse_prefix(&bytes).is_some());
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = Packet {
            command: Command::RegisterSession,
            session_handle: 0,
            status: 0,
            sender_context: [0; 8],
            options: 0,
            data: vec![1, 0, 0, 0],
        };
        let b = Packet {
            command: Command::UnRegisterSession,
            session_handle: 5,
            status: 0,
            sender_context: [0; 8],
            options: 0,
            data: Vec::new(),
        };
        let mut stream = a.to_bytes().unwrap();
        stream.extend_from_slice(&b.to_bytes().unwrap());
        let mut d = Stream::new(Frames::<Packet>::new());
        let mut got = Vec::new();
        contract::check_decode(Frames::<Packet>::new, &stream);
        pump(&mut d, &stream, |packet| got.push(packet)).unwrap();
        assert_eq!(got, vec![a, b]);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_packets_in_linear_time() {
        assert_linear(
            "decoder_takes_many_small_packets_in_linear_time",
            rounds(50_000),
            |size| {
                let one = Packet {
                    command: Command::Nop,
                    session_handle: 0,
                    status: 0,
                    sender_context: [0; 8],
                    options: 0,
                    data: Vec::new(),
                }
                .to_bytes()
                .unwrap();
                let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * size).collect();
                let mut d = Stream::new(Frames::<Packet>::new());
                let mut n = 0;
                pump(&mut d, &stream, |_| n += 1).unwrap();
                assert_eq!(n, size);
                assert_eq!(d.buffered(), 0);
            },
        );
    }

    #[test]
    fn cpf_round_trip_and_errors() {
        let cpf = Cpf {
            items: vec![
                CpfItem::null_address(),
                CpfItem {
                    type_id: item::UNCONNECTED_DATA,
                    data: vec![0x0e, 0x01, 0x20, 0x01],
                },
            ],
        };
        let bytes = cpf.to_bytes().unwrap();
        // Count 2, null item (type 0, len 0), data item (type 0xB2, len 4).
        assert_eq!(&bytes[..4], &[0x02, 0x00, 0x00, 0x00]);
        assert_eq!(Cpf::parse(&bytes), Ok(cpf));
        assert_eq!(Cpf::parse(&[0]), Err(Error::Truncated));
        // Count says 1 item but the item header is cut.
        assert_eq!(Cpf::parse(&[1, 0, 0, 0, 2]), Err(Error::Truncated));
        // Item length runs past the end.
        assert_eq!(Cpf::parse(&[1, 0, 0, 0, 4, 0, 1, 2]), Err(Error::Truncated));
        // Bytes left over after the items.
        assert_eq!(Cpf::parse(&[0, 0, 9]), Err(Error::Trailing));
        // Too many items.
        let mut many = ((MAX_CPF_ITEMS + 1) as u16).to_le_bytes().to_vec();
        many.resize(2 + 4 * (MAX_CPF_ITEMS + 1), 0);
        assert_eq!(Cpf::parse(&many), Err(Error::TooLong));
    }

    #[test]
    fn send_data_round_trip() {
        let send = SendData {
            interface_handle: 0,
            timeout: 10,
            cpf: Cpf {
                items: vec![
                    CpfItem::null_address(),
                    CpfItem {
                        type_id: item::UNCONNECTED_DATA,
                        data: vec![1, 2, 3],
                    },
                ],
            },
        };
        let bytes = send.to_bytes().unwrap();
        assert_eq!(SendData::parse(&bytes), Ok(send));
        assert_eq!(SendData::parse(&[0, 0, 0, 0, 0]), Err(Error::Truncated));
    }

    #[test]
    fn path_segments_round_trip() {
        // Identity object, class 1, instance 1, attribute 7.
        let path = vec![
            PathSegment::Class(1),
            PathSegment::Instance(1),
            PathSegment::Attribute(7),
        ];
        let bytes = write_path(&path).unwrap();
        assert_eq!(bytes, [0x20, 0x01, 0x24, 0x01, 0x30, 0x07]);
        assert_eq!(parse_path(&bytes), Ok(path));
    }

    #[test]
    fn path_segments_wide_values_round_trip() {
        let path = vec![
            PathSegment::Class(0x1234),
            PathSegment::Instance(0x0001_0002),
        ];
        let bytes = write_path(&path).unwrap();
        // 16-bit class with a pad byte, then 32-bit instance with a pad byte.
        assert_eq!(
            bytes,
            [0x21, 0x00, 0x34, 0x12, 0x26, 0x00, 0x02, 0x00, 0x01, 0x00]
        );
        assert_eq!(parse_path(&bytes), Ok(path));
    }

    #[test]
    fn port_segments_round_trip() {
        for port in [1u16, 14, 15, 20, 300] {
            for link in [vec![], vec![0x00], vec![0x0a, 0x0b], vec![1, 2, 3]] {
                let path = vec![PathSegment::Port {
                    port,
                    link: link.clone(),
                }];
                let bytes = write_path(&path).unwrap();
                assert_eq!(
                    bytes.len() % 2,
                    0,
                    "even length for port {port} link {link:?}"
                );
                assert_eq!(parse_path(&bytes), Ok(path), "port {port} link {link:?}");
            }
        }
    }

    #[test]
    fn path_errors() {
        // A logical type this module does not read (service ID, type 6).
        assert_eq!(parse_path(&[0x38, 0x00]), Err(Error::UnknownSegment(0x38)));
        // An ANSI symbol whose name runs past the end, or whose pad byte is
        // missing.
        assert_eq!(parse_path(&[0x91, 0x04, b'a']), Err(Error::Truncated));
        assert_eq!(parse_path(&[0x91, 0x01, b'a']), Err(Error::Truncated));
        // A reserved logical format.
        assert_eq!(parse_path(&[0x23, 0x00]), Err(Error::BadSegment));
        // A segment type this module does not read (symbolic, 0x60).
        assert_eq!(parse_path(&[0x60, 0x00]), Err(Error::UnknownSegment(0x60)));
        // A network segment cut short.
        assert_eq!(parse_path(&[0x43]), Err(Error::Truncated));
        assert_eq!(parse_path(&[0x51, 0x02, 0, 0]), Err(Error::Truncated));
        // A logical segment cut short.
        assert_eq!(parse_path(&[0x20]), Err(Error::Truncated));
        assert_eq!(parse_path(&[0x21, 0x00, 0x00]), Err(Error::Truncated));
        // An extended-link port with no size byte.
        assert_eq!(parse_path(&[0x10]), Err(Error::Truncated));
        // A port with a link that runs past the end.
        assert_eq!(parse_path(&[0x15, 0x04, 0x01]), Err(Error::Truncated));
        // Too many segments.
        let many: Vec<u8> = std::iter::repeat_n([0x20u8, 0x00], MAX_PATH_SEGMENTS + 1)
            .flatten()
            .collect();
        assert_eq!(parse_path(&many), Err(Error::TooLong));
    }

    #[test]
    fn message_request_round_trip() {
        let req = MessageRequest::get_attribute(1, 1, 7);
        let bytes = req.to_bytes().unwrap();
        assert_eq!(bytes, [0x0e, 0x03, 0x20, 0x01, 0x24, 0x01, 0x30, 0x07]);
        assert_eq!(MessageRequest::parse(&bytes), Ok(req));
        // A Set with a value in the data.
        let set = MessageRequest {
            service: service::SET_ATTRIBUTE_SINGLE,
            path: vec![
                PathSegment::Class(4),
                PathSegment::Instance(100),
                PathSegment::Attribute(3),
            ],
            data: vec![0x2a, 0x00],
        };
        assert_eq!(MessageRequest::parse(&set.to_bytes().unwrap()), Ok(set));
        assert_eq!(MessageRequest::parse(&[0x0e]), Err(Error::Truncated));
        // A path size that runs past the end.
        assert_eq!(
            MessageRequest::parse(&[0x0e, 0x04, 0x20, 0x01]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn message_response_round_trip() {
        let resp = MessageResponse {
            service: service::GET_ATTRIBUTE_SINGLE,
            status: status::SUCCESS,
            additional_status: Vec::new(),
            data: vec![0x2a, 0x00],
        };
        let bytes = resp.to_bytes().unwrap();
        // Service with reply bit, reserved 0, status 0, no extra words, data.
        assert_eq!(bytes, [0x8e, 0x00, 0x00, 0x00, 0x2a, 0x00]);
        assert_eq!(MessageResponse::parse(&bytes), Ok(resp));
        // A failure with an additional status word.
        let fail = MessageResponse {
            service: service::SET_ATTRIBUTE_SINGLE,
            status: status::ATTRIBUTE_NOT_SUPPORTED,
            additional_status: vec![0x1234],
            data: Vec::new(),
        };
        let bytes = fail.to_bytes().unwrap();
        assert_eq!(bytes, [0x90, 0x00, 0x14, 0x01, 0x34, 0x12]);
        assert_eq!(MessageResponse::parse(&bytes), Ok(fail));
        assert_eq!(MessageResponse::parse(&[0x8e, 0, 0]), Err(Error::Truncated));
        // An additional status count that runs past the end.
        assert_eq!(
            MessageResponse::parse(&[0x8e, 0, 0, 2, 0, 0]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn forward_open_round_trip() {
        let req = ForwardOpenRequest {
            priority_time_tick: 0x0a,
            timeout_ticks: 0xf8,
            o_t_connection_id: 0,
            t_o_connection_id: 0x8000_0002,
            connection_serial: 0x1234,
            vendor_id: 0x00fe,
            originator_serial: 0xdead_beef,
            timeout_multiplier: 1,
            o_t_rpi: 1_000_000,
            o_t_params: 0x4802,
            t_o_rpi: 1_000_000,
            t_o_params: 0x4802,
            transport_class_trigger: 0xa3,
            connection_path: vec![
                PathSegment::Port {
                    port: 1,
                    link: vec![0x00],
                },
                PathSegment::Class(2),
                PathSegment::Instance(1),
            ],
        };
        let bytes = req.to_bytes().unwrap();
        assert_eq!(ForwardOpenRequest::parse(&bytes), Ok(req));
        assert_eq!(ForwardOpenRequest::parse(&[0; 10]), Err(Error::Truncated));

        let resp = ForwardOpenResponse {
            o_t_connection_id: 0,
            t_o_connection_id: 0x8000_0002,
            connection_serial: 0x1234,
            vendor_id: 0x00fe,
            originator_serial: 0xdead_beef,
            o_t_api: 1_000_000,
            t_o_api: 1_000_000,
            application_reply: Vec::new(),
        };
        let bytes = resp.to_bytes().unwrap();
        assert_eq!(ForwardOpenResponse::parse(&bytes), Ok(resp));
        assert_eq!(ForwardOpenResponse::parse(&[0; 20]), Err(Error::Truncated));
        // Trailing bytes past the reply.
        let mut extra = ForwardOpenResponse {
            o_t_connection_id: 0,
            t_o_connection_id: 0,
            connection_serial: 0,
            vendor_id: 0,
            originator_serial: 0,
            o_t_api: 0,
            t_o_api: 0,
            application_reply: Vec::new(),
        }
        .to_bytes()
        .unwrap();
        extra.push(0xff);
        assert_eq!(ForwardOpenResponse::parse(&extra), Err(Error::Trailing));
    }

    #[test]
    fn forward_close_round_trip() {
        let req = ForwardCloseRequest {
            priority_time_tick: 0x0a,
            timeout_ticks: 0xf8,
            connection_serial: 0x1234,
            vendor_id: 0x00fe,
            originator_serial: 0xdead_beef,
            connection_path: vec![
                PathSegment::Port {
                    port: 1,
                    link: vec![0],
                },
                PathSegment::Class(2),
            ],
        };
        let bytes = req.to_bytes().unwrap();
        assert_eq!(ForwardCloseRequest::parse(&bytes), Ok(req));
        assert_eq!(ForwardCloseRequest::parse(&[0; 8]), Err(Error::Truncated));

        let resp = ForwardCloseResponse {
            connection_serial: 0x1234,
            vendor_id: 0x00fe,
            originator_serial: 0xdead_beef,
            application_reply: Vec::new(),
        };
        let bytes = resp.to_bytes().unwrap();
        assert_eq!(ForwardCloseResponse::parse(&bytes), Ok(resp));
        assert_eq!(ForwardCloseResponse::parse(&[0; 6]), Err(Error::Truncated));
    }

    fn packet(command: Command, options: u32, data: Vec<u8>) -> Packet {
        Packet {
            command,
            session_handle: 1,
            status: 0,
            sender_context: [7; 8],
            options,
            data,
        }
    }

    fn send_data(items: Vec<CpfItem>) -> SendData {
        SendData {
            interface_handle: 0,
            timeout: 0,
            cpf: Cpf { items },
        }
    }

    #[test]
    fn stream_holds_at_most_packets_capacity() {
        // A stream of empty NOPs far longer than the decoder may hold.
        let count = rounds(500_000);
        let one = packet(Command::Nop, 0, Vec::new()).to_bytes().unwrap();
        let stream: Vec<u8> = one
            .iter()
            .copied()
            .cycle()
            .take(one.len() * count)
            .collect();
        let mut d = Stream::new(Frames::<Packet>::new());
        assert_eq!(d.push(&stream), PACKETS_CAPACITY);
        assert_eq!(d.buffered(), PACKETS_CAPACITY);
        // Full, it takes nothing more until packets are taken out.
        assert_eq!(d.push(&stream), 0);
        let mut n = 0;
        while let Some(packet) = d.next() {
            packet.unwrap();
            n += 1;
        }
        pump(&mut d, &stream[PACKETS_CAPACITY..], |_| n += 1).unwrap();
        assert_eq!(n, count);
        assert_eq!(d.buffered(), 0);
        // The longest frame the length field can name still fits whole.
        let mut big = vec![0u8; HEADER_LEN];
        big[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
        big.resize(PACKETS_CAPACITY, 0);
        contract::check_decode_with_alloc_limit(Frames::<Packet>::new, &big, 2 * PACKETS_CAPACITY);
        assert_eq!(d.push(&big), PACKETS_CAPACITY);
        let p = d.next().unwrap().unwrap();
        assert_eq!(p.data.len(), u16::MAX as usize);
        assert_eq!(p.check(), Err(Error::TooLong));
    }

    #[test]
    fn message_readers_refuse_more_than_a_packet_carries() {
        let mut req = vec![service::GET_ATTRIBUTE_SINGLE, 0];
        req.resize(MAX_DATA, 0);
        let back = MessageRequest::parse(&req).unwrap();
        assert_eq!(back.to_bytes().unwrap(), req);
        req.push(0);
        assert_eq!(MessageRequest::parse(&req), Err(Error::TooLong));
        let mut resp = vec![0x8e, 0, 0, 0];
        resp.resize(MAX_DATA, 0);
        let back = MessageResponse::parse(&resp).unwrap();
        assert_eq!(back.to_bytes().unwrap(), resp);
        resp.push(0);
        assert_eq!(MessageResponse::parse(&resp), Err(Error::TooLong));
        // Writers refuse what the readers would refuse.
        let too_long = MessageRequest {
            service: 0x4c,
            path: Vec::new(),
            data: vec![0; MAX_DATA - 1],
        };
        assert_eq!(too_long.to_bytes(), Err(Error::TooLong));
        let too_long = MessageResponse {
            service: 0x4c,
            status: 0,
            additional_status: Vec::new(),
            data: vec![0; MAX_DATA - 3],
        };
        assert_eq!(too_long.to_bytes(), Err(Error::TooLong));
        assert_eq!(Cpf::parse(&vec![0; MAX_DATA + 1]), Err(Error::TooLong));
        assert_eq!(SendData::parse(&vec![0; MAX_DATA + 1]), Err(Error::TooLong));
    }

    #[test]
    fn paths_past_32_segments_round_trip_and_long_ones_are_refused() {
        // 33 one-letter symbols are 132 bytes, well inside the word count.
        let path: Vec<PathSegment> =
            std::iter::repeat_n(PathSegment::Symbol(b"a".to_vec()), 33).collect();
        let req = MessageRequest {
            service: service::SET_ATTRIBUTE_SINGLE,
            path,
            data: vec![1, 0],
        };
        let bytes = req.to_bytes().unwrap();
        assert_eq!(bytes[1], 66);
        assert_eq!(MessageRequest::parse(&bytes), Ok(req));
        // 255 two-byte segments fill the path exactly; one more is refused,
        // not dropped.
        let mut path: Vec<PathSegment> =
            std::iter::repeat_n(PathSegment::Member(1), MAX_PATH_SEGMENTS).collect();
        let full = MessageRequest {
            service: 0x4c,
            path: path.clone(),
            data: Vec::new(),
        };
        assert_eq!(MessageRequest::parse(&full.to_bytes().unwrap()), Ok(full));
        path.push(PathSegment::Member(2));
        let over = MessageRequest {
            service: 0x4c,
            path,
            data: Vec::new(),
        };
        assert_eq!(over.to_bytes(), Err(Error::TooLong));
        // A link address past the limit is refused, not cut.
        let port = vec![PathSegment::Port {
            port: 1,
            link: vec![0; MAX_LINK_ADDRESS + 1],
        }];
        assert_eq!(write_path(&port), Err(Error::TooLong));
        let close = ForwardCloseRequest {
            priority_time_tick: 0,
            timeout_ticks: 0,
            connection_serial: 0,
            vendor_id: 0,
            originator_serial: 0,
            connection_path: port,
        };
        assert_eq!(close.to_bytes(), Err(Error::TooLong));
    }

    #[test]
    fn nested_writers_refuse_instead_of_cutting() {
        // A data item as long as an item may be no longer fits the envelope.
        let send = send_data(vec![
            CpfItem::null_address(),
            CpfItem {
                type_id: item::UNCONNECTED_DATA,
                data: vec![0; u16::MAX as usize],
            },
        ]);
        assert_eq!(send.to_bytes(), Err(Error::TooLong));
        // The longest that fits writes a packet whose every layer reads.
        let room = MAX_DATA - 6 - 2 - 4 - 4;
        let send = send_data(vec![
            CpfItem::null_address(),
            CpfItem {
                type_id: item::UNCONNECTED_DATA,
                data: vec![0; room],
            },
        ]);
        let p = packet(Command::SendRRData, 0, send.to_bytes().unwrap());
        let (back, _) = Packet::parse_prefix(&p.to_bytes().unwrap()).unwrap();
        assert_eq!(back.check(), Ok(()));
        assert_eq!(SendData::parse(&back.data), Ok(send));
        let send = send_data(vec![
            CpfItem::null_address(),
            CpfItem {
                type_id: item::UNCONNECTED_DATA,
                data: vec![0; room + 1],
            },
        ]);
        assert_eq!(send.to_bytes(), Err(Error::TooLong));
        // Item headers count toward the limit too.
        let edge = Cpf {
            items: vec![
                CpfItem {
                    type_id: item::UNCONNECTED_DATA,
                    data: vec![0; MAX_DATA - 7],
                },
                CpfItem::null_address(),
                CpfItem::null_address(),
            ],
        };
        assert_eq!(edge.to_bytes(), Err(Error::TooLong));
        let fits = Cpf {
            items: vec![CpfItem {
                type_id: item::UNCONNECTED_DATA,
                data: vec![0; MAX_DATA - 6],
            }],
        };
        assert_eq!(fits.to_bytes().unwrap().len(), MAX_DATA);
        // Too many items, and a packet with too much data.
        let many = Cpf {
            items: vec![CpfItem::null_address(); MAX_CPF_ITEMS + 1],
        };
        assert_eq!(many.to_bytes(), Err(Error::TooLong));
        let p = packet(Command::SendRRData, 0, vec![0; MAX_DATA + 1]);
        assert_eq!(p.to_bytes(), Err(Error::TooLong));
    }

    #[test]
    fn packets_are_at_most_65535_bytes() {
        let longest = packet(Command::Nop, 0, vec![0; MAX_DATA]);
        let bytes = longest.to_bytes().unwrap();
        assert_eq!(bytes.len(), 65535);
        let (back, _) = Packet::parse_prefix(&bytes).unwrap();
        assert_eq!(back.check(), Ok(()));
        // One byte more is read whole, so the stream keeps its place, but
        // fails the check and cannot be written.
        let mut over = bytes.clone();
        over[2..4].copy_from_slice(&65512u16.to_le_bytes());
        over.push(0);
        over.extend_from_slice(&bytes);
        let (back, used) = Packet::parse_prefix(&over).unwrap();
        assert_eq!(used, 65536);
        assert_eq!(back.check(), Err(Error::TooLong));
        assert_eq!(back.to_bytes(), Err(Error::TooLong));
        assert_eq!(Packet::parse_prefix(&over[used..]).unwrap().0, longest);
    }

    #[test]
    fn forward_open_with_configuration_and_network_segments_reads() {
        // Assembly class 4, configuration instance 3, connection points 1
        // and 2, then one word of configuration data.
        let path_bytes = [
            0x20, 0x04, 0x24, 0x03, 0x2c, 0x01, 0x2c, 0x02, 0x80, 0x01, 0x00, 0x01,
        ];
        let want = vec![
            PathSegment::Class(4),
            PathSegment::Instance(3),
            PathSegment::ConnectionPoint(1),
            PathSegment::ConnectionPoint(2),
            PathSegment::Data(vec![0x00, 0x01]),
        ];
        assert_eq!(parse_path(&path_bytes), Ok(want.clone()));
        assert_eq!(write_path(&want).unwrap(), path_bytes);
        let mut body = ForwardOpenRequest {
            priority_time_tick: 0x0a,
            timeout_ticks: 0x0e,
            o_t_connection_id: 0,
            t_o_connection_id: 0,
            connection_serial: 1,
            vendor_id: 1,
            originator_serial: 2,
            timeout_multiplier: 1,
            o_t_rpi: 10_000,
            o_t_params: 0x4802,
            t_o_rpi: 10_000,
            t_o_params: 0x4802,
            transport_class_trigger: 0x01,
            connection_path: want,
        }
        .to_bytes()
        .unwrap();
        assert_eq!(&body[36..], path_bytes);
        assert!(ForwardOpenRequest::parse(&body).is_ok());
        // A production inhibit time of 10 ms (0x43), and one in
        // microseconds (0x51, two words).
        let inhibit = [0x43, 0x0a, 0x51, 0x02, 0x10, 0x27, 0x00, 0x00];
        let want = vec![
            PathSegment::Network {
                segment_type: 0x43,
                data: vec![0x0a],
            },
            PathSegment::Network {
                segment_type: 0x51,
                data: vec![0x10, 0x27, 0x00, 0x00],
            },
        ];
        assert_eq!(parse_path(&inhibit), Ok(want.clone()));
        assert_eq!(write_path(&want).unwrap(), inhibit);
        body[35] += 4;
        body.extend_from_slice(&inhibit);
        let open = ForwardOpenRequest::parse(&body).unwrap();
        assert_eq!(open.connection_path.len(), 7);
        assert_eq!(open.to_bytes().unwrap(), body);
        // Fields that do not form the segment are refused.
        let bad = [
            PathSegment::Data(vec![1]),
            PathSegment::Network {
                segment_type: 0x43,
                data: vec![],
            },
            PathSegment::Network {
                segment_type: 0x51,
                data: vec![1],
            },
            PathSegment::Network {
                segment_type: 0x20,
                data: vec![1],
            },
        ];
        let want = [
            Error::OddLength,
            Error::BadSegment,
            Error::OddLength,
            Error::BadSegment,
        ];
        for (segment, err) in bad.iter().zip(want) {
            assert_eq!(
                write_path(std::slice::from_ref(segment)),
                Err(err),
                "{segment:?}"
            );
        }
    }

    #[test]
    fn class_and_attribute_have_no_32_bit_form() {
        assert_eq!(
            parse_path(&[0x22, 0x00, 0x00, 0x00, 0x01, 0x00]),
            Err(Error::BadSegment)
        );
        assert_eq!(
            parse_path(&[0x32, 0x00, 0x01, 0x00, 0x00, 0x00]),
            Err(Error::BadSegment)
        );
        // Instance, member and connection point do.
        assert_eq!(
            parse_path(&[0x26, 0x00, 0x00, 0x00, 0x01, 0x00]),
            Ok(vec![PathSegment::Instance(0x1_0000)])
        );
        assert_eq!(
            parse_path(&[0x2e, 0x00, 0x00, 0x00, 0x01, 0x00]),
            Ok(vec![PathSegment::ConnectionPoint(0x1_0000)])
        );
        // The widest class and attribute are 16 bits.
        let wide = vec![
            PathSegment::Class(u16::MAX),
            PathSegment::Attribute(u16::MAX),
        ];
        let bytes = write_path(&wide).unwrap();
        assert_eq!(bytes, [0x21, 0x00, 0xff, 0xff, 0x31, 0x00, 0xff, 0xff]);
        assert_eq!(parse_path(&bytes), Ok(wide));
    }

    #[test]
    fn nonzero_options_fail_the_check_and_are_never_written() {
        let request = packet(Command::ListIdentity, 1, Vec::new());
        let mut bytes = packet(Command::ListIdentity, 0, Vec::new())
            .to_bytes()
            .unwrap();
        bytes[20] = 1;
        let (back, _) = Packet::parse_prefix(&bytes).unwrap();
        assert_eq!(back, request);
        assert_eq!(back.check(), Err(Error::Options));
        assert_eq!(back.to_bytes(), Err(Error::Options));
        // A reply sets the options to 0.
        let reply = back.reply(encap_status::SUCCESS, Vec::new());
        assert_eq!(reply.options, 0);
        assert!(reply.to_bytes().is_ok());
    }

    #[test]
    fn send_data_needs_an_address_item_and_a_data_item() {
        assert_eq!(SendData::parse(&[0; 8]), Err(Error::Items));
        let one = send_data(vec![CpfItem::null_address()]);
        assert_eq!(one.to_bytes(), Err(Error::Items));
        // A null address item carries no bytes.
        let mut bytes = send_data(vec![
            CpfItem::null_address(),
            CpfItem {
                type_id: item::UNCONNECTED_DATA,
                data: vec![1, 2],
            },
        ])
        .to_bytes()
        .unwrap();
        bytes[10] = 1;
        bytes.insert(12, 0xff);
        assert_eq!(SendData::parse(&bytes), Err(Error::Items));
        let bad = send_data(vec![
            CpfItem {
                type_id: item::NULL_ADDRESS,
                data: vec![0xff],
            },
            CpfItem {
                type_id: item::UNCONNECTED_DATA,
                data: vec![1, 2],
            },
        ]);
        assert_eq!(bad.to_bytes(), Err(Error::Items));
        // Data item first is refused; a connected pair reads.
        let swapped = send_data(vec![
            CpfItem {
                type_id: item::UNCONNECTED_DATA,
                data: vec![1, 2],
            },
            CpfItem::null_address(),
        ]);
        assert_eq!(swapped.to_bytes(), Err(Error::Items));
        let connected = send_data(vec![
            CpfItem {
                type_id: item::CONNECTED_ADDRESS,
                data: vec![1, 0, 0, 0],
            },
            CpfItem {
                type_id: item::CONNECTED_DATA,
                data: vec![1, 0, 0x0e, 0x00],
            },
        ]);
        assert_eq!(
            SendData::parse(&connected.to_bytes().unwrap()),
            Ok(connected)
        );
    }

    #[test]
    fn product_names_are_at_most_32_bytes() {
        let mut b = vec![0u8; IDENTITY_FIXED];
        b.push(33);
        b.extend_from_slice(&[b'A'; 33]);
        b.push(0xff);
        assert_eq!(Identity::parse(&b), Err(Error::TooLong));
        let mut id = Identity::parse(&[vec![0u8; IDENTITY_FIXED], vec![0, 0xff]].concat()).unwrap();
        id.product_name = vec![b'A'; 33];
        assert_eq!(id.to_bytes(), Err(Error::TooLong));
    }

    #[test]
    fn writers_refuse_values_that_read_back_as_others() {
        // A named code held in Other would read back as its name.
        assert_eq!(
            packet(Command::Other(0x65), 0, Vec::new()).to_bytes(),
            Err(Error::Unwritable)
        );
        let other = packet(Command::Other(0x72), 0, Vec::new());
        assert_eq!(
            Packet::parse_prefix(&other.to_bytes().unwrap()).unwrap().0,
            other
        );
        // A request's service with the reply bit, or a reply's.
        let req = MessageRequest {
            service: 0x8e,
            path: vec![PathSegment::Class(1)],
            data: Vec::new(),
        };
        assert_eq!(req.to_bytes(), Err(Error::ReplyFlag));
        let resp = MessageResponse {
            service: 0x8e,
            status: 0,
            additional_status: Vec::new(),
            data: Vec::new(),
        };
        assert_eq!(resp.to_bytes(), Err(Error::ReplyFlag));
        // An odd application reply is refused, not padded.
        let close = ForwardCloseResponse {
            connection_serial: 1,
            vendor_id: 2,
            originator_serial: 3,
            application_reply: vec![0xaa],
        };
        assert_eq!(close.to_bytes(), Err(Error::OddLength));
        let close = ForwardCloseResponse {
            application_reply: vec![0xaa, 0xbb],
            ..close
        };
        assert_eq!(
            ForwardCloseResponse::parse(&close.to_bytes().unwrap()),
            Ok(close)
        );
        let open = ForwardOpenResponse {
            o_t_connection_id: 0,
            t_o_connection_id: 0,
            connection_serial: 0,
            vendor_id: 0,
            originator_serial: 0,
            o_t_api: 0,
            t_o_api: 0,
            application_reply: vec![0; MAX_WORD_COUNTED + 2],
        };
        assert_eq!(open.to_bytes(), Err(Error::TooLong));
    }

    #[test]
    fn request_with_reply_bit_is_rejected() {
        // 0x8e is a Get_Attribute_Single reply, not a request.
        assert_eq!(
            MessageRequest::parse(&[0x8e, 0x01, 0x20, 0x01]),
            Err(Error::ReplyFlag)
        );
    }

    #[test]
    fn response_without_reply_bit_is_rejected() {
        // 0x0e with no reply bit is a request, not a reply.
        assert_eq!(
            MessageResponse::parse(&[0x0e, 0x00, 0x00, 0x00]),
            Err(Error::ReplyFlag)
        );
    }

    #[test]
    fn connection_point_segment_round_trips() {
        // An I/O Forward Open path: assembly class 4, instance 1, connection
        // point 0x65 (logical type 3, 0x2c).
        let bytes = [0x20, 0x04, 0x24, 0x01, 0x2c, 0x65];
        let path = vec![
            PathSegment::Class(4),
            PathSegment::Instance(1),
            PathSegment::ConnectionPoint(0x65),
        ];
        assert_eq!(parse_path(&bytes), Ok(path.clone()));
        assert_eq!(write_path(&path).unwrap(), bytes);
    }

    #[test]
    fn electronic_key_segment_round_trips() {
        // Key format 4: vendor 1, device type 0x0e, product 0x36, revision
        // 20.11 with the compatibility bit set.
        let bytes = [0x34, 0x04, 0x01, 0x00, 0x0e, 0x00, 0x36, 0x00, 0x94, 0x0b];
        let key = PathSegment::ElectronicKey {
            vendor_id: 1,
            device_type: 0x0e,
            product_code: 0x36,
            major_revision: 0x94,
            minor_revision: 0x0b,
        };
        assert_eq!(parse_path(&bytes), Ok(vec![key.clone()]));
        assert_eq!(write_path(std::slice::from_ref(&key)).unwrap(), bytes);
        for n in 1..bytes.len() {
            assert_eq!(parse_path(&bytes[..n]), Err(Error::Truncated), "{n} bytes");
        }
        // Another key format.
        let mut other = bytes;
        other[1] = 0x05;
        assert_eq!(parse_path(&other), Err(Error::BadSegment));
        // A special segment that is not an electronic key.
        assert_eq!(parse_path(&[0x35, 0x00]), Err(Error::UnknownSegment(0x35)));
    }

    #[test]
    fn samples_read_down_to_their_messages() {
        let samples = samples();
        // The Forward Open and the tag read ride in a send-data envelope.
        for k in [3, 4] {
            let (p, used) = Packet::parse_prefix(&samples[k]).unwrap();
            assert_eq!(used, samples[k].len());
            let send = SendData::parse(&p.data).unwrap();
            let req = MessageRequest::parse(&send.cpf.items[1].data).unwrap();
            if k == 3 {
                let open = ForwardOpenRequest::parse(&req.data).unwrap();
                assert_eq!(open.connection_path.len(), 5);
            } else {
                assert_eq!(req.path[0], PathSegment::Symbol(b"Counter".to_vec()));
            }
        }
        let (p, _) = Packet::parse_prefix(&samples[5]).unwrap();
        let cpf = Cpf::parse(&p.data).unwrap();
        let id = Identity::parse(&cpf.items[0].data).unwrap();
        assert_eq!(id.product_name, b"1756-L71");
    }

    #[test]
    fn member_and_symbol_segments_round_trip() {
        // A Logix tag read path: symbol "Counter" (7 bytes, so one pad
        // byte), then member 3.
        let bytes = [
            0x91, 0x07, b'C', b'o', b'u', b'n', b't', b'e', b'r', 0x00, 0x28, 0x03,
        ];
        let path = vec![
            PathSegment::Symbol(b"Counter".to_vec()),
            PathSegment::Member(3),
        ];
        assert_eq!(parse_path(&bytes), Ok(path.clone()));
        assert_eq!(write_path(&path).unwrap(), bytes);
        for n in 1..bytes.len() {
            // A prefix that ends after the symbol is a whole path.
            if n == 10 {
                continue;
            }
            assert_eq!(parse_path(&bytes[..n]), Err(Error::Truncated), "{n} bytes");
        }
        // An even-length name has no pad byte.
        let even = vec![PathSegment::Symbol(b"ab".to_vec())];
        assert_eq!(write_path(&even).unwrap(), [0x91, 0x02, b'a', b'b']);
        assert_eq!(parse_path(&[0x91, 0x02, b'a', b'b']), Ok(even));
        // An empty name.
        assert_eq!(
            parse_path(&[0x91, 0x00]),
            Ok(vec![PathSegment::Symbol(Vec::new())])
        );
        // A data segment that is neither simple data nor an ANSI symbol.
        assert_eq!(parse_path(&[0x81, 0x00]), Err(Error::UnknownSegment(0x81)));
        // A name past the limit is refused when written, not cut.
        let long = MessageRequest {
            service: service::GET_ATTRIBUTE_SINGLE,
            path: vec![PathSegment::Symbol(vec![b'x'; MAX_SYMBOL + 1])],
            data: Vec::new(),
        };
        assert_eq!(long.to_bytes(), Err(Error::TooLong));
    }

    #[test]
    fn identity_round_trip_and_errors() {
        let id = Identity {
            protocol_version: PROTOCOL_VERSION,
            socket_family: 2,
            socket_port: PORT,
            socket_address: [192, 168, 1, 10],
            vendor_id: 1,
            device_type: 0x0e,
            product_code: 0x36,
            revision: [20, 11],
            status: 0x0030,
            serial_number: 0x1234_5678,
            product_name: b"PLC".to_vec(),
            state: 3,
        };
        let bytes = id.to_bytes().unwrap();
        let want: Vec<u8> = [
            &[0x01, 0x00][..],
            // Family 2, port 44818 (0xaf12) and 192.168.1.10, big-endian.
            &[0x00, 0x02, 0xaf, 0x12, 192, 168, 1, 10],
            &[0; 8],
            &[0x01, 0x00, 0x0e, 0x00, 0x36, 0x00, 20, 11, 0x30, 0x00],
            &[0x78, 0x56, 0x34, 0x12],
            &[3, b'P', b'L', b'C', 3],
        ]
        .concat();
        assert_eq!(bytes, want);
        assert_eq!(Identity::parse(&bytes), Ok(id.clone()));
        // Reserved socket-address bytes are ignored and written as zeros.
        let mut noncanonical = bytes.clone();
        noncanonical[10..18].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let parsed = <Identity as Wire>::parse(&noncanonical).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(parsed.to_bytes().unwrap(), bytes);
        contract::check_wire::<Identity>(&noncanonical);
        for n in 0..bytes.len() {
            assert_eq!(
                Identity::parse(&bytes[..n]),
                Err(Error::Truncated),
                "{n} bytes"
            );
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(Identity::parse(&extra), Err(Error::Trailing));
        // A name of 32 bytes is the longest an identity may give.
        let longest = Identity {
            product_name: vec![b'n'; MAX_PRODUCT_NAME],
            ..id.clone()
        };
        assert_eq!(Identity::parse(&longest.to_bytes().unwrap()), Ok(longest));
    }

    #[test]
    fn packet_reply_echoes_the_header() {
        let request = Packet {
            command: Command::RegisterSession,
            session_handle: 0,
            status: 0,
            sender_context: [9; 8],
            options: 0,
            data: RegisterSession {
                protocol_version: PROTOCOL_VERSION,
                options: 0,
            }
            .to_bytes()
            .unwrap(),
        };
        let reply = request.reply(encap_status::UNSUPPORTED_PROTOCOL, Vec::new());
        assert_eq!(reply.command, Command::RegisterSession);
        assert_eq!(reply.sender_context, [9; 8]);
        assert_eq!(reply.status, encap_status::UNSUPPORTED_PROTOCOL);
        assert!(reply.data.is_empty());
    }

    /// Representative encapsulation packets with nested CIP messages.
    fn samples() -> Vec<Vec<u8>> {
        let register = Packet {
            command: Command::RegisterSession,
            session_handle: 0,
            status: 0,
            sender_context: [0; 8],
            options: 0,
            data: RegisterSession {
                protocol_version: PROTOCOL_VERSION,
                options: 0,
            }
            .to_bytes()
            .unwrap(),
        };
        let list = Packet {
            command: Command::ListIdentity,
            session_handle: 0,
            status: 0,
            sender_context: [1, 2, 3, 4, 5, 6, 7, 8],
            options: 0,
            data: Vec::new(),
        };
        let read = MessageRequest::get_attribute(1, 1, 7);
        let send = Packet {
            command: Command::SendRRData,
            session_handle: 1,
            status: 0,
            sender_context: [0; 8],
            options: 0,
            data: SendData {
                interface_handle: 0,
                timeout: 0,
                cpf: Cpf {
                    items: vec![
                        CpfItem::null_address(),
                        CpfItem {
                            type_id: item::UNCONNECTED_DATA,
                            data: read.to_bytes().unwrap(),
                        },
                    ],
                },
            }
            .to_bytes()
            .unwrap(),
        };
        let open = ForwardOpenRequest {
            priority_time_tick: 0x0a,
            timeout_ticks: 0x0e,
            o_t_connection_id: 0,
            t_o_connection_id: 0,
            connection_serial: 1,
            vendor_id: 1,
            originator_serial: 2,
            timeout_multiplier: 1,
            o_t_rpi: 10_000,
            o_t_params: 0x4802,
            t_o_rpi: 10_000,
            t_o_params: 0x4802,
            transport_class_trigger: 0x01,
            connection_path: vec![
                PathSegment::Port {
                    port: 1,
                    link: vec![0],
                },
                PathSegment::ElectronicKey {
                    vendor_id: 1,
                    device_type: 0x0e,
                    product_code: 0x36,
                    major_revision: 0x94,
                    minor_revision: 0x0b,
                },
                PathSegment::Class(4),
                PathSegment::Instance(1),
                PathSegment::ConnectionPoint(0x65),
            ],
        };
        let forward_open = MessageRequest {
            service: service::FORWARD_OPEN,
            path: vec![PathSegment::Class(6), PathSegment::Instance(1)],
            data: open.to_bytes().unwrap(),
        };
        let open_packet = Packet {
            command: Command::SendRRData,
            session_handle: 1,
            status: 0,
            sender_context: [0; 8],
            options: 0,
            data: SendData {
                interface_handle: 0,
                timeout: 0,
                cpf: Cpf {
                    items: vec![
                        CpfItem::null_address(),
                        CpfItem {
                            type_id: item::UNCONNECTED_DATA,
                            data: forward_open.to_bytes().unwrap(),
                        },
                    ],
                },
            }
            .to_bytes()
            .unwrap(),
        };
        let tag_read = MessageRequest {
            service: 0x4c,
            path: vec![
                PathSegment::Symbol(b"Counter".to_vec()),
                PathSegment::Member(3),
            ],
            data: vec![1, 0],
        };
        let identity = Identity {
            protocol_version: PROTOCOL_VERSION,
            socket_family: 2,
            socket_port: PORT,
            socket_address: [10, 0, 0, 5],
            vendor_id: 1,
            device_type: 0x0e,
            product_code: 0x36,
            revision: [20, 11],
            status: 0x0030,
            serial_number: 0x1234_5678,
            product_name: b"1756-L71".to_vec(),
            state: 0xff,
        };
        let wrap = |command: Command, items: Vec<CpfItem>| {
            Packet {
                command,
                session_handle: 1,
                status: 0,
                sender_context: [0; 8],
                options: 0,
                data: SendData {
                    interface_handle: 0,
                    timeout: 0,
                    cpf: Cpf { items },
                }
                .to_bytes()
                .unwrap(),
            }
            .to_bytes()
            .unwrap()
        };
        let tag_packet = wrap(
            Command::SendRRData,
            vec![
                CpfItem::null_address(),
                CpfItem {
                    type_id: item::UNCONNECTED_DATA,
                    data: tag_read.to_bytes().unwrap(),
                },
            ],
        );
        let identity_packet = Packet {
            command: Command::ListIdentity,
            session_handle: 0,
            status: 0,
            sender_context: [0; 8],
            options: 0,
            data: Cpf {
                items: vec![CpfItem {
                    type_id: item::LIST_IDENTITY_RESPONSE,
                    data: identity.to_bytes().unwrap(),
                }],
            }
            .to_bytes()
            .unwrap(),
        };
        vec![
            register.to_bytes().unwrap(),
            list.to_bytes().unwrap(),
            send.to_bytes().unwrap(),
            open_packet.to_bytes().unwrap(),
            tag_packet,
            identity_packet.to_bytes().unwrap(),
        ]
    }

    /// Checks stream contracts, packet validation and nested CIP values.
    fn check(data: &[u8]) {
        assert_eq!(
            Stream::new(Frames::<Packet>::new()).push(data),
            data.len().min(PACKETS_CAPACITY)
        );
        contract::check_decode(Frames::<Packet>::new, data);
        let (packets, _) = decode_all(Frames::<Packet>::new, data);
        for p in &packets {
            contract::check_wire_value(p);
            assert_eq!(p.check().is_ok(), p.to_bytes().is_ok());
            contract::check_wire::<SendData>(&p.data);
            if let Ok(send) = SendData::parse(&p.data) {
                for it in &send.cpf.items {
                    check_item(&it.data);
                }
            }
            contract::check_wire::<Cpf>(&p.data);
            if let Ok(cpf) = Cpf::parse(&p.data) {
                for it in &cpf.items {
                    check_item(&it.data);
                }
            }
            check_item(&p.data);
        }
    }

    /// Checks wire contracts for a CIP item and its nested message bodies.
    fn check_item(b: &[u8]) {
        contract::check_wire::<MessageRequest>(b);
        if let Ok(req) = MessageRequest::parse(b) {
            contract::check_wire::<ForwardOpenRequest>(&req.data);
            contract::check_wire::<ForwardCloseRequest>(&req.data);
        }
        contract::check_wire::<MessageResponse>(b);
        if let Ok(resp) = MessageResponse::parse(b) {
            contract::check_wire::<ForwardOpenResponse>(&resp.data);
        }
        contract::check_wire::<Identity>(b);
    }

    #[test]
    fn random_bytes_never_panic_and_round_trip() {
        let mut rng = Lcg::new(0x656e_6970);
        let samples = samples();
        let mut read = 0;
        for i in 0..6000 {
            let data: Vec<u8> = if i % 2 == 0 {
                rng.bytes(63)
            } else {
                let mut d = samples[rng.index(samples.len())].clone();
                for _ in 0..1 + rng.below(4) {
                    test_support::mutate(&mut rng, &mut d);
                }
                d
            };
            if Packet::parse_prefix(&data).is_some() {
                read += 1;
            }
            check(&data);
            // Every parsed CIP value must write and read back unchanged.
            contract::check_wire::<Cpf>(&data);
            contract::check_wire::<SendData>(&data);
            contract::check_wire::<MessageRequest>(&data);
            contract::check_wire::<MessageResponse>(&data);
            let _ = parse_path(&data);
            contract::check_wire::<ForwardOpenRequest>(&data);
            contract::check_wire::<ForwardOpenResponse>(&data);
            contract::check_wire::<ForwardCloseRequest>(&data);
            contract::check_wire::<ForwardCloseResponse>(&data);
            contract::check_wire::<RegisterSession>(&data);
            contract::check_wire::<Identity>(&data);
        }
        assert!(read > 500, "{read} packets read");
    }
}
