//! L2TP: reading and writing the headers, control messages and AVPs of
//! the Layer 2 Tunneling Protocol over UDP, with no I/O.
//!
//! L2TP carries a link layer, such as a PPP session or an Ethernet
//! pseudowire, between two hosts over an IP network. A VPN concentrator
//! and its clients use it, and so do the access networks of most ISPs.
//! Two peers first set up a control connection (a tunnel) with control
//! messages, then open sessions inside it, and send the session's frames
//! as data messages. Everything goes over UDP, usually to port 1701.
//!
//! This module reads and writes two versions. L2TPv2 (RFC 2661) has one
//! header for both kinds of message. Its first 16 bits hold the T bit
//! (control or data), the L, S and O bits (which say whether the length,
//! the sequence numbers and the offset fields are there) and the P bit
//! (priority). Then come a 16-bit tunnel ID and a 16-bit session ID. Such
//! a datagram is a [`V2Packet`]. L2TPv3 (RFC 3931) has a control header
//! with a 32-bit control connection ID, a [`V3Control`], and a separate
//! data header over UDP with a 32-bit session ID and an optional cookie,
//! a [`V3Data`]. [`Packet::parse`] tells the three apart by the version
//! field and the T bit.
//!
//! A control message's body is a list of attribute-value pairs (AVPs),
//! read as a [`ControlMessage`]. The first AVP says what the message is,
//! a [`MessageType`]. A body with no AVPs at all is a zero-length body
//! (ZLB) acknowledgment. Each [`Avp`] keeps its mandatory (M) and hidden
//! (H) bits. A hidden value is scrambled with a secret the two peers
//! share, so it is kept as the bytes that came, and recovering it is up
//! to world code.
//!
//! Nothing here reads a socket. A world that plays an LNS (the server
//! end) takes each UDP datagram it receives, reads it with
//! [`Packet::parse`], reads a control message's AVPs, and sends the bytes
//! of what it answers. Which tunnels and sessions exist, the sequence
//! numbers, the retransmissions and what the frames carry are up to
//! world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Reserved header bits are written as zero. A reader ignores those
//! bits. [`Avp::reserved_bits`] reports received AVP reserved bits so an
//! L2TPv2 peer can treat the AVP as unknown (RFC 2661 section 4.1).
//! Parsed values omit those bits, and writers always send them as zero.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::l2tp::{attribute, Avp, ControlMessage, MessageType, Packet, V2Packet};
//!
//! // An SCCRQ from a client: the L2TPv2 control header (T, L and S set,
//! // version 2, length 55, tunnel 0, session 0, Ns 0, Nr 0), then five
//! // AVPs: the message type, protocol version 1.0, host name "lac",
//! // framing capabilities 3 and assigned tunnel ID 1.
//! let datagram = [
//!     0xc8, 0x02, 0, 55, 0, 0, 0, 0, 0, 0, 0, 0, //
//!     0x80, 8, 0, 0, 0, 0, 0, 1, //
//!     0x80, 8, 0, 0, 0, 2, 1, 0, //
//!     0x80, 9, 0, 0, 0, 7, b'l', b'a', b'c', //
//!     0x80, 10, 0, 0, 0, 3, 0, 0, 0, 3, //
//!     0x80, 8, 0, 0, 0, 9, 0, 1,
//! ];
//! let Ok(Packet::V2(packet)) = Packet::parse(&datagram) else { panic!() };
//! assert!(packet.control);
//! let request = packet.message().unwrap();
//! assert_eq!(request.message_type, Some(MessageType::Sccrq));
//! let peer = request.find(attribute::ASSIGNED_TUNNEL_ID).and_then(Avp::as_u16);
//! assert_eq!(peer, Some(1));
//! assert_eq!(request.find(attribute::HOST_NAME).unwrap().value, b"lac");
//!
//! // The reply, an SCCRP to the client's tunnel 1, which assigns tunnel 7
//! // on this side.
//! let reply = ControlMessage::new(
//!     MessageType::Sccrp,
//!     vec![
//!         Avp::from_u16(attribute::PROTOCOL_VERSION, 0x0100),
//!         Avp::new(attribute::HOST_NAME, b"lns".to_vec()),
//!         Avp::from_u32(attribute::FRAMING_CAPABILITIES, 3),
//!         Avp::from_u16(attribute::ASSIGNED_TUNNEL_ID, 7),
//!     ],
//! );
//! let bytes = V2Packet::control(1, 0, 0, 1, &reply).unwrap().to_bytes().unwrap();
//! assert_eq!(bytes[..12], [0xc8, 0x02, 0, 55, 0, 1, 0, 0, 0, 0, 0, 1]);
//! let Ok(Packet::V2(back)) = Packet::parse(&bytes) else { panic!() };
//! assert_eq!(back.message(), Ok(reply));
//! ```

extern crate self as fictionet;
use fictionet::stdlib::codec::Wire;

/// The UDP port L2TP peers listen on.
pub const PORT: u16 = 1701;
/// The longest datagram a reader takes: the most a UDP datagram can
/// carry, 65535 bytes less its 8-byte header.
pub const MAX_DATAGRAM: usize = 65_527;
/// The length of a control message header, in L2TPv2 and in L2TPv3 over
/// UDP alike: 12 bytes before the first AVP.
pub const CONTROL_HEADER_LEN: usize = 12;
/// The shortest L2TPv2 header: the flags and version, the tunnel ID and
/// the session ID, with no optional fields.
pub const V2_MIN_HEADER_LEN: usize = 6;
/// The length of the L2TPv3 data header over UDP, before the cookie.
pub const V3_DATA_HEADER_LEN: usize = 8;
/// The longest L2TPv3 cookie, in bytes. A cookie is 0, 4 or 8 bytes long.
pub const MAX_COOKIE: usize = 8;
/// The longest control message body: the longest datagram less the
/// control header.
pub const MAX_MESSAGE: usize = MAX_DATAGRAM - CONTROL_HEADER_LEN;
/// The length of an AVP header: the bits and length, the vendor ID and
/// the attribute type.
pub const AVP_HEADER_LEN: usize = 6;
/// The longest AVP, header included: its length field is 10 bits wide.
pub const MAX_AVP_LEN: usize = 1023;
/// The longest AVP value.
pub const MAX_AVP_VALUE: usize = MAX_AVP_LEN - AVP_HEADER_LEN;
/// The most AVPs one control message may hold, message type included.
pub const MAX_AVPS: usize = 1024;
/// The version field of an L2TPv2 header.
pub const VERSION_2: u8 = 2;
/// The version field of an L2TPv3 header.
pub const VERSION_3: u8 = 3;

/// The bits in the first 16 bits of an L2TP header.
pub mod bits {
    /// The T bit: set for a control message, clear for a data message.
    pub const T: u16 = 0x8000;
    /// The L bit: the length field is there.
    pub const L: u16 = 0x4000;
    /// The S bit: the Ns and Nr fields are there.
    pub const S: u16 = 0x0800;
    /// L2TPv2 only, the O bit: the offset size field is there.
    pub const O: u16 = 0x0200;
    /// L2TPv2 only, the P bit: the data message should be sent ahead of
    /// others.
    pub const P: u16 = 0x0100;
    /// The version field, the low 4 bits.
    pub const VERSION: u16 = 0x000f;
}

/// The bits in the first 16 bits of an AVP.
pub mod avp_bits {
    /// The M bit: a peer that does not know the AVP must tear down the
    /// session or tunnel it came in.
    pub const M: u16 = 0x8000;
    /// The H bit: the value is hidden.
    pub const H: u16 = 0x4000;
    /// The 4 reserved bits.
    pub const RESERVED: u16 = 0x3c00;
    /// The length field, the low 10 bits.
    pub const LENGTH: u16 = 0x03ff;
}

/// IETF attribute types (vendor ID 0), from the IANA registry: RFC 2661,
/// then the ones RFC 3931 adds.
pub mod attribute {
    #![allow(missing_docs)]
    pub const MESSAGE_TYPE: u16 = 0;
    pub const RESULT_CODE: u16 = 1;
    pub const PROTOCOL_VERSION: u16 = 2;
    pub const FRAMING_CAPABILITIES: u16 = 3;
    pub const BEARER_CAPABILITIES: u16 = 4;
    pub const TIE_BREAKER: u16 = 5;
    pub const FIRMWARE_REVISION: u16 = 6;
    pub const HOST_NAME: u16 = 7;
    pub const VENDOR_NAME: u16 = 8;
    pub const ASSIGNED_TUNNEL_ID: u16 = 9;
    pub const RECEIVE_WINDOW_SIZE: u16 = 10;
    pub const CHALLENGE: u16 = 11;
    pub const Q931_CAUSE_CODE: u16 = 12;
    pub const CHALLENGE_RESPONSE: u16 = 13;
    pub const ASSIGNED_SESSION_ID: u16 = 14;
    pub const CALL_SERIAL_NUMBER: u16 = 15;
    pub const MINIMUM_BPS: u16 = 16;
    pub const MAXIMUM_BPS: u16 = 17;
    pub const BEARER_TYPE: u16 = 18;
    pub const FRAMING_TYPE: u16 = 19;
    pub const CALLED_NUMBER: u16 = 21;
    pub const CALLING_NUMBER: u16 = 22;
    pub const SUB_ADDRESS: u16 = 23;
    pub const TX_CONNECT_SPEED_BPS: u16 = 24;
    pub const PHYSICAL_CHANNEL_ID: u16 = 25;
    pub const INITIAL_RECEIVED_LCP_CONFREQ: u16 = 26;
    pub const LAST_SENT_LCP_CONFREQ: u16 = 27;
    pub const LAST_RECEIVED_LCP_CONFREQ: u16 = 28;
    pub const PROXY_AUTHEN_TYPE: u16 = 29;
    pub const PROXY_AUTHEN_NAME: u16 = 30;
    pub const PROXY_AUTHEN_CHALLENGE: u16 = 31;
    pub const PROXY_AUTHEN_ID: u16 = 32;
    pub const PROXY_AUTHEN_RESPONSE: u16 = 33;
    pub const CALL_ERRORS: u16 = 34;
    pub const ACCM: u16 = 35;
    pub const RANDOM_VECTOR: u16 = 36;
    pub const PRIVATE_GROUP_ID: u16 = 37;
    pub const RX_CONNECT_SPEED_BPS: u16 = 38;
    pub const SEQUENCING_REQUIRED: u16 = 39;
    pub const EXTENDED_VENDOR_ID: u16 = 58;
    pub const MESSAGE_DIGEST: u16 = 59;
    pub const ROUTER_ID: u16 = 60;
    pub const ASSIGNED_CONTROL_CONNECTION_ID: u16 = 61;
    pub const PSEUDOWIRE_CAPABILITIES_LIST: u16 = 62;
    pub const LOCAL_SESSION_ID: u16 = 63;
    pub const REMOTE_SESSION_ID: u16 = 64;
    pub const ASSIGNED_COOKIE: u16 = 65;
    pub const REMOTE_END_ID: u16 = 66;
    pub const PSEUDOWIRE_TYPE: u16 = 68;
    pub const L2_SPECIFIC_SUBLAYER: u16 = 69;
    pub const DATA_SEQUENCING: u16 = 70;
    pub const CIRCUIT_STATUS: u16 = 71;
    pub const PREFERRED_LANGUAGE: u16 = 72;
    pub const CONTROL_MESSAGE_AUTHENTICATION_NONCE: u16 = 73;
    pub const TX_CONNECT_SPEED: u16 = 74;
    pub const RX_CONNECT_SPEED: u16 = 75;
}

/// Why bytes are not an L2TP datagram, control message or AVP. A real
/// peer drops such a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// Bytes follow the declared unit length.
    Trailing,
    /// The value cannot be written without changing it.
    Unwritable,
    /// The bytes ended before a header, a field or an AVP did.
    Truncated,
    /// The bytes were longer than [`MAX_DATAGRAM`], or a control message
    /// body longer than [`MAX_MESSAGE`]. It holds the length.
    TooLong(usize),
    /// The version field was not the one asked for, or not 2 or 3. It
    /// holds the field.
    Version(u8),
    /// A control message without the L or S bit, or, in L2TPv2, with the
    /// O or P bit.
    ControlBits,
    /// A control message was asked for and the T bit was clear.
    NotControl,
    /// A data message was asked for and the T bit was set.
    NotData,
    /// The length field was shorter than the header. It holds the field.
    Length(u16),
    /// The offset size ran past the end of the message. It holds the
    /// size.
    Offset(u16),
    /// A cookie length other than 0, 4 or 8. It holds the length.
    Cookie(usize),
    /// An AVP's length field was below 6, the length of its header. It
    /// holds the field.
    AvpLength(u16),
    /// A control message held more than [`MAX_AVPS`] AVPs.
    TooManyAvps,
    /// A control message's first AVP was not a message type AVP:
    /// attribute 0, not hidden, with a 2-byte value.
    MessageType,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Trailing => f.write_str("bytes after the unit"),
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Truncated => f.write_str("the bytes end before the header, field or AVP does"),
            Error::TooLong(n) => write!(f, "{n} bytes, longer than an L2TP datagram or message can be"),
            Error::Version(v) => write!(f, "L2TP version {v}, not the one expected"),
            Error::ControlBits => f.write_str("a control message without L and S, or with O or P"),
            Error::NotControl => f.write_str("a data message where a control message was expected"),
            Error::NotData => f.write_str("a control message where a data message was expected"),
            Error::Length(n) => write!(f, "length field {n}, shorter than the header"),
            Error::Offset(n) => write!(f, "offset size {n}, past the end of the message"),
            Error::Cookie(n) => write!(f, "cookie length {n}, not 0, 4 or 8"),
            Error::AvpLength(n) => write!(f, "AVP length {n}, shorter than the AVP header"),
            Error::TooManyAvps => write!(f, "more than {MAX_AVPS} AVPs in one message"),
            Error::MessageType => f.write_str("the first AVP is not a message type AVP"),
        }
    }
}

impl std::error::Error for Error {}

/// A control message's type: the value of its first AVP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// 1: Start-Control-Connection-Request.
    Sccrq,
    /// 2: Start-Control-Connection-Reply.
    Sccrp,
    /// 3: Start-Control-Connection-Connected.
    Scccn,
    /// 4: Stop-Control-Connection-Notification.
    StopCcn,
    /// 6: Hello, a keepalive.
    Hello,
    /// 7: Outgoing-Call-Request.
    Ocrq,
    /// 8: Outgoing-Call-Reply.
    Ocrp,
    /// 9: Outgoing-Call-Connected.
    Occn,
    /// 10: Incoming-Call-Request.
    Icrq,
    /// 11: Incoming-Call-Reply.
    Icrp,
    /// 12: Incoming-Call-Connected.
    Iccn,
    /// 14: Call-Disconnect-Notify.
    Cdn,
    /// 15: WAN-Error-Notify.
    Wen,
    /// 16: Set-Link-Info.
    Sli,
    /// 20: Explicit Acknowledgement, from RFC 3931.
    Ack,
    /// Any other type.
    Other(u16),
}

impl MessageType {
    /// The type's number.
    pub fn code(self) -> u16 {
        match self {
            MessageType::Sccrq => 1,
            MessageType::Sccrp => 2,
            MessageType::Scccn => 3,
            MessageType::StopCcn => 4,
            MessageType::Hello => 6,
            MessageType::Ocrq => 7,
            MessageType::Ocrp => 8,
            MessageType::Occn => 9,
            MessageType::Icrq => 10,
            MessageType::Icrp => 11,
            MessageType::Iccn => 12,
            MessageType::Cdn => 14,
            MessageType::Wen => 15,
            MessageType::Sli => 16,
            MessageType::Ack => 20,
            MessageType::Other(c) => c,
        }
    }

    /// The type for number `c`.
    pub fn from_code(c: u16) -> MessageType {
        match c {
            1 => MessageType::Sccrq,
            2 => MessageType::Sccrp,
            3 => MessageType::Scccn,
            4 => MessageType::StopCcn,
            6 => MessageType::Hello,
            7 => MessageType::Ocrq,
            8 => MessageType::Ocrp,
            9 => MessageType::Occn,
            10 => MessageType::Icrq,
            11 => MessageType::Icrp,
            12 => MessageType::Iccn,
            14 => MessageType::Cdn,
            15 => MessageType::Wen,
            16 => MessageType::Sli,
            20 => MessageType::Ack,
            c => MessageType::Other(c),
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            MessageType::Sccrq => "SCCRQ",
            MessageType::Sccrp => "SCCRP",
            MessageType::Scccn => "SCCCN",
            MessageType::StopCcn => "StopCCN",
            MessageType::Hello => "HELLO",
            MessageType::Ocrq => "OCRQ",
            MessageType::Ocrp => "OCRP",
            MessageType::Occn => "OCCN",
            MessageType::Icrq => "ICRQ",
            MessageType::Icrp => "ICRP",
            MessageType::Iccn => "ICCN",
            MessageType::Cdn => "CDN",
            MessageType::Wen => "WEN",
            MessageType::Sli => "SLI",
            MessageType::Ack => "ACK",
            MessageType::Other(c) => return write!(f, "message type {c}"),
        };
        f.write_str(name)
    }
}

/// One attribute-value pair.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Avp {
    /// The M bit: a peer that does not know this AVP must give up on the
    /// session or tunnel.
    pub mandatory: bool,
    /// The H bit: the value is hidden, scrambled with the shared secret
    /// and the last Random Vector AVP. It is kept as the bytes that came.
    pub hidden: bool,
    /// The vendor ID: 0 for the attributes the IETF defines, otherwise
    /// the vendor's SMI Network Management Private Enterprise Code.
    pub vendor: u16,
    /// The attribute type, such as one in [`attribute`].
    pub attribute: u16,
    /// The value. The writer refuses more than [`MAX_AVP_VALUE`] bytes.
    pub value: Vec<u8>,
}

impl Avp {
    /// A mandatory IETF AVP that is not hidden.
    pub fn new(attribute: u16, value: Vec<u8>) -> Avp {
        Avp { mandatory: true, hidden: false, vendor: 0, attribute, value }
    }

    /// A mandatory IETF AVP holding a 16-bit number.
    pub fn from_u16(attribute: u16, value: u16) -> Avp {
        Avp::new(attribute, value.to_be_bytes().to_vec())
    }

    /// A mandatory IETF AVP holding a 32-bit number.
    pub fn from_u32(attribute: u16, value: u32) -> Avp {
        Avp::new(attribute, value.to_be_bytes().to_vec())
    }

    /// The value as a 16-bit number, if it is not hidden and is 2 bytes
    /// long.
    pub fn as_u16(&self) -> Option<u16> {
        match (self.hidden, self.value.as_slice()) {
            (false, &[a, b]) => Some(u16::from_be_bytes([a, b])),
            _ => None,
        }
    }

    /// The value as a 32-bit number, if it is not hidden and is 4 bytes
    /// long.
    pub fn as_u32(&self) -> Option<u32> {
        match (self.hidden, self.value.as_slice()) {
            (false, &[a, b, c, d]) => Some(u32::from_be_bytes([a, b, c, d])),
            _ => None,
        }
    }

    /// Reads the four reserved bits from an AVP's first two bytes.
    /// Refuses fewer than two bytes. It does not validate the rest of the AVP.
    /// L2TPv2 treats nonzero bits as an unknown AVP; L2TPv3 ignores them.
    pub fn reserved_bits(b: &[u8]) -> Result<u8, Error> {
        let word = b.first_chunk::<2>().ok_or(Error::Truncated)?;
        Ok(((u16::from_be_bytes(*word) & avp_bits::RESERVED) >> 10) as u8)
    }

    /// Reads the AVP at the start of `b`, and how many bytes it took.
    fn parse_prefix(b: &[u8]) -> Result<(Avp, usize), Error> {
        let Some(header) = b.first_chunk::<AVP_HEADER_LEN>() else {
            return Err(Error::Truncated);
        };
        let word = u16::from_be_bytes([header[0], header[1]]);
        let length = word & avp_bits::LENGTH;
        let len = usize::from(length);
        if len < AVP_HEADER_LEN {
            return Err(Error::AvpLength(length));
        }
        let Some(value) = b.get(AVP_HEADER_LEN..len) else {
            return Err(Error::Truncated);
        };
        let avp = Avp {
            mandatory: word & avp_bits::M != 0,
            hidden: word & avp_bits::H != 0,
            vendor: u16::from_be_bytes([header[2], header[3]]),
            attribute: u16::from_be_bytes([header[4], header[5]]),
            value: value.to_vec(),
        };
        Ok((avp, len))
    }
}

/// A control message body: its type, the bits of its message type AVP,
/// and the AVPs after that one. A message with no type is a zero-length
/// body (ZLB) acknowledgment, which holds no AVPs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ControlMessage {
    /// The message type, or `None` for a ZLB acknowledgment. A type
    /// from a vendor other than 0 is always [`MessageType::Other`].
    pub message_type: Option<MessageType>,
    /// The M bit of the message type AVP. It says what to do with a type
    /// the receiver does not know. If set, the tunnel or control
    /// connection must be cleared. If clear, the message may be ignored.
    /// The RFCs set it for every type they define.
    pub mandatory: bool,
    /// The vendor ID of the message type AVP: 0 for the types the IETF
    /// defines, otherwise the vendor of a vendor-specific message (RFC
    /// 3931 section 5.4.1).
    pub vendor: u16,
    /// The AVPs after the message type AVP, in order.
    pub avps: Vec<Avp>,
}

impl ControlMessage {
    /// A message of IETF type `message_type` with the M bit set, then
    /// `avps`.
    pub fn new(message_type: MessageType, avps: Vec<Avp>) -> ControlMessage {
        ControlMessage { message_type: Some(message_type), mandatory: true, vendor: 0, avps }
    }

    /// A ZLB acknowledgment: a control header with no body.
    pub fn zlb() -> ControlMessage {
        ControlMessage::default()
    }

    /// Whether this is a ZLB acknowledgment.
    pub fn is_zlb(&self) -> bool {
        self.message_type.is_none()
    }

    /// The first IETF AVP (vendor 0) of type `attribute`, if there is one.
    pub fn find(&self, attribute: u16) -> Option<&Avp> {
        self.find_vendor(0, attribute)
    }

    /// The first AVP from `vendor` of type `attribute`, if there is one.
    pub fn find_vendor(&self, vendor: u16, attribute: u16) -> Option<&Avp> {
        self.avps.iter().find(|a| a.vendor == vendor && a.attribute == attribute)
    }
}

/// An L2TPv2 datagram, control or data, with the fields its header holds.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct V2Packet {
    /// The T bit: a control message, whose payload is a
    /// [`ControlMessage`] body. Otherwise a data message, whose payload
    /// is a PPP frame.
    pub control: bool,
    /// The L bit: the header holds the message's length. A control
    /// message requires this to be true.
    pub has_length: bool,
    /// The S bit and the Ns and Nr fields: the message's sequence number,
    /// then the next one the sender expects. A control message always has
    /// them; the writer refuses `None` for a control message.
    pub sequence: Option<(u16, u16)>,
    /// The O bit and the offset padding: the bytes between the header and
    /// the payload, whose length is the offset size field. A control
    /// message requires `None`.
    pub offset_pad: Option<Vec<u8>>,
    /// The P bit: the data message should be sent ahead of others. A
    /// control message requires this to be false.
    pub priority: bool,
    /// The tunnel ID the receiver assigned.
    pub tunnel: u16,
    /// The session ID the receiver assigned, or 0 for a message about
    /// the whole tunnel.
    pub session: u16,
    /// What follows the header and any offset padding, up to the length
    /// field if there is one.
    pub payload: Vec<u8>,
}

impl V2Packet {
    /// A control message to `tunnel` and `session`, with sequence numbers
    /// `ns` and `nr`.
    pub fn control(tunnel: u16, session: u16, ns: u16, nr: u16, message: &ControlMessage) -> Result<V2Packet, Error> {
        Ok(V2Packet {
            control: true,
            has_length: true,
            sequence: Some((ns, nr)),
            offset_pad: None,
            priority: false,
            tunnel,
            session,
            payload: message.to_bytes()?,
        })
    }

    /// A data message to `tunnel` and `session` with no optional fields.
    pub fn data(tunnel: u16, session: u16, payload: Vec<u8>) -> V2Packet {
        V2Packet {
            control: false,
            has_length: false,
            sequence: None,
            offset_pad: None,
            priority: false,
            tunnel,
            session,
            payload,
        }
    }

    /// Reads the payload of a control message as a [`ControlMessage`].
    pub fn message(&self) -> Result<ControlMessage, Error> {
        if !self.control {
            return Err(Error::NotControl);
        }
        ControlMessage::parse(&self.payload)
    }
}

/// An L2TPv3 control message over UDP: the header's fields and the body.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct V3Control {
    /// The control connection ID the receiver assigned, or 0 before it
    /// has assigned one.
    pub connection: u32,
    /// The message's sequence number.
    pub ns: u16,
    /// The next sequence number the sender expects.
    pub nr: u16,
    /// The message body, AVPs read with [`ControlMessage::parse`].
    pub payload: Vec<u8>,
}

impl V3Control {
    /// A control message to `connection`, with sequence numbers `ns` and
    /// `nr`.
    pub fn new(connection: u32, ns: u16, nr: u16, message: &ControlMessage) -> Result<V3Control, Error> {
        Ok(V3Control { connection, ns, nr, payload: message.to_bytes()? })
    }

    /// Reads the body as a [`ControlMessage`].
    pub fn message(&self) -> Result<ControlMessage, Error> {
        ControlMessage::parse(&self.payload)
    }
}

/// An L2TPv3 data message over UDP: the session, the cookie and the
/// frame. An L2-Specific Sublayer, if the session has one, stays at the
/// front of the payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct V3Data<const COOKIE_LEN: usize = 0> {
    /// The session ID the receiver assigned.
    pub session: u32,
    /// The cookie: 0, 4 or 8 bytes, a length the peers agree on when they
    /// set up the session. A writer refuses a cookie of another length.
    pub cookie: Vec<u8>,
    /// The bytes after the cookie.
    pub payload: Vec<u8>,
}

/// Any L2TP datagram over UDP, told apart by the version and the T bit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Packet {
    /// An L2TPv2 control or data message.
    V2(V2Packet),
    /// An L2TPv3 control message.
    V3Control(V3Control),
    /// An L2TPv3 data message, read with no cookie. A session with a
    /// cookie reads the datagram again with [`V3Data::parse`].
    V3Data(V3Data),
}

impl Packet {
    /// Whether this is a control message.
    pub fn is_control(&self) -> bool {
        match self {
            Packet::V2(p) => p.control,
            Packet::V3Control(_) => true,
            Packet::V3Data(_) => false,
        }
    }
}

/// Checks an L2TPv3 datagram's length and version, and gives its first
/// 16 bits.
fn v3_word(b: &[u8]) -> Result<u16, Error> {
    if b.len() > MAX_DATAGRAM {
        return Err(Error::TooLong(b.len()));
    }
    let Some(&[f0, f1]) = b.first_chunk::<2>() else {
        return Err(Error::Truncated);
    };
    let word = u16::from_be_bytes([f0, f1]);
    let version = (word & bits::VERSION) as u8;
    if version != VERSION_3 {
        return Err(Error::Version(version));
    }
    if word & bits::T == 0 && b.len() < V3_DATA_HEADER_LEN {
        return Err(Error::Truncated);
    }
    Ok(word)
}

/// The big-endian 16-bit number at `i`. Callers check the length first.
fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

/// The big-endian 32-bit number at `i`. Callers check the length first.
fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

impl Wire for Avp {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one AVP, ignoring reserved bits. Refuses incomplete fields and
    /// trailing bytes. Inspect received bits with [`Avp::reserved_bits`].
    fn parse(b: &[u8]) -> Result<Avp, Error> {
        let (avp, used) = Self::parse_prefix(b)?;
        if used != b.len() {
            return Err(Error::Trailing);
        }
        Ok(avp)
    }

    /// Appends the AVP with reserved bits zero. Refuses values above
    /// [`MAX_AVP_VALUE`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.value.len() > MAX_AVP_VALUE {
            return Err(Error::Unwritable);
        }
        let value = &self.value;
        let mut out = Vec::new();
        let mut word = (AVP_HEADER_LEN + value.len()) as u16;
        if self.mandatory {
            word |= avp_bits::M;
        }
        if self.hidden {
            word |= avp_bits::H;
        }
        out.extend_from_slice(&word.to_be_bytes());
        out.extend_from_slice(&self.vendor.to_be_bytes());
        out.extend_from_slice(&self.attribute.to_be_bytes());
        out.extend_from_slice(value);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for ControlMessage {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a control message body: the bytes after the control header.
    /// Empty bytes are a ZLB acknowledgment. Otherwise the body must be
    /// whole AVPs, at most [`MAX_AVPS`] of them, and the first one a
    /// message type AVP. Its M bit and vendor ID are kept. Reserved bits
    /// are ignored; [`Avp::reserved_bits`] reads them from the body header.
    /// Refuses malformed or trailing input.
    fn parse(body: &[u8]) -> Result<ControlMessage, Error> {
        if body.len() > MAX_MESSAGE {
            return Err(Error::TooLong(body.len()));
        }
        if body.is_empty() {
            return Ok(ControlMessage::zlb());
        }
        let (first, mut at) = Avp::parse_prefix(body)?;
        let code = match (first.attribute, first.as_u16()) {
            (attribute::MESSAGE_TYPE, Some(code)) => code,
            _ => return Err(Error::MessageType),
        };
        let message_type = match first.vendor {
            0 => MessageType::from_code(code),
            _ => MessageType::Other(code),
        };
        let mut avps = Vec::new();
        while at < body.len() {
            if avps.len() + 1 >= MAX_AVPS {
                return Err(Error::TooManyAvps);
            }
            let (avp, used) = Avp::parse_prefix(&body[at..])?;
            avps.push(avp);
            at += used;
        }
        Ok(ControlMessage {
            message_type: Some(message_type),
            mandatory: first.mandatory,
            vendor: first.vendor,
            avps,
        })
    }

    /// Appends every AVP. Refuses invalid AVPs, oversized messages or counts,
    /// nonempty ZLB values, and message types that would change on reading.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let Some(t) = self.message_type else {
            if self != &Self::zlb() {
                return Err(Error::Unwritable);
            }
            return Ok(());
        };
        if self.avps.len() >= MAX_AVPS {
            return Err(Error::Unwritable);
        }
        let mut out = Vec::new();
        Avp { mandatory: self.mandatory, vendor: self.vendor,
            ..Avp::from_u16(attribute::MESSAGE_TYPE, t.code()) }.write(&mut out)?;
        for avp in &self.avps {
            avp.write(&mut out)?;
            if out.len() > MAX_MESSAGE {
                return Err(Error::Unwritable);
            }
        }
        if Self::parse(&out).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for V2Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole L2TPv2 datagram, the UDP payload. Bytes past the
    /// length field, if there is one, are not part of the message and are
    /// ignored. Reserved header bits are ignored.
    /// Refuses malformed or oversized input.
    fn parse(b: &[u8]) -> Result<V2Packet, Error> {
        if b.len() > MAX_DATAGRAM {
            return Err(Error::TooLong(b.len()));
        }
        let Some(&[f0, f1]) = b.first_chunk::<2>() else {
            return Err(Error::Truncated);
        };
        let word = u16::from_be_bytes([f0, f1]);
        let version = (word & bits::VERSION) as u8;
        if version != VERSION_2 {
            return Err(Error::Version(version));
        }
        let control = word & bits::T != 0;
        let (l, s, o, p) = (word & bits::L != 0, word & bits::S != 0, word & bits::O != 0, word & bits::P != 0);
        if control && (!l || !s || o || p) {
            return Err(Error::ControlBits);
        }
        let header = V2_MIN_HEADER_LEN + 2 * usize::from(l) + 4 * usize::from(s) + 2 * usize::from(o);
        if b.len() < header {
            return Err(Error::Truncated);
        }
        let mut at = 2;
        let mut end = b.len();
        if l {
            let length = be16(b, at);
            at += 2;
            if usize::from(length) < header {
                return Err(Error::Length(length));
            }
            if usize::from(length) > b.len() {
                return Err(Error::Truncated);
            }
            end = usize::from(length);
        }
        let tunnel = be16(b, at);
        let session = be16(b, at + 2);
        at += 4;
        let sequence = if s {
            at += 4;
            Some((be16(b, at - 4), be16(b, at - 2)))
        } else {
            None
        };
        let offset_pad = if o {
            let size = be16(b, at);
            at += 2;
            let Some(pad) = b.get(at..end).and_then(|rest| rest.get(..usize::from(size))) else {
                return Err(Error::Offset(size));
            };
            at += pad.len();
            Some(pad.to_vec())
        } else {
            None
        };
        let payload = b.get(at..end).ok_or(Error::Truncated)?.to_vec();
        Ok(V2Packet { control, has_length: l, sequence, offset_pad, priority: p, tunnel, session, payload })
    }

    /// Appends the complete packet. Refuses invalid control flags, missing control sequence
    /// numbers, and oversized payloads or offset padding. Control bodies remain raw bytes.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.control && (!self.has_length || self.sequence.is_none() || self.offset_pad.is_some() || self.priority) {
            return Err(Error::Unwritable);
        }
        let l = self.has_length;
        let sequence = self.sequence;
        let pad = self.offset_pad.as_deref();
        let priority = self.priority;
        let header = V2_MIN_HEADER_LEN
            + 2 * usize::from(l)
            + 4 * usize::from(sequence.is_some())
            + 2 * usize::from(pad.is_some());
        let total = header.checked_add(pad.map_or(0, <[u8]>::len))
            .and_then(|n| n.checked_add(self.payload.len())).filter(|n| *n <= MAX_DATAGRAM).ok_or(Error::Unwritable)?;
        let payload = &self.payload;

        let mut word = u16::from(VERSION_2);
        if self.control {
            word |= bits::T;
        }
        if l {
            word |= bits::L;
        }
        if sequence.is_some() {
            word |= bits::S;
        }
        if pad.is_some() {
            word |= bits::O;
        }
        if priority {
            word |= bits::P;
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&word.to_be_bytes());
        if l {
            out.extend_from_slice(&(total as u16).to_be_bytes());
        }
        out.extend_from_slice(&self.tunnel.to_be_bytes());
        out.extend_from_slice(&self.session.to_be_bytes());
        if let Some((ns, nr)) = sequence {
            out.extend_from_slice(&ns.to_be_bytes());
            out.extend_from_slice(&nr.to_be_bytes());
        }
        if let Some(pad) = pad {
            out.extend_from_slice(&(pad.len() as u16).to_be_bytes());
            out.extend_from_slice(pad);
        }
        out.extend_from_slice(payload);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for V3Control {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole L2TPv3 control datagram, the UDP payload. Bytes past
    /// the length field are ignored. Reserved header bits are ignored.
    /// Refuses malformed or oversized input.
    fn parse(b: &[u8]) -> Result<V3Control, Error> {
        let word = v3_word(b)?;
        if word & bits::T == 0 {
            return Err(Error::NotControl);
        }
        if word & (bits::L | bits::S) != bits::L | bits::S {
            return Err(Error::ControlBits);
        }
        if b.len() < CONTROL_HEADER_LEN {
            return Err(Error::Truncated);
        }
        let length = be16(b, 2);
        if usize::from(length) < CONTROL_HEADER_LEN {
            return Err(Error::Length(length));
        }
        let payload = b.get(CONTROL_HEADER_LEN..usize::from(length)).ok_or(Error::Truncated)?;
        Ok(V3Control { connection: be32(b, 4), ns: be16(b, 8), nr: be16(b, 10), payload: payload.to_vec() })
    }

    /// Appends the complete control packet. Refuses oversized control bodies.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.payload.len() > MAX_MESSAGE {
            return Err(Error::Unwritable);
        }
        let payload = &self.payload;
        let total = CONTROL_HEADER_LEN + payload.len();
        let word = bits::T | bits::L | bits::S | u16::from(VERSION_3);
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&word.to_be_bytes());
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&self.connection.to_be_bytes());
        out.extend_from_slice(&self.ns.to_be_bytes());
        out.extend_from_slice(&self.nr.to_be_bytes());
        out.extend_from_slice(payload);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl<const COOKIE_LEN: usize> Wire for V3Data<COOKIE_LEN> {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole L2TPv3 data datagram whose session uses a cookie of
    /// `COOKIE_LEN` bytes. The header's reserved bits are ignored.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let cookie_len = COOKIE_LEN;
        if !matches!(cookie_len, 0 | 4 | 8) {
            return Err(Error::Cookie(cookie_len));
        }
        let word = v3_word(b)?;
        if word & bits::T != 0 {
            return Err(Error::NotData);
        }
        let Some(cookie) = b.get(V3_DATA_HEADER_LEN..V3_DATA_HEADER_LEN + cookie_len) else {
            return Err(Error::Truncated);
        };
        Ok(V3Data {
            session: be32(b, 4),
            cookie: cookie.to_vec(),
            payload: b[V3_DATA_HEADER_LEN + cookie_len..].to_vec(),
        })
    }

    /// Appends the data packet. Refuses COOKIE_LEN outside 0, 4 or 8, a stored
    /// cookie of another length and an oversized payload. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let cookie = self.cookie.as_slice();
        if cookie.len() != COOKIE_LEN || !matches!(COOKIE_LEN, 0 | 4 | 8) {
            return Err(Error::Unwritable);
        }
        let room = MAX_DATAGRAM - V3_DATA_HEADER_LEN - cookie.len();
        if self.payload.len() > room {
            return Err(Error::Unwritable);
        }
        let payload = &self.payload;
        let mut out = Vec::with_capacity(V3_DATA_HEADER_LEN + cookie.len() + payload.len());
        out.extend_from_slice(&u16::from(VERSION_3).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(cookie);
        out.extend_from_slice(payload);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole datagram, the UDP payload. Version 1 (L2F) and any
    /// other version but 2 and 3 is [`Error::Version`].
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Packet, Error> {
        if b.len() > MAX_DATAGRAM {
            return Err(Error::TooLong(b.len()));
        }
        let Some(&[f0, f1]) = b.first_chunk::<2>() else {
            return Err(Error::Truncated);
        };
        let word = u16::from_be_bytes([f0, f1]);
        match (word & bits::VERSION) as u8 {
            VERSION_2 => V2Packet::parse(b).map(Packet::V2),
            VERSION_3 if word & bits::T != 0 => V3Control::parse(b).map(Packet::V3Control),
            VERSION_3 => V3Data::parse(b).map(Packet::V3Data),
            v => Err(Error::Version(v)),
        }
    }

    /// Appends the complete wire form. Refuses values that exceed wire limits
    /// or cannot be read back unchanged. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Packet::V2(p) => p.write(dst),
            Packet::V3Control(p) => p.write(dst),
            Packet::V3Data(p) => p.write(dst),
        }
    }
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::codec::{contract, test_support::{Lcg, mutate}};
    use super::*;

    /// The SCCRQ from the module doc.
    fn sccrq() -> Vec<u8> {
        vec![
            0xc8, 0x02, 0, 55, 0, 0, 0, 0, 0, 0, 0, 0, //
            0x80, 8, 0, 0, 0, 0, 0, 1, //
            0x80, 8, 0, 0, 0, 2, 1, 0, //
            0x80, 9, 0, 0, 0, 7, b'l', b'a', b'c', //
            0x80, 10, 0, 0, 0, 3, 0, 0, 0, 3, //
            0x80, 8, 0, 0, 0, 9, 0, 1,
        ]
    }

    #[test]
    fn rfc2661_control_header() {
        let bytes = sccrq();
        let p = V2Packet::parse(&bytes).unwrap();
        assert!(p.control && p.has_length && !p.priority);
        assert_eq!(p.sequence, Some((0, 0)));
        assert_eq!(p.offset_pad, None);
        assert_eq!((p.tunnel, p.session), (0, 0));
        assert_eq!(p.payload.len(), 43);
        assert_eq!(p.to_bytes().unwrap(), bytes);
        let m = p.message().unwrap();
        assert_eq!(m.message_type, Some(MessageType::Sccrq));
        assert_eq!(m.avps.len(), 4);
        assert_eq!(m.find(attribute::PROTOCOL_VERSION).and_then(Avp::as_u16), Some(0x0100));
        assert_eq!(m.find(attribute::FRAMING_CAPABILITIES).and_then(Avp::as_u32), Some(3));
        assert_eq!(m.find(attribute::CHALLENGE), None);
        assert_eq!(m.to_bytes().unwrap(), bytes[12..]);
        // Trailing bytes past the length field are not part of it.
        let mut longer = bytes.clone();
        longer.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(V2Packet::parse(&longer), Ok(p));
        contract::check_wire::<V2Packet>(&longer);
    }

    #[test]
    fn zlb_ack() {
        // A ZLB: the control header alone, Ns 3, Nr 5.
        let bytes = [0xc8, 0x02, 0, 12, 0, 7, 0, 0, 0, 3, 0, 5];
        let p = V2Packet::parse(&bytes).unwrap();
        assert_eq!(p.sequence, Some((3, 5)));
        let m = p.message().unwrap();
        assert!(m.is_zlb());
        assert_eq!(V2Packet::control(7,0,3,5,&ControlMessage::zlb()).unwrap().to_bytes().unwrap(), bytes);
        // A ZLB cannot carry AVPs.
        let odd = ControlMessage { avps: vec![Avp::from_u16(9, 1)], ..ControlMessage::zlb() };
        assert_eq!(odd.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&odd);
    }

    #[test]
    fn data_header_with_every_option() {
        // T clear; L, S, O and P set; length 20; tunnel 1, session 2;
        // Ns 3, Nr 4; offset size 2 with pad 0xee 0xee; then a PPP frame
        // start (0xff 0x03 0xc0 0x21).
        let bytes = [0x4b, 0x02, 0, 20, 0, 1, 0, 2, 0, 3, 0, 4, 0, 2, 0xee, 0xee, 0xff, 0x03, 0xc0, 0x21];
        let p = V2Packet::parse(&bytes).unwrap();
        assert_eq!(
            p,
            V2Packet {
                control: false,
                has_length: true,
                sequence: Some((3, 4)),
                offset_pad: Some(vec![0xee, 0xee]),
                priority: true,
                tunnel: 1,
                session: 2,
                payload: vec![0xff, 0x03, 0xc0, 0x21],
            }
        );
        assert_eq!(p.to_bytes().unwrap(), bytes);
        assert_eq!(p.message(), Err(Error::NotControl));
        // The plainest data header: six bytes, then the frame.
        let plain = V2Packet::data(1, 2, vec![0xff, 0x03]);
        assert_eq!(plain.to_bytes().unwrap(), [0x00, 0x02, 0, 1, 0, 2, 0xff, 0x03]);
        assert_eq!(V2Packet::parse(&plain.to_bytes().unwrap()), Ok(plain));
    }

    #[test]
    fn reserved_header_bits_are_ignored_and_written_as_zero() {
        // Every x bit set on a data header, and on a control header.
        let data = [0x34, 0xf2, 0, 1, 0, 2, 9];
        let p = V2Packet::parse(&data).unwrap();
        assert_eq!(p.payload, [9]);
        assert_eq!(p.to_bytes().unwrap(), [0x00, 0x02, 0, 1, 0, 2, 9]);
        let mut ctl = sccrq();
        ctl[0] |= 0x34;
        ctl[1] |= 0xf0;
        assert_eq!(V2Packet::parse(&ctl).unwrap().to_bytes().unwrap(), sccrq());
    }

    #[test]
    fn avps() {
        // A hidden mandatory vendor AVP with reserved bits set: M, H,
        // rsvd 0b0101, length 10, vendor 9, attribute 0x1234, 4 bytes.
        let bytes = [0xd4, 10, 0, 9, 0x12, 0x34, 1, 2, 3, 4];
        let a = Avp::parse(&bytes).unwrap();
        assert_eq!(
            a,
            Avp { mandatory: true, hidden: true, vendor: 9, attribute: 0x1234, value: vec![1, 2, 3, 4] }
        );
        assert_eq!(a.as_u32(), None, "hidden values are not read");
        // Reserved bits are sent as zero.
        let mut zeroed = bytes;
        zeroed[0] &= 0xc3;
        assert_eq!(a.to_bytes().unwrap(), zeroed);
        let r = Avp::parse(&[0x84, 8, 0, 0, 0, 9, 0, 7]).unwrap();
        assert_eq!(Avp::reserved_bits(&bytes), Ok(5));
        contract::check_wire::<Avp>(&bytes);
        assert_eq!(r.to_bytes().unwrap(), [0x80, 8, 0, 0, 0, 9, 0, 7]);
        assert_eq!(Avp::parse(&bytes[..9]), Err(Error::Truncated));
        assert_eq!(Avp::parse(&[0x80, 5, 0, 0, 0, 0]), Err(Error::AvpLength(5)));
        // An oversized value cannot fit the length field.
        let big = Avp::new(attribute::CHALLENGE, vec![7; 5000]);
        assert_eq!(big.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&big);
        let boundary = Avp::new(attribute::CHALLENGE, vec![7; MAX_AVP_VALUE]);
        contract::check_wire_value(&boundary);
    }

    #[test]
    fn message_types() {
        for c in 0..=u16::MAX {
            assert_eq!(MessageType::from_code(c).code(), c);
        }
        assert_eq!(MessageType::from_code(20), MessageType::Ack);
        assert_eq!(MessageType::StopCcn.to_string(), "StopCCN");
        assert_eq!(MessageType::Other(5).to_string(), "message type 5");
    }

    #[test]
    fn message_errors() {
        // The first AVP is not a message type.
        assert_eq!(ControlMessage::parse(&[0x80, 8, 0, 0, 0, 9, 0, 1]), Err(Error::MessageType));
        // A hidden message type.
        assert_eq!(ControlMessage::parse(&[0xc0, 8, 0, 0, 0, 0, 0, 1]), Err(Error::MessageType));
        // A message type with a 3-byte value.
        assert_eq!(ControlMessage::parse(&[0x80, 9, 0, 0, 0, 0, 0, 1, 0]), Err(Error::MessageType));
        // An AVP that runs past the body, and a bad AVP length.
        assert_eq!(ControlMessage::parse(&[0x80, 8, 0, 0, 0, 0, 0, 6, 0x80, 9]), Err(Error::Truncated));
        let bad = [0x80, 8, 0, 0, 0, 0, 0, 6, 0x80, 2, 0, 0, 0, 0];
        assert_eq!(ControlMessage::parse(&bad), Err(Error::AvpLength(2)));
        // Too many AVPs, and too many bytes.
        let mut many = vec![0x80, 8, 0, 0, 0, 0, 0, 6];
        for _ in 0..MAX_AVPS {
            many.extend_from_slice(&[0, 6, 0, 0, 0, 50]);
        }
        assert_eq!(ControlMessage::parse(&many), Err(Error::TooManyAvps));
        assert_eq!(ControlMessage::parse(&vec![0; MAX_MESSAGE + 1]), Err(Error::TooLong(MAX_MESSAGE + 1)));
        // MAX_AVPS in all reads.
        many.truncate(8 + 6 * (MAX_AVPS - 1));
        assert_eq!(ControlMessage::parse(&many).unwrap().avps.len(), MAX_AVPS - 1);
    }

    #[test]
    fn message_type_m_bit_is_kept() {
        // RFC 2661 4.4.1 and RFC 3931 5.4.1: an unknown type with M clear
        // may be ignored, and one with M set clears the tunnel. So the
        // reader keeps the bit, and the writer writes it back.
        let optional = [0x00, 8, 0, 0, 0, 0, 0x7f, 0x00];
        let m = ControlMessage::parse(&optional).unwrap();
        assert!(!m.mandatory);
        assert_eq!(m.message_type, Some(MessageType::Other(0x7f00)));
        assert_eq!(m.to_bytes().unwrap(), optional);
        let required = ControlMessage::parse(&[0x80, 8, 0, 0, 0, 0, 0x7f, 0x00]).unwrap();
        assert!(required.mandatory);
        assert!(ControlMessage::new(MessageType::Hello, vec![]).mandatory);
    }

    #[test]
    fn message_type_reserved_bits_are_read_and_written_as_zero() {
        let bytes = [0x84, 8, 0, 0, 0, 0, 0, 6];
        let m = ControlMessage::parse(&bytes).unwrap();
        assert_eq!(m.message_type, Some(MessageType::Hello));
        assert_eq!(Avp::reserved_bits(&bytes), Ok(1));
        assert_eq!(m.to_bytes().unwrap(), [0x80, 8, 0, 0, 0, 0, 0, 6]);
        assert_eq!(Avp::reserved_bits(&m.to_bytes().unwrap()), Ok(0));
        assert_eq!(Avp::reserved_bits(&[]), Err(Error::Truncated));
        contract::check_wire::<ControlMessage>(&bytes);
    }

    #[test]
    fn vendor_message_types_are_read() {
        // RFC 3931 5.4.1: a vendor-specific control message sets the
        // Vendor ID of its Message Type AVP. Vendor 9, type 1, M clear.
        let body = [0x00, 8, 0, 9, 0, 0, 0, 1, 0x80, 8, 0, 0, 0, 9, 0, 1];
        let m = ControlMessage::parse(&body).unwrap();
        assert_eq!(m.vendor, 9);
        assert_eq!(m.message_type, Some(MessageType::Other(1)), "not the IETF SCCRQ");
        assert_eq!(m.avps.len(), 1);
        assert_eq!(m.to_bytes().unwrap(), body);
    }

    #[test]
    fn header_errors() {
        assert_eq!(Packet::parse(&[]), Err(Error::Truncated));
        assert_eq!(Packet::parse(&[0xc8]), Err(Error::Truncated));
        assert_eq!(Packet::parse(&[0xc8, 0x01, 0, 12]), Err(Error::Version(1)));
        assert_eq!(V2Packet::parse(&[0xc8, 0x03]), Err(Error::Version(3)));
        assert_eq!(V3Control::parse(&[0xc8, 0x02]), Err(Error::Version(2)));
        assert_eq!(Packet::parse(&vec![0; MAX_DATAGRAM + 1]), Err(Error::TooLong(MAX_DATAGRAM + 1)));
        // Control messages need L and S, and must not have O or P.
        assert_eq!(V2Packet::parse(&[0x88, 0x02]), Err(Error::ControlBits));
        assert_eq!(V2Packet::parse(&[0xc0, 0x02]), Err(Error::ControlBits));
        assert_eq!(V2Packet::parse(&[0xca, 0x02]), Err(Error::ControlBits));
        assert_eq!(V2Packet::parse(&[0xc9, 0x02]), Err(Error::ControlBits));
        assert_eq!(V3Control::parse(&[0x80, 0x03]), Err(Error::ControlBits));
        // A length field shorter than the header.
        assert_eq!(V2Packet::parse(&[0xc8, 0x02, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::Length(11)));
        assert_eq!(V3Control::parse(&[0xc8, 0x03, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::Length(4)));
        // A length field longer than the datagram.
        assert_eq!(V2Packet::parse(&[0xc8, 0x02, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::Truncated));
        // An offset past the end.
        assert_eq!(V2Packet::parse(&[0x02, 0x02, 0, 1, 0, 2, 0, 3, 0xee, 0xee]), Err(Error::Offset(3)));
        // The wrong kind for the reader asked.
        assert_eq!(V3Control::parse(&[0x00, 0x03, 0, 0, 0, 0, 0, 1]), Err(Error::NotControl));
        assert_eq!(V3Data::<0>::parse(&sccrq_v3()), Err(Error::NotData));
        assert_eq!(V3Data::<5>::parse(&[0, 3, 0, 0, 0, 0, 0, 1]), Err(Error::Cookie(5)));
        assert_eq!(V3Data::<4>::parse(&[0, 3, 0, 0, 0, 0, 0, 1, 1, 2]), Err(Error::Truncated));
        for e in [Error::Truncated, Error::Cookie(1), Error::Offset(3), Error::TooManyAvps] {
            assert!(!e.to_string().is_empty());
        }
    }

    /// An L2TPv3 SCCRQ: connection 0, Ns 0, Nr 0, the message type AVP
    /// and an assigned control connection ID of 0x01020304.
    fn sccrq_v3() -> Vec<u8> {
        vec![
            0xc8, 0x03, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, //
            0x80, 8, 0, 0, 0, 0, 0, 1, //
            0x80, 10, 0, 0, 0, 61, 1, 2, 3, 4,
        ]
    }

    #[test]
    fn rfc3931_control_and_data() {
        let bytes = sccrq_v3();
        let Ok(Packet::V3Control(c)) = Packet::parse(&bytes) else { panic!() };
        assert_eq!((c.connection, c.ns, c.nr), (0, 0, 0));
        let m = c.message().unwrap();
        assert_eq!(m.message_type, Some(MessageType::Sccrq));
        assert_eq!(m.find(attribute::ASSIGNED_CONTROL_CONNECTION_ID).and_then(Avp::as_u32), Some(0x0102_0304));
        assert_eq!(c.to_bytes().unwrap(), bytes);
        assert_eq!(V3Control::new(0,0,0,&m).unwrap(), c);
        // An ACK to connection 0x01020304.
        let ack = V3Control::new(0x0102_0304,1,1,&ControlMessage::new(MessageType::Ack, vec![])).unwrap();
        assert_eq!(ack.to_bytes().unwrap(), [0xc8, 0x03, 0, 20, 1, 2, 3, 4, 0, 1, 0, 1, 0x80, 8, 0, 0, 0, 0, 0, 20]);

        // A data message: session 0x11223344, a 4-byte cookie, a frame.
        let d = [0x00, 0x03, 0, 0, 0x11, 0x22, 0x33, 0x44, 0xc0, 0x0c, 0x1e, 0x00, 0xde, 0xad];
        let Ok(Packet::V3Data(plain)) = Packet::parse(&d) else { panic!() };
        assert_eq!(plain.cookie, []);
        assert_eq!(plain.payload.len(), 6);
        let v = V3Data::<4>::parse(&d).unwrap();
        assert_eq!(v, V3Data { session: 0x1122_3344, cookie: vec![0xc0, 0x0c, 0x1e, 0x00], payload: vec![0xde, 0xad] });
        assert_eq!(v.to_bytes(), Ok(d.to_vec()));
        assert_eq!(v.to_bytes(), Ok(d.to_vec()));
        assert_eq!(V3Data::<8>::parse(&d), Err(Error::Truncated));
        assert_eq!(V3Data::<4>::parse(&d[..12]).unwrap().payload, []);
        // Reserved bits in the data header are ignored and written as zero.
        let mut r = d;
        r[0] = 0x7f;
        r[1] = 0xf3;
        r[2] = 0xff;
        assert_eq!(V3Data::<4>::parse(&r).unwrap().to_bytes(), Ok(d.to_vec()));
        // A cookie of a length other than 0, 4 or 8 is refused, not cut.
        for n in [1, 3, 5, 6, 7, 9, 12] {
            let odd = V3Data::<0> { session: 1, cookie: vec![1; n], payload: vec![] };
            assert_eq!(odd.to_bytes(), Err(Error::Unwritable));
            assert_eq!(Packet::V3Data(odd).to_bytes(), Err(Error::Unwritable));
        }
    }

    #[test]
    fn every_truncated_prefix() {
        let examples = [
            sccrq(),
            sccrq_v3(),
            vec![0x4b, 0x02, 0, 20, 0, 1, 0, 2, 0, 3, 0, 4, 0, 2, 0xee, 0xee, 0xff, 0x03, 0xc0, 0x21],
        ];
        for bytes in &examples {
            for n in 0..bytes.len() {
                let r = Packet::parse(&bytes[..n]);
                assert!(r.is_err(), "{n} bytes of {bytes:?}");
                if n < 2 {
                    assert_eq!(r, Err(Error::Truncated));
                }
            }
        }
        // Control bodies cut anywhere but between AVPs fail.
        let body = &sccrq()[12..];
        let bounds = [0, 8, 16, 25, 35, 43];
        for n in 0..=body.len() {
            let r = ControlMessage::parse(&body[..n]);
            assert_eq!(r.is_ok(), bounds.contains(&n), "{n} bytes");
        }
        let d = [0x00, 0x03, 0, 0, 0x11, 0x22, 0x33, 0x44, 1, 2, 3, 4];
        for n in 0..d.len() {
            assert!(V3Data::<4>::parse(&d[..n]).is_err() || n >= 12);
            assert_eq!(V3Data::<0>::parse(&d[..n]).is_ok(), n >= 8);
        }
    }

    #[test]
    fn writers_refuse_oversized_values() {
        let huge = vec![1u8; 100_000];
        let mut p = V2Packet::data(1, 2, huge.clone());
        p.has_length = true;
        p.sequence = Some((1, 2));
        p.offset_pad = Some(huge.clone());
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&p);
        let c = V3Control { connection: 1, ns: 0, nr: 0, payload: huge.clone() };
        assert_eq!(c.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&c);
        let d = V3Data::<8> { session: 1, cookie: vec![0; 8], payload: huge };
        assert_eq!(d.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&d);
        let many = ControlMessage::new(MessageType::Hello, vec![Avp::from_u16(50, 1); MAX_AVPS + 10]);
        let fat = ControlMessage::new(MessageType::Hello, vec![Avp::new(50, vec![0; MAX_AVP_VALUE]); 100]);
        for message in [many, fat] {
            assert_eq!(message.to_bytes(), Err(Error::Unwritable));
            contract::check_wire_value(&message);
            assert_eq!(V2Packet::control(1, 0, 0, 0, &message), Err(Error::Unwritable));
        }
    }

    #[test]
    fn oversized_control_bodies_are_refused() {
        // A message type AVP, 64 AVPs of 1023 bytes and one of 42: 65522
        // bytes, 7 more than a body can be. Cutting at MAX_MESSAGE would
        // end inside the last AVP. The writer refuses the whole body.
        let mut body = ControlMessage::new(MessageType::Hello, vec![]).to_bytes().unwrap();
        for _ in 0..64 {
            Avp::new(50, vec![0; MAX_AVP_VALUE]).write(&mut body).unwrap();
        }
        Avp::new(51, vec![0; 36]).write(&mut body).unwrap();
        assert_eq!(body.len(), 65_522);
        assert_eq!(ControlMessage::parse(&body), Err(Error::TooLong(65_522)));
        let kept = ControlMessage::parse(&body[..65_522 - 42]).unwrap();
        assert_eq!(kept.avps.len(), 64);
        let c = V3Control { connection: 1, ns: 0, nr: 0, payload: body.clone() };
        assert_eq!(c.to_bytes(), Err(Error::Unwritable));
        let v2 = V2Packet { payload: body.clone(), ..V2Packet::control(1, 0, 0, 0, &ControlMessage::zlb()).unwrap() };
        assert_eq!(v2.to_bytes(), Err(Error::Unwritable));
        let bounded = V3Control::new(1, 0, 0, &kept).unwrap();
        assert_eq!(V3Control::parse(&bounded.to_bytes().unwrap()).unwrap().message(), Ok(kept));
        let junk = V3Control { connection: 1, ns: 0, nr: 0, payload: vec![0; 70_000] };
        assert_eq!(junk.to_bytes(), Err(Error::Unwritable));
        let data = V2Packet::data(1, 2, body);
        assert_eq!(data.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn writers_refuse_invalid_control_headers() {
        // A control packet built by hand with data-only fields.
        let p = V2Packet {
            control: true,
            has_length: false,
            sequence: None,
            offset_pad: Some(vec![1, 2]),
            priority: true,
            tunnel: 4,
            session: 5,
            payload: vec![],
        };
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&p);
    }

    #[test]
    fn find_vendor_avps() {
        let m = ControlMessage::new(
            MessageType::Hello,
            vec![Avp { vendor: 9, ..Avp::from_u16(attribute::HOST_NAME, 1) }, Avp::from_u16(attribute::HOST_NAME, 2)],
        );
        assert_eq!(m.find_vendor(9, attribute::HOST_NAME).and_then(Avp::as_u16), Some(1));
        assert_eq!(m.find(attribute::HOST_NAME).and_then(Avp::as_u16), Some(2));
        assert_eq!(m.find_vendor(8, attribute::HOST_NAME), None);
    }

    #[test]
    fn random_values_write_what_reads() {
        // Values built by hand, with any field contents: what the writers
        // give always reads, and writing what was read gives the same bytes.
        let mut rng = Lcg::new(0x0001_2661);
        let mut written = 0;
        for iteration in 0..2_000 {
            let u16r = |rng: &mut Lcg| u16::from_be_bytes([(rng.next() as u8), (rng.next() as u8)]);
            let mut avps = Vec::new();
            for _ in 0..rng.index(8) {
                avps.push(Avp {
                    mandatory: rng.coin(),
                    hidden: rng.coin(),
                    vendor: u16r(&mut rng),
                    attribute: u16r(&mut rng),
                    value: rng.bytes(MAX_AVP_VALUE),
                });
            }
            let mut message = ControlMessage {
                message_type: if avps.is_empty() && rng.index(8) == 0 {
                    None
                } else {
                    Some(MessageType::from_code(u16r(&mut rng)))
                },
                mandatory: rng.coin(),
                vendor: if rng.coin() { 0 } else { u16r(&mut rng) },
                avps,
            };
            if iteration % 16 == 0 {
                message.avps = vec![Avp::new(attribute::CHALLENGE, vec![]); MAX_AVPS];
            }
            if iteration % 17 == 0
                && let Some(avp) = message.avps.first_mut()
            {
                avp.value.resize(MAX_AVP_VALUE + 1, 0);
            }
            contract::check_wire_value(&message);
            let Ok(body) = message.to_bytes() else { continue };
            written += 1;
            let read = ControlMessage::parse(&body).unwrap();
            assert_eq!(read, message.clone());
            assert_eq!(read.to_bytes().unwrap(), body);
            let v2 = V2Packet {
                control: rng.coin(),
                has_length: rng.coin(),
                sequence: if rng.coin() { None } else { Some((u16r(&mut rng), u16r(&mut rng))) },
                offset_pad: if rng.coin() { None } else { Some(rng.bytes(40)) },
                priority: rng.coin(),
                tunnel: u16r(&mut rng),
                session: u16r(&mut rng),
                payload: body.clone(),
            };
            contract::check_wire_value(&v2);
            let c = V3Control::new(u32::from(u16r(&mut rng)) << 16,u16r(&mut rng),u16r(&mut rng),&message).unwrap();
            assert_eq!(V3Control::parse(&c.to_bytes().unwrap()), Ok(c.clone()));
            assert_eq!(c.message().unwrap().to_bytes().unwrap(), body);
            let cookie = match rng.index(4) {
                0 => rng.bytes(10),
                n => vec![rng.next() as u8; [0, 4, 8][n - 1]],
            };
            macro_rules! data {
                ($len:expr) => {{
                    let d = V3Data::<$len> {
                        session: u32::from(u16r(&mut rng)),
                        cookie,
                        payload: body,
                    };
                    contract::check_wire_value(&d);
                }};
            }
            match cookie.len() {
                4 => data!(4),
                8 => data!(8),
                _ => data!(0),
            }
        }
        assert!(written > 1500, "only {written} messages written");
    }

    /// What the fuzz target checks: whatever reads, writes and reads back
    /// the same.
    fn check(data: &[u8]) {
        contract::check_wire::<Packet>(data);
        contract::check_wire::<V2Packet>(data);
        contract::check_wire::<V3Control>(data);
        contract::check_wire::<V3Data<4>>(data);
        contract::check_wire::<V3Data<8>>(data);
        contract::check_wire::<ControlMessage>(data);
        contract::check_wire::<Avp>(data);
        if let Ok(m) = ControlMessage::parse(data) {
            let body = m.to_bytes().unwrap();
            if !body.is_empty() {
                let long = body.repeat(MAX_MESSAGE / body.len() + 1);
                let c = V3Control { connection: 1, ns: 0, nr: 0, payload: long };
                assert_eq!(c.to_bytes(), Err(Error::Unwritable));
            }
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x5eed_1701);
        let mut parsed = 0;
        let mut messages = 0;
        for i in 0..20_000 {
            let len = rng.index(64);
            let mut data = vec![0; len];
            rng.fill(&mut data);
            // Often make a plausible header, so many buffers get past the
            // first checks.
            if data.len() >= 2 && rng.index(4) != 0 {
                data[0] = [0xc8, 0x00, 0x4b, 0x02][rng.index(4)];
                data[1] = [2, 3][rng.index(2)];
                if data.len() >= 4 && rng.coin() {
                    data[2] = 0;
                    data[3] = data.len() as u8;
                }
            }
            // Sometimes a real message with a byte changed.
            if i % 5 == 0 {
                data = if i % 2 == 0 { sccrq() } else { sccrq_v3() };
                mutate(&mut rng, &mut data);
            }
            check(&data);
            if Packet::parse(&data).is_ok() {
                parsed += 1;
            }
            if let Ok(Packet::V2(p)) = Packet::parse(&data)
                && p.message().is_ok()
            {
                messages += 1;
            }
            // The datagram a byte at a time: every prefix reads or fails
            // without a panic, and the first two bytes decide nothing.
            for n in 0..data.len() {
                check(&data[..n]);
                if n < 2 {
                    assert_eq!(Packet::parse(&data[..n]), Err(Error::Truncated));
                }
            }
        }
        assert!(parsed > 1000, "only {parsed} parsed");
        assert!(messages > 100, "only {messages} messages");
    }
}
