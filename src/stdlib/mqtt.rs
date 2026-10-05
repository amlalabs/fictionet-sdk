//! MQTT 3.1.1: reading and writing control packets, with no I/O.
//!
//! MQTT is the publish and subscribe protocol much of the Internet of
//! Things speaks: sensors, gateways and dashboards connect to a broker,
//! publish messages under topic names such as `plant/tank1/level`, and
//! subscribe to topic filters such as `plant/+/level`. Each message is one
//! control packet on a TCP connection, usually on port 1883. A packet is a
//! fixed header (the packet type, four flag bits, and the length of the
//! rest as a variable-length integer), then fields that depend on the
//! type. This module follows the OASIS MQTT Version 3.1.1 standard
//! (Plus Errata 01).
//!
//! Nothing here reads a socket. A world that plays a broker feeds the bytes
//! it reads from a TCP connection to a [`Decoder`], gets [`Packet`]s back,
//! and writes the bytes of its replies, from [`Packet::to_bytes`], back to
//! the connection. Which clients may connect, which topics exist, and who
//! receives what is up to world code. [`topic_matches`] says whether a
//! subscription's filter matches a topic name, as the standard defines it.
//!
//! Every reader checks lengths, flags and strings, because the agent can
//! send any bytes it likes. A packet that breaks the standard is an
//! [`Error`]. The standard says a broker closes the connection then, except
//! for a CONNECT with a protocol level it does not speak
//! ([`Error::UnsupportedVersion`]), which it first answers with a CONNACK
//! that carries [`ConnectReturnCode::UnacceptableProtocolVersion`]. MQTT 5
//! (protocol level 5) is not read here, and is that case.
//!
//! ```
//! use fictionet::stdlib::mqtt::{topic_matches, ConnAck, ConnectReturnCode, Decoder, Packet, QoS, SubAck, SubAckCode};
//!
//! let mut decoder = Decoder::new();
//! // CONNECT: protocol "MQTT" level 4, clean session, keep alive 60 s, client "a".
//! decoder.feed(&[0x10, 0x0d, 0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 60, 0, 1, b'a']);
//! // SUBSCRIBE, packet 1: the filter "a/#" at QoS 1.
//! decoder.feed(&[0x82, 0x08, 0, 1, 0, 3, b'a', b'/', b'#', 1]);
//!
//! let Some(Ok(Packet::Connect(connect))) = decoder.next_packet() else { panic!("not a CONNECT") };
//! assert_eq!(connect.client_id, "a");
//! assert_eq!(connect.keep_alive, 60);
//! let reply = Packet::ConnAck(ConnAck { session_present: false, code: ConnectReturnCode::Accepted });
//! assert_eq!(reply.to_bytes().unwrap(), [0x20, 0x02, 0, 0]);
//!
//! let Some(Ok(Packet::Subscribe(subscribe))) = decoder.next_packet() else { panic!("not a SUBSCRIBE") };
//! assert_eq!(subscribe.filters, [("a/#".to_string(), QoS::AtLeastOnce)]);
//! let granted = subscribe.filters.iter().map(|(_, qos)| SubAckCode::Granted(*qos)).collect();
//! let reply = Packet::SubAck(SubAck { packet_id: subscribe.packet_id, codes: granted });
//! assert_eq!(reply.to_bytes().unwrap(), [0x90, 0x03, 0, 1, 1]);
//! assert!(decoder.next_packet().is_none());
//!
//! // A message published to "a/b/c" goes to this subscriber.
//! assert!(topic_matches("a/#", "a/b/c"));
//! // Wildcards at the start never match topics that begin with '$'.
//! assert!(!topic_matches("#", "$SYS/broker/uptime"));
//! ```

/// The TCP port MQTT brokers listen on, without TLS.
pub const PORT: u16 = 1883;
/// The protocol name a 3.1.1 CONNECT carries.
pub const PROTOCOL_NAME: &str = "MQTT";
/// The protocol name MQTT 3.1 used. A CONNECT with it is answered as an
/// unsupported version.
pub const PROTOCOL_NAME_V31: &str = "MQIsdp";
/// The protocol level of MQTT 3.1.1, the only one this module reads.
pub const PROTOCOL_LEVEL: u8 = 4;
/// The largest remaining length: what four bytes of the variable-length
/// integer can hold.
pub const MAX_REMAINING_LENGTH: usize = 268_435_455;
/// The most bytes the remaining length takes.
pub const MAX_REMAINING_LENGTH_BYTES: usize = 4;
/// The longest packet: the first byte, four length bytes, and the largest
/// remaining length.
pub const MAX_PACKET: usize = 1 + MAX_REMAINING_LENGTH_BYTES + MAX_REMAINING_LENGTH;
/// The longest packet a [`Decoder`] takes unless told otherwise: 1 MiB.
pub const DEFAULT_MAX_PACKET: usize = 1 << 20;
/// The longest UTF-8 string or binary field, in bytes: its length is a
/// 16-bit number.
pub const MAX_STRING: usize = 65_535;

/// Packet type numbers: the high four bits of a packet's first byte.
pub mod packet_type {
    /// A client asks to connect.
    pub const CONNECT: u8 = 1;
    /// The broker answers a CONNECT.
    pub const CONNACK: u8 = 2;
    /// A message, in either direction.
    pub const PUBLISH: u8 = 3;
    /// Acknowledges a QoS 1 PUBLISH.
    pub const PUBACK: u8 = 4;
    /// The first answer to a QoS 2 PUBLISH.
    pub const PUBREC: u8 = 5;
    /// Answers a PUBREC.
    pub const PUBREL: u8 = 6;
    /// Answers a PUBREL, which ends a QoS 2 exchange.
    pub const PUBCOMP: u8 = 7;
    /// A client asks for messages on topic filters.
    pub const SUBSCRIBE: u8 = 8;
    /// The broker answers a SUBSCRIBE.
    pub const SUBACK: u8 = 9;
    /// A client stops receiving messages on topic filters.
    pub const UNSUBSCRIBE: u8 = 10;
    /// The broker answers an UNSUBSCRIBE.
    pub const UNSUBACK: u8 = 11;
    /// A client checks the connection is alive.
    pub const PINGREQ: u8 = 12;
    /// The broker answers a PINGREQ.
    pub const PINGRESP: u8 = 13;
    /// A client says it is closing the connection.
    pub const DISCONNECT: u8 = 14;
}

/// A quality of service level: how hard the sender tries to deliver a
/// message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QoS {
    /// Level 0: sent once, never acknowledged.
    AtMostOnce,
    /// Level 1: sent until a PUBACK comes, so it may arrive twice.
    AtLeastOnce,
    /// Level 2: delivered once, through PUBREC, PUBREL and PUBCOMP.
    ExactlyOnce,
}

impl QoS {
    /// The level's number, 0 to 2.
    pub fn level(self) -> u8 {
        match self {
            QoS::AtMostOnce => 0,
            QoS::AtLeastOnce => 1,
            QoS::ExactlyOnce => 2,
        }
    }

    /// The level numbered `n`, or `None` for 3 and above.
    pub fn from_level(n: u8) -> Option<QoS> {
        match n {
            0 => Some(QoS::AtMostOnce),
            1 => Some(QoS::AtLeastOnce),
            2 => Some(QoS::ExactlyOnce),
            _ => None,
        }
    }
}

/// The message a broker publishes for a client whose connection ends
/// without a DISCONNECT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Will {
    /// The topic name it is published to. It has no wildcards.
    pub topic: String,
    /// The message itself, at most [`MAX_STRING`] bytes.
    pub message: Vec<u8>,
    /// The QoS it is published at.
    pub qos: QoS,
    /// Whether the broker keeps it as the topic's retained message.
    pub retain: bool,
}

/// A CONNECT packet: the first packet a client sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connect {
    /// Whether the broker drops any session it holds for this client and
    /// starts a new one, ended when the connection ends.
    pub clean_session: bool,
    /// The longest time, in seconds, the client may stay silent. 0 turns
    /// the check off.
    pub keep_alive: u16,
    /// The client identifier. It may be empty. The standard says a broker
    /// answers an empty identifier without `clean_session` with
    /// [`ConnectReturnCode::IdentifierRejected`]; that choice is left to
    /// the world, so the reader accepts it.
    pub client_id: String,
    /// The will message, if the client set one.
    pub will: Option<Will>,
    /// The user name, if the client sent one.
    pub username: Option<String>,
    /// The password, if the client sent one. A password needs a user name.
    pub password: Option<Vec<u8>>,
}

/// How a broker answers a CONNECT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectReturnCode {
    /// 0: the connection is accepted.
    Accepted,
    /// 1: the broker does not speak the protocol level the client asked for.
    UnacceptableProtocolVersion,
    /// 2: the client identifier is not allowed.
    IdentifierRejected,
    /// 3: the MQTT service is not available.
    ServerUnavailable,
    /// 4: the user name or password is malformed.
    BadUsernameOrPassword,
    /// 5: the client may not connect.
    NotAuthorized,
}

impl ConnectReturnCode {
    /// The code's number.
    pub fn code(self) -> u8 {
        match self {
            ConnectReturnCode::Accepted => 0,
            ConnectReturnCode::UnacceptableProtocolVersion => 1,
            ConnectReturnCode::IdentifierRejected => 2,
            ConnectReturnCode::ServerUnavailable => 3,
            ConnectReturnCode::BadUsernameOrPassword => 4,
            ConnectReturnCode::NotAuthorized => 5,
        }
    }

    /// The code numbered `c`, or `None` for the reserved numbers, 6 to 255.
    pub fn from_code(c: u8) -> Option<ConnectReturnCode> {
        Some(match c {
            0 => ConnectReturnCode::Accepted,
            1 => ConnectReturnCode::UnacceptableProtocolVersion,
            2 => ConnectReturnCode::IdentifierRejected,
            3 => ConnectReturnCode::ServerUnavailable,
            4 => ConnectReturnCode::BadUsernameOrPassword,
            5 => ConnectReturnCode::NotAuthorized,
            _ => return None,
        })
    }
}

/// A CONNACK packet: the broker's answer to a CONNECT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnAck {
    /// Whether the broker still holds a session for this client. The
    /// standard allows it only when the connection is accepted, so a writer
    /// writes it as false for any other code.
    pub session_present: bool,
    /// Whether the connection is accepted, and why not.
    pub code: ConnectReturnCode,
}

/// A PUBLISH packet: a message, from a client to the broker or from the
/// broker to a subscriber.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publish {
    /// Whether this is a resend of a message sent before. Only QoS 1 and 2
    /// messages may set it.
    pub dup: bool,
    /// The QoS it is sent at.
    pub qos: QoS,
    /// Whether the broker keeps it as the topic's retained message.
    pub retain: bool,
    /// The topic name. It is not empty and has no wildcards.
    pub topic: String,
    /// The packet identifier: `Some` and not 0 for QoS 1 and 2, and `None`
    /// for QoS 0.
    pub packet_id: Option<u16>,
    /// The message itself. It may be empty.
    pub payload: Vec<u8>,
}

/// A SUBSCRIBE packet: a client asks for the messages on some topic
/// filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscribe {
    /// The packet identifier, not 0. The SUBACK carries it back.
    pub packet_id: u16,
    /// Each topic filter, with the highest QoS the client wants messages on
    /// it sent at. There is at least one.
    pub filters: Vec<(String, QoS)>,
}

/// What a broker granted for one topic filter of a SUBSCRIBE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubAckCode {
    /// The subscription is made, and messages on it are sent at most at
    /// this QoS.
    Granted(QoS),
    /// The subscription is refused (code 0x80).
    Failure,
}

impl SubAckCode {
    /// The code's byte.
    pub fn code(self) -> u8 {
        match self {
            SubAckCode::Granted(qos) => qos.level(),
            SubAckCode::Failure => 0x80,
        }
    }

    /// The code for byte `c`, or `None` for a reserved byte.
    pub fn from_code(c: u8) -> Option<SubAckCode> {
        match c {
            0x80 => Some(SubAckCode::Failure),
            c => QoS::from_level(c).map(SubAckCode::Granted),
        }
    }
}

/// A SUBACK packet: the broker's answer to a SUBSCRIBE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubAck {
    /// The packet identifier of the SUBSCRIBE it answers, not 0.
    pub packet_id: u16,
    /// One code for each topic filter, in the SUBSCRIBE's order. As a
    /// SUBSCRIBE has at least one filter, there is at least one code.
    pub codes: Vec<SubAckCode>,
}

/// An UNSUBSCRIBE packet: a client stops receiving messages on some topic
/// filters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsubscribe {
    /// The packet identifier, not 0. The UNSUBACK carries it back.
    pub packet_id: u16,
    /// The topic filters, as the client subscribed to them. There is at
    /// least one.
    pub filters: Vec<String>,
}

/// One MQTT control packet. The variants that carry a `u16` carry only a
/// packet identifier, which is never 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// A client asks to connect.
    Connect(Connect),
    /// The broker answers a CONNECT.
    ConnAck(ConnAck),
    /// A message.
    Publish(Publish),
    /// Acknowledges the QoS 1 PUBLISH with this packet identifier.
    PubAck(u16),
    /// Answers the QoS 2 PUBLISH with this packet identifier.
    PubRec(u16),
    /// Answers the PUBREC with this packet identifier.
    PubRel(u16),
    /// Answers the PUBREL with this packet identifier.
    PubComp(u16),
    /// A client asks for messages on topic filters.
    Subscribe(Subscribe),
    /// The broker answers a SUBSCRIBE.
    SubAck(SubAck),
    /// A client stops receiving messages on topic filters.
    Unsubscribe(Unsubscribe),
    /// Answers the UNSUBSCRIBE with this packet identifier.
    UnsubAck(u16),
    /// A client checks the connection is alive.
    PingReq,
    /// The broker answers a PINGREQ.
    PingResp,
    /// A client says it is closing the connection.
    Disconnect,
}

/// Why bytes are not an MQTT 3.1.1 packet, or why a packet cannot be
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The packet type was 0 or 15, which are reserved.
    ReservedType(u8),
    /// The four flag bits were wrong for the packet type: not the fixed
    /// value the type requires, or, for PUBLISH, QoS 3 or DUP at QoS 0.
    Flags {
        /// The packet type.
        packet_type: u8,
        /// The four flag bits.
        flags: u8,
    },
    /// The remaining length ran past four bytes.
    RemainingLength,
    /// The packet is longer than the reader or writer allows.
    TooLarge {
        /// The packet's length in bytes: the whole packet for a reader, the
        /// remaining length for a writer.
        size: usize,
        /// The most allowed.
        max: usize,
    },
    /// A field ran past the end of the packet.
    Truncated,
    /// Bytes were left after the packet's last field.
    TrailingBytes,
    /// A string was not well-formed UTF-8.
    Utf8,
    /// A string held the character U+0000, which MQTT forbids.
    NullChar,
    /// A string or binary field to write was longer than [`MAX_STRING`]
    /// bytes. It holds the length.
    TooLong(usize),
    /// A CONNECT named a protocol other than MQTT.
    ProtocolName,
    /// A CONNECT asked for a protocol level other than 4, such as 3 (MQTT
    /// 3.1) or 5 (MQTT 5), or named MQTT 3.1's protocol, `MQIsdp`, at any
    /// level. It holds the level. A broker answers it with
    /// [`ConnectReturnCode::UnacceptableProtocolVersion`].
    UnsupportedVersion(u8),
    /// A CONNECT's flags byte broke a rule: the reserved bit set, will QoS
    /// or retain without a will, will QoS 3, or a password without a user
    /// name.
    ConnectFlags(u8),
    /// A CONNACK's flags byte had reserved bits set, or said a session is
    /// present on a refused connection.
    ConnAckFlags(u8),
    /// A CONNACK or SUBACK return code was reserved.
    ReturnCode(u8),
    /// A packet identifier was 0.
    PacketIdZero,
    /// A PUBLISH to write had a packet identifier at QoS 0, or none at QoS
    /// 1 or 2.
    PacketId,
    /// A topic name was empty or had a wildcard.
    TopicName,
    /// A topic filter was empty, or used a wildcard in a way the standard
    /// does not allow.
    TopicFilter,
    /// A SUBSCRIBE or UNSUBSCRIBE carried no topic filters, or a SUBACK no
    /// return codes.
    EmptySubscription,
    /// A SUBSCRIBE's requested QoS byte had reserved bits set, or asked for
    /// QoS 3.
    SubscribeOptions(u8),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ReservedType(t) => write!(f, "reserved packet type {t}"),
            Error::Flags { packet_type, flags } => {
                write!(f, "flags {flags:#06b} not allowed on packet type {packet_type}")
            }
            Error::RemainingLength => f.write_str("remaining length longer than four bytes"),
            Error::TooLarge { size, max } => write!(f, "packet of {size} bytes, over the limit of {max}"),
            Error::Truncated => f.write_str("a field runs past the end of the packet"),
            Error::TrailingBytes => f.write_str("bytes left after the packet's last field"),
            Error::Utf8 => f.write_str("string is not well-formed UTF-8"),
            Error::NullChar => f.write_str("string holds U+0000"),
            Error::TooLong(n) => write!(f, "field of {n} bytes, over the limit of {MAX_STRING}"),
            Error::ProtocolName => f.write_str("protocol name is not MQTT"),
            Error::UnsupportedVersion(v) => {
                write!(f, "protocol version not supported (level {v}); only MQTT 3.1.1, level 4 named MQTT, is read")
            }
            Error::ConnectFlags(b) => write!(f, "CONNECT flags {b:#010b} break the rules"),
            Error::ConnAckFlags(b) => write!(f, "CONNACK flags {b:#010b} break the rules"),
            Error::ReturnCode(c) => write!(f, "reserved return code {c:#04x}"),
            Error::PacketIdZero => f.write_str("packet identifier 0"),
            Error::PacketId => f.write_str("packet identifier does not fit the QoS"),
            Error::TopicName => f.write_str("topic name is empty or has a wildcard"),
            Error::TopicFilter => f.write_str("topic filter is empty or misuses a wildcard"),
            Error::EmptySubscription => f.write_str("no topic filters or return codes"),
            Error::SubscribeOptions(b) => write!(f, "requested QoS byte {b:#04x} is not 0, 1 or 2"),
        }
    }
}

impl std::error::Error for Error {}

/// Reads the remaining length at the start of `b`. It returns `Ok(None)` if
/// `b` holds only part of it, and otherwise the length and how many bytes
/// it took. An encoding longer than it needs to be is read, as the 3.1.1
/// standard does not forbid it.
pub fn read_remaining_length(b: &[u8]) -> Result<Option<(usize, usize)>, Error> {
    let mut value = 0usize;
    for (i, &byte) in b.iter().enumerate().take(MAX_REMAINING_LENGTH_BYTES) {
        value |= usize::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(Some((value, i + 1)));
        }
    }
    if b.len() >= MAX_REMAINING_LENGTH_BYTES { Err(Error::RemainingLength) } else { Ok(None) }
}

/// Appends `n` as a remaining length, in as few bytes as it fits. A length
/// over [`MAX_REMAINING_LENGTH`] is an error, and nothing is written.
pub fn write_remaining_length(n: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    if n > MAX_REMAINING_LENGTH {
        return Err(Error::TooLarge { size: n, max: MAX_REMAINING_LENGTH });
    }
    let mut n = n;
    loop {
        let byte = (n % 128) as u8;
        n /= 128;
        if n == 0 {
            out.push(byte);
            return Ok(());
        }
        out.push(byte | 0x80);
    }
}

/// Checks a UTF-8 string field's rules: at most [`MAX_STRING`] bytes, and
/// no U+0000. A Rust string is always well-formed UTF-8.
pub fn check_string(s: &str) -> Result<(), Error> {
    if s.len() > MAX_STRING {
        return Err(Error::TooLong(s.len()));
    }
    if s.contains('\0') {
        return Err(Error::NullChar);
    }
    Ok(())
}

/// Checks a topic name, as PUBLISH and a will carry it: a valid string, at
/// least one character long, with no `+` or `#`.
pub fn check_topic_name(topic: &str) -> Result<(), Error> {
    check_string(topic)?;
    if topic.is_empty() || topic.contains(['+', '#']) {
        return Err(Error::TopicName);
    }
    Ok(())
}

/// Checks a topic filter, as SUBSCRIBE and UNSUBSCRIBE carry it: a valid
/// string, at least one character long, where `+` fills a whole level and
/// `#` fills the last level.
pub fn check_topic_filter(filter: &str) -> Result<(), Error> {
    check_string(filter)?;
    if filter.is_empty() {
        return Err(Error::TopicFilter);
    }
    let mut levels = filter.split('/').peekable();
    while let Some(level) = levels.next() {
        let ok = match level {
            "#" => levels.peek().is_none(),
            "+" => true,
            other => !other.contains(['+', '#']),
        };
        if !ok {
            return Err(Error::TopicFilter);
        }
    }
    Ok(())
}

/// Whether a message published to `topic` goes to a subscription on
/// `filter`, by section 4.7 of the standard. `+` matches exactly one
/// level, which may be empty. `#` matches the level it stands in for and
/// every level below, and also its parent: `a/#` matches `a`. A filter
/// that starts with a wildcard does not match a topic that starts with
/// `$`, such as `$SYS/broker/uptime`. An invalid filter or topic name
/// matches nothing.
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    if check_topic_filter(filter).is_err() || check_topic_name(topic).is_err() {
        return false;
    }
    if topic.starts_with('$') && filter.starts_with(['+', '#']) {
        return false;
    }
    let mut topic_levels = topic.split('/');
    for f in filter.split('/') {
        if f == "#" {
            return true;
        }
        let Some(t) = topic_levels.next() else { return false };
        if f != "+" && f != t {
            return false;
        }
    }
    topic_levels.next().is_none()
}

/// The checks on a packet's first byte: a type that is not reserved, and
/// the flags that type allows.
fn check_first_byte(byte: u8) -> Result<(), Error> {
    let (t, flags) = (byte >> 4, byte & 0x0f);
    let ok = match t {
        0 | 15 => return Err(Error::ReservedType(t)),
        packet_type::PUBLISH => {
            let qos = (flags >> 1) & 3;
            qos != 3 && !(qos == 0 && flags & 0x08 != 0)
        }
        packet_type::PUBREL | packet_type::SUBSCRIBE | packet_type::UNSUBSCRIBE => flags == 0x02,
        _ => flags == 0,
    };
    if ok { Ok(()) } else { Err(Error::Flags { packet_type: t, flags }) }
}

/// Finds the packet at the start of `b`: its first byte and where its body
/// is. It returns `Ok(None)` if `b` holds only part of it, and an error as
/// soon as the bytes so far show one.
fn frame(b: &[u8], max: usize) -> Result<Option<(u8, std::ops::Range<usize>)>, Error> {
    let Some(&first) = b.first() else { return Ok(None) };
    check_first_byte(first)?;
    let Some((length, used)) = read_remaining_length(&b[1..])? else { return Ok(None) };
    let start = 1 + used;
    // At most 5 + 268,435,455, so this cannot overflow.
    let end = start + length;
    if end > max {
        return Err(Error::TooLarge { size: end, max });
    }
    if b.len() < end {
        return Ok(None);
    }
    Ok(Some((first, start..end)))
}

/// Reads a packet's fields in order, failing on any that runs past the end.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.b.len() < n {
            return Err(Error::Truncated);
        }
        let (head, tail) = self.b.split_at(n);
        self.b = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        let [b] = self.take(1)? else { return Err(Error::Truncated) };
        Ok(*b)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let [a, b] = self.take(2)? else { return Err(Error::Truncated) };
        Ok(u16::from_be_bytes([*a, *b]))
    }

    fn packet_id(&mut self) -> Result<u16, Error> {
        match self.u16()? {
            0 => Err(Error::PacketIdZero),
            id => Ok(id),
        }
    }

    fn binary(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    fn string(&mut self) -> Result<String, Error> {
        let s = std::str::from_utf8(self.binary()?).map_err(|_| Error::Utf8)?;
        check_string(s)?;
        Ok(s.to_owned())
    }

    fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.b)
    }

    fn is_empty(&self) -> bool {
        self.b.is_empty()
    }

    fn end(&self) -> Result<(), Error> {
        if self.b.is_empty() { Ok(()) } else { Err(Error::TrailingBytes) }
    }
}

fn put_u16(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_be_bytes());
}

fn put_binary(out: &mut Vec<u8>, b: &[u8]) -> Result<(), Error> {
    let n = u16::try_from(b.len()).map_err(|_| Error::TooLong(b.len()))?;
    put_u16(out, n);
    out.extend_from_slice(b);
    Ok(())
}

fn put_string(out: &mut Vec<u8>, s: &str) -> Result<(), Error> {
    check_string(s)?;
    put_binary(out, s.as_bytes())
}

fn put_packet_id(out: &mut Vec<u8>, id: u16) -> Result<(), Error> {
    if id == 0 {
        return Err(Error::PacketIdZero);
    }
    put_u16(out, id);
    Ok(())
}

impl Packet {
    /// Reads the packet at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the packet and how many bytes
    /// of `b` it took. A bad first byte or remaining length is an error as
    /// soon as it arrives, before the rest of the packet.
    pub fn parse(b: &[u8]) -> Result<Option<(Packet, usize)>, Error> {
        let Some((first, body)) = frame(b, MAX_PACKET)? else { return Ok(None) };
        let end = body.end;
        Ok(Some((parse_body(first, &b[body])?, end)))
    }

    /// The packet's type number, from [`packet_type`].
    pub fn packet_type(&self) -> u8 {
        use packet_type::*;
        match self {
            Packet::Connect(_) => CONNECT,
            Packet::ConnAck(_) => CONNACK,
            Packet::Publish(_) => PUBLISH,
            Packet::PubAck(_) => PUBACK,
            Packet::PubRec(_) => PUBREC,
            Packet::PubRel(_) => PUBREL,
            Packet::PubComp(_) => PUBCOMP,
            Packet::Subscribe(_) => SUBSCRIBE,
            Packet::SubAck(_) => SUBACK,
            Packet::Unsubscribe(_) => UNSUBSCRIBE,
            Packet::UnsubAck(_) => UNSUBACK,
            Packet::PingReq => PINGREQ,
            Packet::PingResp => PINGRESP,
            Packet::Disconnect => DISCONNECT,
        }
    }

    /// The packet's bytes. Whatever this returns, [`Packet::parse`] reads
    /// back as the same packet, with one exception: a [`ConnAck`] that
    /// refuses the connection is written with no session present. A packet
    /// that breaks a rule the reader checks, such as a topic name with a
    /// wildcard, a packet identifier of 0, or a field or packet over its
    /// size limit, is an error instead. A [`Decoder`] with a smaller limit
    /// than [`MAX_PACKET`] may still refuse a large packet.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut body = Vec::new();
        let mut flags = 0u8;
        match self {
            Packet::Connect(c) => {
                let mut connect_flags = 0u8;
                if c.clean_session {
                    connect_flags |= 0x02;
                }
                if let Some(w) = &c.will {
                    connect_flags |= 0x04 | (w.qos.level() << 3);
                    if w.retain {
                        connect_flags |= 0x20;
                    }
                }
                if c.username.is_some() {
                    connect_flags |= 0x80;
                }
                if c.password.is_some() {
                    connect_flags |= 0x40;
                    if c.username.is_none() {
                        return Err(Error::ConnectFlags(connect_flags));
                    }
                }
                put_string(&mut body, PROTOCOL_NAME)?;
                body.push(PROTOCOL_LEVEL);
                body.push(connect_flags);
                put_u16(&mut body, c.keep_alive);
                put_string(&mut body, &c.client_id)?;
                if let Some(w) = &c.will {
                    check_topic_name(&w.topic)?;
                    put_string(&mut body, &w.topic)?;
                    put_binary(&mut body, &w.message)?;
                }
                if let Some(u) = &c.username {
                    put_string(&mut body, u)?;
                }
                if let Some(p) = &c.password {
                    put_binary(&mut body, p)?;
                }
            }
            Packet::ConnAck(a) => {
                let present = a.session_present && a.code == ConnectReturnCode::Accepted;
                body.push(u8::from(present));
                body.push(a.code.code());
            }
            Packet::Publish(p) => {
                flags = (u8::from(p.dup) << 3) | (p.qos.level() << 1) | u8::from(p.retain);
                if p.dup && p.qos == QoS::AtMostOnce {
                    return Err(Error::Flags { packet_type: packet_type::PUBLISH, flags });
                }
                check_topic_name(&p.topic)?;
                put_string(&mut body, &p.topic)?;
                match (p.qos, p.packet_id) {
                    (QoS::AtMostOnce, None) => {}
                    (QoS::AtLeastOnce | QoS::ExactlyOnce, Some(id)) => put_packet_id(&mut body, id)?,
                    _ => return Err(Error::PacketId),
                }
                body.extend_from_slice(&p.payload);
            }
            Packet::PubAck(id) | Packet::PubRec(id) | Packet::PubComp(id) | Packet::UnsubAck(id) => {
                put_packet_id(&mut body, *id)?;
            }
            Packet::PubRel(id) => {
                flags = 0x02;
                put_packet_id(&mut body, *id)?;
            }
            Packet::Subscribe(s) => {
                flags = 0x02;
                put_packet_id(&mut body, s.packet_id)?;
                if s.filters.is_empty() {
                    return Err(Error::EmptySubscription);
                }
                for (filter, qos) in &s.filters {
                    check_topic_filter(filter)?;
                    put_string(&mut body, filter)?;
                    body.push(qos.level());
                }
            }
            Packet::SubAck(s) => {
                put_packet_id(&mut body, s.packet_id)?;
                if s.codes.is_empty() {
                    return Err(Error::EmptySubscription);
                }
                body.extend(s.codes.iter().map(|c| c.code()));
            }
            Packet::Unsubscribe(u) => {
                flags = 0x02;
                put_packet_id(&mut body, u.packet_id)?;
                if u.filters.is_empty() {
                    return Err(Error::EmptySubscription);
                }
                for filter in &u.filters {
                    check_topic_filter(filter)?;
                    put_string(&mut body, filter)?;
                }
            }
            Packet::PingReq | Packet::PingResp | Packet::Disconnect => {}
        }
        let mut out = Vec::with_capacity(1 + MAX_REMAINING_LENGTH_BYTES + body.len());
        out.push((self.packet_type() << 4) | flags);
        write_remaining_length(body.len(), &mut out)?;
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Reads a packet's body, given its first byte, which [`frame`] checked.
fn parse_body(first: u8, body: &[u8]) -> Result<Packet, Error> {
    let mut r = Reader { b: body };
    let flags = first & 0x0f;
    let packet = match first >> 4 {
        packet_type::CONNECT => Packet::Connect(parse_connect(&mut r)?),
        packet_type::CONNACK => {
            let ack_flags = r.u8()?;
            let raw = r.u8()?;
            let code = ConnectReturnCode::from_code(raw).ok_or(Error::ReturnCode(raw))?;
            if ack_flags & 0xfe != 0 || (ack_flags & 1 != 0 && code != ConnectReturnCode::Accepted) {
                return Err(Error::ConnAckFlags(ack_flags));
            }
            Packet::ConnAck(ConnAck { session_present: ack_flags & 1 != 0, code })
        }
        packet_type::PUBLISH => {
            // The first byte's check has ruled out QoS 3.
            let qos =
                QoS::from_level((flags >> 1) & 3).ok_or(Error::Flags { packet_type: packet_type::PUBLISH, flags })?;
            let topic = r.string()?;
            check_topic_name(&topic)?;
            let packet_id = if qos == QoS::AtMostOnce { None } else { Some(r.packet_id()?) };
            Packet::Publish(Publish {
                dup: flags & 0x08 != 0,
                qos,
                retain: flags & 0x01 != 0,
                topic,
                packet_id,
                payload: r.rest().to_vec(),
            })
        }
        packet_type::PUBACK => Packet::PubAck(r.packet_id()?),
        packet_type::PUBREC => Packet::PubRec(r.packet_id()?),
        packet_type::PUBREL => Packet::PubRel(r.packet_id()?),
        packet_type::PUBCOMP => Packet::PubComp(r.packet_id()?),
        packet_type::UNSUBACK => Packet::UnsubAck(r.packet_id()?),
        packet_type::SUBSCRIBE => {
            let packet_id = r.packet_id()?;
            let mut filters = Vec::new();
            while !r.is_empty() {
                let filter = r.string()?;
                check_topic_filter(&filter)?;
                let options = r.u8()?;
                let qos = match QoS::from_level(options) {
                    Some(q) => q,
                    None => return Err(Error::SubscribeOptions(options)),
                };
                filters.push((filter, qos));
            }
            if filters.is_empty() {
                return Err(Error::EmptySubscription);
            }
            Packet::Subscribe(Subscribe { packet_id, filters })
        }
        packet_type::SUBACK => {
            let packet_id = r.packet_id()?;
            let codes = r
                .rest()
                .iter()
                .map(|&c| SubAckCode::from_code(c).ok_or(Error::ReturnCode(c)))
                .collect::<Result<Vec<_>, _>>()?;
            if codes.is_empty() {
                return Err(Error::EmptySubscription);
            }
            Packet::SubAck(SubAck { packet_id, codes })
        }
        packet_type::UNSUBSCRIBE => {
            let packet_id = r.packet_id()?;
            let mut filters = Vec::new();
            while !r.is_empty() {
                let filter = r.string()?;
                check_topic_filter(&filter)?;
                filters.push(filter);
            }
            if filters.is_empty() {
                return Err(Error::EmptySubscription);
            }
            Packet::Unsubscribe(Unsubscribe { packet_id, filters })
        }
        packet_type::PINGREQ => Packet::PingReq,
        packet_type::PINGRESP => Packet::PingResp,
        packet_type::DISCONNECT => Packet::Disconnect,
        t => return Err(Error::ReservedType(t)),
    };
    r.end()?;
    Ok(packet)
}

fn parse_connect(r: &mut Reader<'_>) -> Result<Connect, Error> {
    let name = r.string()?;
    if name != PROTOCOL_NAME && name != PROTOCOL_NAME_V31 {
        return Err(Error::ProtocolName);
    }
    let level = r.u8()?;
    if name != PROTOCOL_NAME || level != PROTOCOL_LEVEL {
        return Err(Error::UnsupportedVersion(level));
    }
    let flags = r.u8()?;
    let (has_will, will_qos, will_retain) = (flags & 0x04 != 0, (flags >> 3) & 3, flags & 0x20 != 0);
    let (has_user, has_password) = (flags & 0x80 != 0, flags & 0x40 != 0);
    let bad = flags & 0x01 != 0
        || will_qos == 3
        || (!has_will && (will_qos != 0 || will_retain))
        || (has_password && !has_user);
    if bad {
        return Err(Error::ConnectFlags(flags));
    }
    let keep_alive = r.u16()?;
    let client_id = r.string()?;
    let will = if has_will {
        let topic = r.string()?;
        check_topic_name(&topic)?;
        let message = r.binary()?.to_vec();
        let qos = QoS::from_level(will_qos).ok_or(Error::ConnectFlags(flags))?;
        Some(Will { topic, message, qos, retain: will_retain })
    } else {
        None
    };
    let username = if has_user { Some(r.string()?) } else { None };
    let password = if has_password { Some(r.binary()?.to_vec()) } else { None };
    Ok(Connect { clean_session: flags & 0x02 != 0, keep_alive, client_id, will, username, password })
}

/// Splits an MQTT byte stream into packets. Feed it the bytes a connection
/// reads, in order, and take packets out until it has none.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start in `buf`. Taken bytes are
    /// dropped in [`Decoder::feed`], once they are at least half of `buf`,
    /// so a stream of many small packets costs linear time, not quadratic.
    start: usize,
    max_packet: usize,
    failed: Option<Error>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, that takes packets up to
    /// [`DEFAULT_MAX_PACKET`] bytes long.
    pub fn new() -> Decoder {
        Decoder::with_max_packet(DEFAULT_MAX_PACKET)
    }

    /// A decoder that takes packets up to `max` bytes long, header
    /// included. `max` is clamped to between 2, the shortest packet, and
    /// [`MAX_PACKET`].
    pub fn with_max_packet(max: usize) -> Decoder {
        Decoder { buf: Vec::new(), start: 0, max_packet: max.clamp(2, MAX_PACKET), failed: None }
    }

    /// The longest packet this decoder takes.
    pub fn max_packet(&self) -> usize {
        self.max_packet
    }

    /// Adds bytes read from the connection. After an [`Error`] the stream
    /// cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        if self.start > 0 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole packet, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the stream
    /// has broken. A packet over the limit is an error as soon as its
    /// header arrives, so the bytes waiting ([`Decoder::buffered`]) never
    /// exceed one packet's worth plus what was fed since the last call.
    /// Taking packets out costs time in proportion to their bytes, however
    /// small they are.
    pub fn next_packet(&mut self) -> Option<Result<Packet, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let held = &self.buf[self.start..];
        let result = match frame(held, self.max_packet) {
            Ok(None) => return None,
            Ok(Some((first, body))) => {
                let end = body.end;
                let parsed = parse_body(first, &held[body]);
                self.start += end;
                if self.start == self.buf.len() {
                    self.buf.clear();
                    self.start = 0;
                }
                parsed
            }
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            self.failed = Some(e);
            self.buf = Vec::new();
            self.start = 0;
        }
        Some(result)
    }

    /// How many bytes are held, waiting for the rest of a packet.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_bytes() -> Vec<u8> {
        // The variable header from the standard's example in section
        // 3.1.2.10, flags 0xCE: user name, password, will QoS 1, will,
        // clean session. Keep alive 10.
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 0xce, 0, 10];
        for field in [&b"client"[..], b"dead/client", b"gone", b"user", b"pw"] {
            body.extend_from_slice(&(field.len() as u16).to_be_bytes());
            body.extend_from_slice(field);
        }
        let mut out = vec![0x10];
        write_remaining_length(body.len(), &mut out).unwrap();
        out.extend_from_slice(&body);
        out
    }

    fn connect() -> Connect {
        Connect {
            clean_session: true,
            keep_alive: 10,
            client_id: "client".into(),
            will: Some(Will {
                topic: "dead/client".into(),
                message: b"gone".to_vec(),
                qos: QoS::AtLeastOnce,
                retain: false,
            }),
            username: Some("user".into()),
            password: Some(b"pw".to_vec()),
        }
    }

    /// One packet of each type, with its bytes.
    fn samples() -> Vec<(Packet, Vec<u8>)> {
        vec![
            (Packet::Connect(connect()), connect_bytes()),
            (
                Packet::Connect(Connect {
                    clean_session: false,
                    keep_alive: 0,
                    client_id: String::new(),
                    will: Some(Will { topic: "w".into(), message: vec![], qos: QoS::ExactlyOnce, retain: true }),
                    username: Some(String::new()),
                    password: None,
                }),
                vec![0x10, 19, 0, 4, b'M', b'Q', b'T', b'T', 4, 0xb4, 0, 0, 0, 0, 0, 1, b'w', 0, 0, 0, 0],
            ),
            (
                Packet::ConnAck(ConnAck { session_present: true, code: ConnectReturnCode::Accepted }),
                vec![0x20, 2, 1, 0],
            ),
            (
                Packet::ConnAck(ConnAck { session_present: false, code: ConnectReturnCode::NotAuthorized }),
                vec![0x20, 2, 0, 5],
            ),
            (
                Packet::Publish(Publish {
                    dup: false,
                    qos: QoS::AtMostOnce,
                    retain: true,
                    topic: "a/b".into(),
                    packet_id: None,
                    payload: b"hi".to_vec(),
                }),
                vec![0x31, 7, 0, 3, b'a', b'/', b'b', b'h', b'i'],
            ),
            (
                Packet::Publish(Publish {
                    dup: true,
                    qos: QoS::ExactlyOnce,
                    retain: false,
                    topic: "a/b".into(),
                    packet_id: Some(10),
                    payload: vec![],
                }),
                vec![0x3c, 7, 0, 3, b'a', b'/', b'b', 0, 10],
            ),
            (Packet::PubAck(1), vec![0x40, 2, 0, 1]),
            (Packet::PubRec(2), vec![0x50, 2, 0, 2]),
            (Packet::PubRel(3), vec![0x62, 2, 0, 3]),
            (Packet::PubComp(0x1234), vec![0x70, 2, 0x12, 0x34]),
            (
                Packet::Subscribe(Subscribe {
                    packet_id: 7,
                    filters: vec![("a/+".into(), QoS::AtMostOnce), ("#".into(), QoS::ExactlyOnce)],
                }),
                vec![0x82, 12, 0, 7, 0, 3, b'a', b'/', b'+', 0, 0, 1, b'#', 2],
            ),
            (
                Packet::SubAck(SubAck {
                    packet_id: 7,
                    codes: vec![SubAckCode::Granted(QoS::AtMostOnce), SubAckCode::Failure],
                }),
                vec![0x90, 4, 0, 7, 0, 0x80],
            ),
            (
                Packet::Unsubscribe(Unsubscribe { packet_id: 8, filters: vec!["a/+".into()] }),
                vec![0xa2, 7, 0, 8, 0, 3, b'a', b'/', b'+'],
            ),
            (Packet::UnsubAck(8), vec![0xb0, 2, 0, 8]),
            (Packet::PingReq, vec![0xc0, 0]),
            (Packet::PingResp, vec![0xd0, 0]),
            (Packet::Disconnect, vec![0xe0, 0]),
        ]
    }

    fn parse(b: &[u8]) -> Result<Packet, Error> {
        match Packet::parse(b)? {
            Some((p, used)) => {
                assert_eq!(used, b.len());
                Ok(p)
            }
            None => panic!("incomplete: {b:?}"),
        }
    }

    #[test]
    fn every_packet_type_reads_and_writes() {
        let samples = samples();
        let mut types: Vec<u8> = samples.iter().map(|(p, _)| p.packet_type()).collect();
        types.dedup();
        assert_eq!(types, (1..=14).collect::<Vec<u8>>());
        for (packet, bytes) in samples {
            assert_eq!(parse(&bytes), Ok(packet.clone()), "{packet:?}");
            assert_eq!(packet.to_bytes().unwrap(), bytes, "{packet:?}");
        }
    }

    #[test]
    fn every_prefix_is_incomplete() {
        for (packet, bytes) in samples() {
            for n in 0..bytes.len() {
                assert_eq!(Packet::parse(&bytes[..n]), Ok(None), "{packet:?} cut to {n}");
                let mut d = Decoder::new();
                d.feed(&bytes[..n]);
                assert_eq!(d.next_packet(), None);
                assert_eq!(d.buffered(), n);
            }
        }
    }

    #[test]
    fn connect_example() {
        let Packet::Connect(c) = parse(&connect_bytes()).unwrap() else { panic!() };
        assert_eq!(c, connect());
        // Trailing bytes after the password are not allowed.
        let mut b = connect_bytes();
        b[1] += 1;
        b.push(0);
        assert_eq!(Packet::parse(&b), Err(Error::TrailingBytes));
    }

    #[test]
    fn remaining_length_examples() {
        // The table in section 2.2.3, at the edges of each size.
        let cases: [(usize, &[u8]); 8] = [
            (0, &[0x00]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (16_383, &[0xff, 0x7f]),
            (16_384, &[0x80, 0x80, 0x01]),
            (2_097_151, &[0xff, 0xff, 0x7f]),
            (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
            (268_435_455, &[0xff, 0xff, 0xff, 0x7f]),
        ];
        for (n, bytes) in cases {
            let mut out = Vec::new();
            write_remaining_length(n, &mut out).unwrap();
            assert_eq!(out, bytes);
            assert_eq!(read_remaining_length(bytes), Ok(Some((n, bytes.len()))));
            for k in 0..bytes.len() {
                assert_eq!(read_remaining_length(&bytes[..k]), Ok(None));
            }
        }
        assert_eq!(read_remaining_length(&[0xff, 0xff, 0xff, 0xff]), Err(Error::RemainingLength));
        assert_eq!(read_remaining_length(&[0x80, 0x80, 0x80, 0x80, 0x01]), Err(Error::RemainingLength));
        // A longer encoding than needed is still read.
        assert_eq!(read_remaining_length(&[0x80, 0x00]), Ok(Some((0, 2))));
        assert_eq!(Packet::parse(&[0xc0, 0x80, 0x00]), Ok(Some((Packet::PingReq, 3))));
        let mut out = Vec::new();
        assert_eq!(
            write_remaining_length(MAX_REMAINING_LENGTH + 1, &mut out),
            Err(Error::TooLarge { size: MAX_REMAINING_LENGTH + 1, max: MAX_REMAINING_LENGTH })
        );
        assert!(out.is_empty());
        assert_eq!(Packet::parse(&[0x30, 0xff, 0xff, 0xff, 0xff]), Err(Error::RemainingLength));
    }

    #[test]
    fn topic_matching_examples() {
        // Section 4.7.1.2.
        for t in ["sport/tennis/player1", "sport/tennis/player1/ranking", "sport/tennis/player1/score/wimbledon"] {
            assert!(topic_matches("sport/tennis/player1/#", t), "{t}");
        }
        assert!(topic_matches("sport/#", "sport"));
        assert!(topic_matches("#", "sport/tennis"));
        assert!(!topic_matches("sport/tennis/#", "sport/tennisplayer1"));
        // Section 4.7.1.3.
        assert!(topic_matches("sport/tennis/+", "sport/tennis/player1"));
        assert!(topic_matches("sport/tennis/+", "sport/tennis/player2"));
        assert!(!topic_matches("sport/tennis/+", "sport/tennis/player1/ranking"));
        assert!(!topic_matches("sport/+", "sport"));
        assert!(topic_matches("sport/+", "sport/"));
        assert!(topic_matches("+/+", "/finance"));
        assert!(topic_matches("/+", "/finance"));
        assert!(!topic_matches("+", "/finance"));
        assert!(topic_matches("+/tennis/#", "sport/tennis/player1"));
        // Section 4.7.2: topics that start with '$'.
        assert!(!topic_matches("#", "$SYS/monitor/Clients"));
        assert!(!topic_matches("+/monitor/Clients", "$SYS/monitor/Clients"));
        assert!(topic_matches("$SYS/#", "$SYS/monitor/Clients"));
        assert!(topic_matches("$SYS/monitor/+", "$SYS/monitor/Clients"));
        // Section 4.7.3: case, spaces and empty levels count.
        assert!(!topic_matches("ACCOUNTS", "Accounts"));
        assert!(topic_matches("Accounts payable", "Accounts payable"));
        assert!(topic_matches("a//b", "a//b"));
        assert!(!topic_matches("a/b", "a/b/"));
        // Invalid filters and topics match nothing.
        assert!(!topic_matches("sport/tennis#", "sport/tennis#"));
        assert!(!topic_matches("#", "a/+"));
        assert!(!topic_matches("", ""));
    }

    #[test]
    fn topic_validation() {
        for f in ["#", "+", "sport/#", "+/tennis/#", "sport/+/player1", "/", "a//+", "$SYS/#"] {
            assert_eq!(check_topic_filter(f), Ok(()), "{f}");
        }
        for f in ["", "sport/tennis#", "sport/tennis/#/ranking", "sport+", "#/a", "a/++", "a/#/"] {
            assert_eq!(check_topic_filter(f), Err(Error::TopicFilter), "{f}");
        }
        for t in ["a", "/", "a b/c", "$SYS"] {
            assert_eq!(check_topic_name(t), Ok(()), "{t}");
        }
        for t in ["", "a/+", "#", "a#"] {
            assert_eq!(check_topic_name(t), Err(Error::TopicName), "{t}");
        }
        assert_eq!(check_topic_name("a\0b"), Err(Error::NullChar));
        let long = "a".repeat(MAX_STRING + 1);
        assert_eq!(check_topic_name(&long), Err(Error::TooLong(MAX_STRING + 1)));
        assert_eq!(check_topic_filter(&long), Err(Error::TooLong(MAX_STRING + 1)));
        assert_eq!(check_string(&long[1..]), Ok(()));
    }

    #[test]
    fn fixed_header_errors() {
        assert_eq!(Packet::parse(&[0x00]), Err(Error::ReservedType(0)));
        assert_eq!(Packet::parse(&[0xf0, 0]), Err(Error::ReservedType(15)));
        // Fixed flags on each type that has them.
        assert_eq!(Packet::parse(&[0x11]), Err(Error::Flags { packet_type: 1, flags: 1 }));
        assert_eq!(Packet::parse(&[0x60, 2, 0, 1]), Err(Error::Flags { packet_type: 6, flags: 0 }));
        assert_eq!(Packet::parse(&[0x80]), Err(Error::Flags { packet_type: 8, flags: 0 }));
        assert_eq!(Packet::parse(&[0xa3]), Err(Error::Flags { packet_type: 10, flags: 3 }));
        assert_eq!(Packet::parse(&[0xe8, 0]), Err(Error::Flags { packet_type: 14, flags: 8 }));
        // PUBLISH: QoS 3, and DUP at QoS 0.
        assert_eq!(Packet::parse(&[0x36]), Err(Error::Flags { packet_type: 3, flags: 6 }));
        assert_eq!(Packet::parse(&[0x38]), Err(Error::Flags { packet_type: 3, flags: 8 }));
        assert!(Packet::parse(&[0x3b]).unwrap().is_none());
    }

    #[test]
    fn body_errors() {
        // Fields that run past the end.
        assert_eq!(Packet::parse(&[0x40, 1, 0]), Err(Error::Truncated));
        assert_eq!(Packet::parse(&[0x30, 2, 0, 5]), Err(Error::Truncated));
        assert_eq!(Packet::parse(&[0x20, 1, 0]), Err(Error::Truncated));
        // Bytes left over.
        assert_eq!(Packet::parse(&[0x40, 3, 0, 1, 0]), Err(Error::TrailingBytes));
        assert_eq!(Packet::parse(&[0xc0, 1, 0]), Err(Error::TrailingBytes));
        assert_eq!(Packet::parse(&[0x20, 3, 0, 0, 0]), Err(Error::TrailingBytes));
        // Strings: bad UTF-8, a surrogate, and U+0000.
        assert_eq!(Packet::parse(&[0x30, 3, 0, 1, 0xff]), Err(Error::Utf8));
        assert_eq!(Packet::parse(&[0x30, 5, 0, 3, 0xed, 0xa0, 0x80]), Err(Error::Utf8));
        assert_eq!(Packet::parse(&[0x30, 3, 0, 1, 0]), Err(Error::NullChar));
        // Topic names.
        assert_eq!(Packet::parse(&[0x30, 2, 0, 0]), Err(Error::TopicName));
        assert_eq!(Packet::parse(&[0x30, 3, 0, 1, b'#']), Err(Error::TopicName));
        // Packet identifiers of 0.
        assert_eq!(Packet::parse(&[0x32, 5, 0, 1, b'a', 0, 0]), Err(Error::PacketIdZero));
        assert_eq!(Packet::parse(&[0x40, 2, 0, 0]), Err(Error::PacketIdZero));
        assert_eq!(Packet::parse(&[0x82, 6, 0, 0, 0, 1, b'a', 0]), Err(Error::PacketIdZero));
        // CONNACK.
        assert_eq!(Packet::parse(&[0x20, 2, 0, 6]), Err(Error::ReturnCode(6)));
        assert_eq!(Packet::parse(&[0x20, 2, 2, 0]), Err(Error::ConnAckFlags(2)));
        assert_eq!(Packet::parse(&[0x20, 2, 1, 4]), Err(Error::ConnAckFlags(1)));
        // SUBSCRIBE and UNSUBSCRIBE.
        assert_eq!(Packet::parse(&[0x82, 2, 0, 1]), Err(Error::EmptySubscription));
        assert_eq!(Packet::parse(&[0xa2, 2, 0, 1]), Err(Error::EmptySubscription));
        assert_eq!(Packet::parse(&[0x82, 6, 0, 1, 0, 1, b'a', 3]), Err(Error::SubscribeOptions(3)));
        assert_eq!(Packet::parse(&[0x82, 6, 0, 1, 0, 1, b'a', 0x04]), Err(Error::SubscribeOptions(4)));
        assert_eq!(Packet::parse(&[0x82, 7, 0, 1, 0, 2, b'a', b'#', 0]), Err(Error::TopicFilter));
        assert_eq!(
            Packet::parse(&[0xa2, 5, 0, 1, 0, 1, b'+']),
            Ok(Some((Packet::Unsubscribe(Unsubscribe { packet_id: 1, filters: vec!["+".into()] }), 7)))
        );
        assert_eq!(Packet::parse(&[0xa2, 6, 0, 1, 0, 2, b'+', b'a']), Err(Error::TopicFilter));
        assert_eq!(Packet::parse(&[0x82, 5, 0, 1, 0, 1, b'a']), Err(Error::Truncated));
        // SUBACK.
        assert_eq!(Packet::parse(&[0x90, 3, 0, 1, 3]), Err(Error::ReturnCode(3)));
        // A SUBACK answers at least one filter, so it has at least one code.
        assert_eq!(Packet::parse(&[0x90, 2, 0, 1]), Err(Error::EmptySubscription));
    }

    fn connect_with(name: &[u8], level: u8, flags: u8, rest: &[u8]) -> Vec<u8> {
        let mut body = (name.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(name);
        body.extend_from_slice(&[level, flags, 0, 60]);
        body.extend_from_slice(rest);
        let mut out = vec![0x10];
        write_remaining_length(body.len(), &mut out).unwrap();
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn connect_errors() {
        let id = [0, 1, b'a'];
        assert!(parse(&connect_with(b"MQTT", 4, 0x02, &id)).is_ok());
        // MQTT 5, with its properties length, and MQTT 3.1.
        assert_eq!(Packet::parse(&connect_with(b"MQTT", 5, 0x02, &[0, 0, 1, b'a'])), Err(Error::UnsupportedVersion(5)));
        assert_eq!(Packet::parse(&connect_with(b"MQIsdp", 3, 0x02, &id)), Err(Error::UnsupportedVersion(3)));
        assert_eq!(Packet::parse(&connect_with(b"MQTT", 3, 0x02, &id)), Err(Error::UnsupportedVersion(3)));
        assert_eq!(Packet::parse(&connect_with(b"HTTP", 4, 0x02, &id)), Err(Error::ProtocolName));
        // The reserved bit.
        assert_eq!(Packet::parse(&connect_with(b"MQTT", 4, 0x03, &id)), Err(Error::ConnectFlags(0x03)));
        // Will QoS or retain without a will.
        assert_eq!(Packet::parse(&connect_with(b"MQTT", 4, 0x0a, &id)), Err(Error::ConnectFlags(0x0a)));
        assert_eq!(Packet::parse(&connect_with(b"MQTT", 4, 0x22, &id)), Err(Error::ConnectFlags(0x22)));
        // Will QoS 3.
        assert_eq!(Packet::parse(&connect_with(b"MQTT", 4, 0x1e, &id)), Err(Error::ConnectFlags(0x1e)));
        // A password without a user name.
        assert_eq!(Packet::parse(&connect_with(b"MQTT", 4, 0x42, &id)), Err(Error::ConnectFlags(0x42)));
        // A will whose topic has a wildcard.
        assert_eq!(
            Packet::parse(&connect_with(b"MQTT", 4, 0x06, &[0, 1, b'a', 0, 1, b'+', 0, 0])),
            Err(Error::TopicName)
        );
        // A user name flag with no user name.
        assert_eq!(Packet::parse(&connect_with(b"MQTT", 4, 0x82, &id)), Err(Error::Truncated));
    }

    #[test]
    fn writer_errors() {
        let publish = Publish {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: "t".into(),
            packet_id: None,
            payload: vec![],
        };
        let p = |f: &dyn Fn(&mut Publish)| {
            let mut x = publish.clone();
            f(&mut x);
            Packet::Publish(x).to_bytes()
        };
        assert!(p(&|_| {}).is_ok());
        assert_eq!(p(&|x| x.packet_id = Some(1)), Err(Error::PacketId));
        assert_eq!(p(&|x| x.qos = QoS::AtLeastOnce), Err(Error::PacketId));
        assert_eq!(
            p(&|x| {
                x.qos = QoS::AtLeastOnce;
                x.packet_id = Some(0)
            }),
            Err(Error::PacketIdZero)
        );
        assert_eq!(p(&|x| x.dup = true), Err(Error::Flags { packet_type: 3, flags: 8 }));
        assert_eq!(p(&|x| x.topic = "a/#".into()), Err(Error::TopicName));
        assert_eq!(p(&|x| x.topic = "a\0".into()), Err(Error::NullChar));
        assert_eq!(p(&|x| x.topic = "a".repeat(MAX_STRING + 1)), Err(Error::TooLong(MAX_STRING + 1)));

        let mut c = connect();
        c.username = None;
        assert_eq!(Packet::Connect(c.clone()).to_bytes(), Err(Error::ConnectFlags(0xce & !0x80)));
        c.password = None;
        c.will.as_mut().unwrap().topic = "+".into();
        assert_eq!(Packet::Connect(c.clone()).to_bytes(), Err(Error::TopicName));
        c.will = None;
        c.password = Some(vec![0; MAX_STRING + 1]);
        c.username = Some("u".into());
        assert_eq!(Packet::Connect(c).to_bytes(), Err(Error::TooLong(MAX_STRING + 1)));

        assert_eq!(Packet::PubAck(0).to_bytes(), Err(Error::PacketIdZero));
        assert_eq!(
            Packet::Subscribe(Subscribe { packet_id: 1, filters: vec![] }).to_bytes(),
            Err(Error::EmptySubscription)
        );
        assert_eq!(
            Packet::Unsubscribe(Unsubscribe { packet_id: 1, filters: vec![] }).to_bytes(),
            Err(Error::EmptySubscription)
        );
        assert_eq!(
            Packet::Subscribe(Subscribe { packet_id: 1, filters: vec![("a#".into(), QoS::AtMostOnce)] }).to_bytes(),
            Err(Error::TopicFilter)
        );
        assert_eq!(
            Packet::Unsubscribe(Unsubscribe { packet_id: 1, filters: vec![String::new()] }).to_bytes(),
            Err(Error::TopicFilter)
        );
        assert_eq!(Packet::SubAck(SubAck { packet_id: 0, codes: vec![] }).to_bytes(), Err(Error::PacketIdZero));
        assert_eq!(Packet::SubAck(SubAck { packet_id: 1, codes: vec![] }).to_bytes(), Err(Error::EmptySubscription));
    }

    #[test]
    fn connack_writer_clamps_session_present() {
        let refused =
            Packet::ConnAck(ConnAck { session_present: true, code: ConnectReturnCode::BadUsernameOrPassword });
        let bytes = refused.to_bytes().unwrap();
        assert_eq!(bytes, [0x20, 2, 0, 4]);
        assert_eq!(
            parse(&bytes),
            Ok(Packet::ConnAck(ConnAck { session_present: false, code: ConnectReturnCode::BadUsernameOrPassword }))
        );
    }

    #[test]
    fn codes_round_trip() {
        for c in 0..=255u8 {
            if let Some(code) = ConnectReturnCode::from_code(c) {
                assert_eq!(code.code(), c);
            } else {
                assert!(c > 5);
            }
            if let Some(code) = SubAckCode::from_code(c) {
                assert_eq!(code.code(), c);
            } else {
                assert!(c > 2 && c != 0x80);
            }
            if let Some(q) = QoS::from_level(c) {
                assert_eq!(q.level(), c);
            }
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let samples = samples();
        let stream: Vec<u8> = samples.iter().flat_map(|(_, b)| b.clone()).collect();
        let want: Vec<Packet> = samples.into_iter().map(|(p, _)| p).collect();
        for piece in [1, 2, 3, 7, stream.len()] {
            let mut d = Decoder::default();
            let mut got = Vec::new();
            for chunk in stream.chunks(piece) {
                d.feed(chunk);
                while let Some(p) = d.next_packet() {
                    got.push(p.unwrap());
                }
            }
            assert_eq!(got, want, "pieces of {piece}");
            assert_eq!(d.buffered(), 0);
        }
    }

    #[test]
    fn decoder_stays_broken() {
        let mut d = Decoder::new();
        d.feed(&[0xc0, 0, 0x00, 0xd0, 0]);
        assert_eq!(d.next_packet(), Some(Ok(Packet::PingReq)));
        assert_eq!(d.next_packet(), Some(Err(Error::ReservedType(0))));
        d.feed(&[0xc0, 0]);
        assert_eq!(d.next_packet(), Some(Err(Error::ReservedType(0))));
        assert_eq!(d.buffered(), 0);
        // A broken body breaks the stream too.
        let mut d = Decoder::new();
        d.feed(&[0x40, 2, 0, 0, 0xc0, 0]);
        assert_eq!(d.next_packet(), Some(Err(Error::PacketIdZero)));
        assert_eq!(d.next_packet(), Some(Err(Error::PacketIdZero)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_packets_in_linear_time() {
        // 4 MiB of PINGREQs, fed at once. Moving the rest of the buffer
        // down after each packet took about 23 s here (1.4 s for 1 MiB,
        // optimized); taking them by offset takes milliseconds. The bound
        // is loose so a slow machine still passes.
        let data = [0xc0u8, 0].repeat(1 << 21);
        let started = std::time::Instant::now();
        let mut d = Decoder::with_max_packet(MAX_PACKET);
        d.feed(&data[..data.len() - 1]);
        let mut n = 0;
        while let Some(p) = d.next_packet() {
            assert_eq!(p, Ok(Packet::PingReq));
            n += 1;
        }
        assert_eq!(n, (1 << 21) - 1);
        assert_eq!(d.buffered(), 1);
        d.feed(&[0]);
        assert_eq!(d.buffered(), 2);
        assert_eq!(d.next_packet(), Some(Ok(Packet::PingReq)));
        assert_eq!(d.buffered(), 0);
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[test]
    fn decoder_keeps_a_partial_packet_across_compaction() {
        // Whole packets, then half of one; the next feed drops the taken
        // bytes and keeps the half.
        let mut d = Decoder::new();
        d.feed(&[0xc0, 0, 0xd0, 0, 0x40, 2, 0]);
        assert_eq!(d.next_packet(), Some(Ok(Packet::PingReq)));
        assert_eq!(d.next_packet(), Some(Ok(Packet::PingResp)));
        assert_eq!(d.next_packet(), None);
        assert_eq!(d.buffered(), 3);
        d.feed(&[9, 0xe0]);
        assert_eq!(d.buffered(), 5);
        assert_eq!(d.next_packet(), Some(Ok(Packet::PubAck(9))));
        assert_eq!(d.next_packet(), None);
        d.feed(&[0]);
        assert_eq!(d.next_packet(), Some(Ok(Packet::Disconnect)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn mqisdp_at_level_4_reads_sensibly() {
        // MQTT 3.1's name with 3.1.1's level is still unsupported, and the
        // message must not say "level 4, not 4".
        let e = Packet::parse(&connect_with(b"MQIsdp", 4, 0x02, &[0, 1, b'a'])).unwrap_err();
        assert_eq!(e, Error::UnsupportedVersion(4));
        assert!(!e.to_string().contains("4, not 4"), "{e}");
    }

    #[test]
    fn decoder_limits_packet_size() {
        let mut d = Decoder::with_max_packet(10);
        assert_eq!(d.max_packet(), 10);
        // A PUBLISH of 2 + 8 bytes fits; one of 2 + 9 is refused from its header.
        d.feed(&[0x30, 8, 0, 1, b't', 1, 2, 3, 4, 5]);
        assert!(matches!(d.next_packet(), Some(Ok(Packet::Publish(_)))));
        d.feed(&[0x30, 9]);
        assert_eq!(d.next_packet(), Some(Err(Error::TooLarge { size: 11, max: 10 })));
        assert_eq!(Decoder::with_max_packet(0).max_packet(), 2);
        assert_eq!(Decoder::with_max_packet(usize::MAX).max_packet(), MAX_PACKET);
        assert_eq!(Decoder::new().max_packet(), DEFAULT_MAX_PACKET);
        // The largest header is refused at once by the default limit.
        let mut d = Decoder::new();
        d.feed(&[0x30, 0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(d.next_packet(), Some(Err(Error::TooLarge { size: MAX_PACKET, max: DEFAULT_MAX_PACKET })));
    }

    #[test]
    fn errors_display() {
        let all = [
            Error::ReservedType(0),
            Error::Flags { packet_type: 3, flags: 6 },
            Error::RemainingLength,
            Error::TooLarge { size: 9, max: 8 },
            Error::Truncated,
            Error::TrailingBytes,
            Error::Utf8,
            Error::NullChar,
            Error::TooLong(70_000),
            Error::ProtocolName,
            Error::UnsupportedVersion(5),
            Error::ConnectFlags(1),
            Error::ConnAckFlags(2),
            Error::ReturnCode(6),
            Error::PacketIdZero,
            Error::PacketId,
            Error::TopicName,
            Error::TopicFilter,
            Error::EmptySubscription,
            Error::SubscribeOptions(3),
        ];
        for e in all {
            let s = e.to_string();
            assert!(!s.is_empty());
            let _: &dyn std::error::Error = &e;
        }
        assert_eq!(
            Error::UnsupportedVersion(5).to_string(),
            "protocol version not supported (level 5); only MQTT 3.1.1, level 4 named MQTT, is read"
        );
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
    }

    /// What every reader must hold for any bytes: no panic, a packet read
    /// writes back to bytes that read the same, and a decoder fed in pieces
    /// finds what one fed all at once finds.
    fn check(data: &[u8], piece: usize) {
        // The same limit as Packet::parse, so a large packet reads the same
        // both ways.
        let mut whole = Decoder::with_max_packet(MAX_PACKET);
        whole.feed(data);
        let mut packets = Vec::new();
        while let Some(Ok(p)) = whole.next_packet() {
            packets.push(p);
        }
        let mut pieces = Decoder::with_max_packet(MAX_PACKET);
        let mut again = Vec::new();
        for chunk in data.chunks(piece.max(1)) {
            pieces.feed(chunk);
            while let Some(Ok(p)) = pieces.next_packet() {
                again.push(p);
            }
        }
        assert_eq!(packets, again);
        if let Ok(Some((p, used))) = Packet::parse(data) {
            assert!(used <= data.len());
            assert_eq!(packets.first(), Some(&p));
        }
        for p in &packets {
            let bytes = p.to_bytes().expect("a packet read can be written");
            assert_eq!(parse(&bytes), Ok(p.clone()));
        }
    }

    #[test]
    fn random_bytes_never_panic_and_round_trip() {
        let mut rng = Lcg(0x6d71_7474);
        let samples = samples();
        let mut read = 0;
        for i in 0..4000 {
            let data: Vec<u8> = if i % 2 == 0 {
                // Bytes from scratch, with a first byte that is often a real type.
                let n = rng.below(48);
                let mut d: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                if let Some(first) = d.first_mut()
                    && rng.below(2) == 0
                {
                    *first &= 0xf3;
                }
                if d.len() > 1 && rng.below(2) == 0 {
                    d[1] &= 0x3f;
                }
                d
            } else {
                // A real packet with a few bytes changed, cut or added.
                let mut d = samples[rng.below(samples.len())].1.clone();
                for _ in 0..1 + rng.below(3) {
                    match rng.below(3) {
                        0 if !d.is_empty() => {
                            let k = rng.below(d.len());
                            d[k] = rng.next() as u8;
                        }
                        1 if !d.is_empty() => {
                            let k = rng.below(d.len());
                            d.truncate(k);
                        }
                        _ => d.push(rng.next() as u8),
                    }
                }
                d
            };
            if matches!(Packet::parse(&data), Ok(Some(_))) {
                read += 1;
            }
            check(&data, 1 + rng.below(5));
        }
        // The loop reaches real packets, not only errors.
        assert!(read > 200, "{read} packets read");
    }

    #[test]
    fn random_topics_match_themselves() {
        let mut rng = Lcg(42);
        let alphabet = ['a', 'b', '/', '+', '#', '$', '\0'];
        for _ in 0..3000 {
            let make =
                |rng: &mut Lcg| -> String { (0..rng.below(7)).map(|_| alphabet[rng.below(alphabet.len())]).collect() };
            let (filter, topic) = (make(&mut rng), make(&mut rng));
            let matched = topic_matches(&filter, &topic);
            if matched {
                assert!(check_topic_filter(&filter).is_ok() && check_topic_name(&topic).is_ok());
            }
            if check_topic_name(&topic).is_ok() {
                assert!(topic_matches(&topic, &topic), "{topic:?}");
                let first_wild = !topic.starts_with('$');
                assert_eq!(topic_matches("#", &topic), first_wild, "{topic:?}");
            }
        }
    }
}
