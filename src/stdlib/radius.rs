//! RADIUS: reading and writing packets and attributes, with no I/O.
//!
//! `Packet` implements `Wire` and supports `codec::Frames<Packet>` for TCP
//! framing. There is no authentication session, `Service`, or cryptography.
//! Authenticators and hidden passwords remain the caller's responsibility.
//!
//! RADIUS is how network equipment asks a central server whether a user
//! may connect. A Wi-Fi access point, VPN gateway or switch (the NAS, for
//! network access server) sends an Access-Request over UDP to port 1812,
//! and the server answers Access-Accept, Access-Reject or
//! Access-Challenge. The NAS then reports each session's start, progress
//! and end in Accounting-Requests to port 1813. A server can also reach
//! back to the NAS on port 3799, to change a session's settings
//! (CoA-Request) or end it (Disconnect-Request). Every packet is a
//! 20-byte header (code, identifier, length and a 16-byte authenticator)
//! followed by attributes, each a type, a length and a value.
//!
//! This module follows RFC 2865 for packets and the base attributes,
//! RFC 2866 for accounting, RFC 5176 for CoA and Disconnect messages, and
//! RFC 6929 for the extended and long extended attributes, TLVs and
//! extended vendor-specific attributes. Its dictionary holds every
//! standard attribute from 1 to 101, and it reads the data types of RFC
//! 6572 and RFC 8044. RFC 6613 and RFC 6614 carry the same packets
//! over TCP and TLS. [`Stream<codec::Frames<Packet>>`](fictionet::stdlib::codec::Stream) reads those streams.
//!
//! Nothing here reads a socket, and nothing here does cryptography. A
//! world that plays a RADIUS server gives each datagram's bytes to
//! [`Packet::parse_datagram`], reads the attributes it cares about, builds the
//! answer with [`Packet::reply`], and sends back the bytes of
//! [`Packet::to_bytes`]. The authenticators, the Message-Authenticator
//! attribute and the hiding of User-Password and Tunnel-Password all use
//! MD5 and the shared secret, so they are left to the caller. Hidden
//! values stay as the bytes on the wire. The docs of [`Packet::reply`]
//! say which bytes each authenticator is taken over.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A packet whose attributes do not fit its length is refused
//! whole, as RFC 2865 asks. A single attribute whose value does not fit
//! its type is only an error when that value is read, so a world can
//! skip attributes it does not use, as RFC 6929 asks. Every writer
//! refuses what its reader would refuse: it returns `None` or
//! [`Error::Unwritable`] rather than cut a value or leave an attribute out.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::radius::{attr, enum_name, Code, Packet, Value};
//!
//! // An Accounting-Request: a session for "bob" has started.
//! let mut bytes = vec![4, 7, 0, 36];
//! bytes.extend_from_slice(&[0; 16]); // the authenticator
//! bytes.extend_from_slice(&[40, 6, 0, 0, 0, 1]); // Acct-Status-Type = Start
//! bytes.extend_from_slice(&[44, 5, b'a', b'b', b'c']); // Acct-Session-Id = "abc"
//! bytes.extend_from_slice(&[1, 5, b'b', b'o', b'b']); // User-Name = "bob"
//!
//! let request = Packet::parse_datagram(&bytes).unwrap();
//! assert_eq!(request.code, Code::AccountingRequest);
//! let status = request.get(attr::ACCT_STATUS_TYPE).unwrap().decode();
//! assert_eq!(status, Ok(Value::Enum(1)));
//! assert_eq!(enum_name(attr::ACCT_STATUS_TYPE, 1), Some("Start"));
//! let user = request.get(attr::USER_NAME).unwrap().decode();
//! assert_eq!(user, Ok(Value::Text("bob".to_string())));
//!
//! // The answer has the same identifier and no attributes. Its
//! // authenticator is still the request's, which is what the Response
//! // Authenticator's MD5 is taken over.
//! let reply = request.reply(Code::AccountingResponse);
//! let out = reply.to_bytes().unwrap();
//! assert_eq!(out[..4], [5, 7, 0, 20]);
//! assert_eq!(out[4..], [0; 16]);
//! ```

use fictionet::stdlib::codec::Prefixed;
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::codec::{Wire};

/// The UDP port RADIUS servers take Access-Requests on.
pub const AUTH_PORT: u16 = 1812;
/// The UDP port RADIUS servers take Accounting-Requests on.
pub const ACCT_PORT: u16 = 1813;
/// The UDP port a NAS takes CoA-Requests and Disconnect-Requests on
/// (RFC 5176).
pub const DYNAMIC_AUTH_PORT: u16 = 3799;
/// The TCP port RADIUS over TLS listens on (RFC 6614).
pub const RADSEC_PORT: u16 = 2083;
/// The length of the header: code, identifier, length and authenticator.
pub const HEADER_LEN: usize = 20;
/// The length of the authenticator.
pub const AUTHENTICATOR_LEN: usize = 16;
/// The longest packet, header included (RFC 2865, section 3).
pub const MAX_PACKET: usize = 4096;
/// The longest value one attribute can carry: 255 less the type and
/// length bytes.
pub const MAX_VALUE: usize = 253;
/// The longest value an extended attribute (types 241 to 244) can carry
/// after its Extended-Type byte.
pub const MAX_EXTENDED_VALUE: usize = MAX_VALUE - 1;
/// The longest piece of a value one long extended attribute (types 245
/// and 246) can carry after its Extended-Type and flags bytes.
pub const MAX_LONG_FRAGMENT: usize = MAX_VALUE - 2;
/// The longest value a long extended attribute can carry once its
/// fragments are joined. Every fragment must fit in one packet, so this
/// is the room a packet has after its header, less the 4 bytes each of
/// the 16 fragments spends on its own header.
pub const MAX_LONG_EXTENDED_VALUE: usize = MAX_PACKET - HEADER_LEN - 4 * (MAX_PACKET - HEADER_LEN).div_ceil(255);
/// The longest value [`Attribute::split`] spreads over attributes that
/// all fit in one packet: the room after the header, less the 2 bytes
/// each of the 16 attributes spends on its type and length.
pub const MAX_CONCAT_VALUE: usize = MAX_PACKET - HEADER_LEN - 2 * (MAX_PACKET - HEADER_LEN).div_ceil(255);
/// The most attributes a packet can hold: each takes at least 2 bytes.
pub const MAX_ATTRIBUTES: usize = (MAX_PACKET - HEADER_LEN) / 2;

/// The More flag in a long extended attribute's flags byte: more of the
/// value follows in another attribute.
pub const MORE_FLAG: u8 = 0x80;

/// A packet's code: what kind of message it is. Codes compare and hash
/// by number, so `Code::Other(1)` equals [`Code::AccessRequest`], which is
/// how a packet built with it reads back.
#[derive(Clone, Copy, Debug)]
pub enum Code {
    /// 1: a NAS asks whether a user may connect.
    AccessRequest,
    /// 2: the user may connect, with the settings in the attributes.
    AccessAccept,
    /// 3: the user may not connect.
    AccessReject,
    /// 4: a NAS reports a session's start, progress or end (RFC 2866).
    AccountingRequest,
    /// 5: the server has stored an Accounting-Request (RFC 2866).
    AccountingResponse,
    /// 11: the server needs more from the user, such as a one-time code.
    AccessChallenge,
    /// 12: a client asks whether the server is up (experimental, RFC 5997).
    StatusServer,
    /// 13: reserved for Status-Client (experimental).
    StatusClient,
    /// 40: a server asks a NAS to end a session (RFC 5176).
    DisconnectRequest,
    /// 41: the NAS ended the session.
    DisconnectAck,
    /// 42: the NAS did not end the session.
    DisconnectNak,
    /// 43: a server asks a NAS to change a session (RFC 5176).
    CoaRequest,
    /// 44: the NAS changed the session.
    CoaAck,
    /// 45: the NAS did not change the session.
    CoaNak,
    /// Any other code.
    Other(u8),
}

impl PartialEq for Code {
    fn eq(&self, other: &Code) -> bool {
        self.to_u8() == other.to_u8()
    }
}

impl Eq for Code {}

impl std::hash::Hash for Code {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_u8().hash(state);
    }
}

impl Code {
    /// The code's number.
    pub fn to_u8(self) -> u8 {
        match self {
            Code::AccessRequest => 1,
            Code::AccessAccept => 2,
            Code::AccessReject => 3,
            Code::AccountingRequest => 4,
            Code::AccountingResponse => 5,
            Code::AccessChallenge => 11,
            Code::StatusServer => 12,
            Code::StatusClient => 13,
            Code::DisconnectRequest => 40,
            Code::DisconnectAck => 41,
            Code::DisconnectNak => 42,
            Code::CoaRequest => 43,
            Code::CoaAck => 44,
            Code::CoaNak => 45,
            Code::Other(c) => c,
        }
    }

    /// The code for number `c`.
    pub fn from_u8(c: u8) -> Code {
        match c {
            1 => Code::AccessRequest,
            2 => Code::AccessAccept,
            3 => Code::AccessReject,
            4 => Code::AccountingRequest,
            5 => Code::AccountingResponse,
            11 => Code::AccessChallenge,
            12 => Code::StatusServer,
            13 => Code::StatusClient,
            40 => Code::DisconnectRequest,
            41 => Code::DisconnectAck,
            42 => Code::DisconnectNak,
            43 => Code::CoaRequest,
            44 => Code::CoaAck,
            45 => Code::CoaNak,
            c => Code::Other(c),
        }
    }

    /// The code's name as the RFCs write it, or `None` for a number
    /// with no name here.
    pub fn name(self) -> Option<&'static str> {
        Some(match Code::from_u8(self.to_u8()) {
            Code::AccessRequest => "Access-Request",
            Code::AccessAccept => "Access-Accept",
            Code::AccessReject => "Access-Reject",
            Code::AccountingRequest => "Accounting-Request",
            Code::AccountingResponse => "Accounting-Response",
            Code::AccessChallenge => "Access-Challenge",
            Code::StatusServer => "Status-Server",
            Code::StatusClient => "Status-Client",
            Code::DisconnectRequest => "Disconnect-Request",
            Code::DisconnectAck => "Disconnect-ACK",
            Code::DisconnectNak => "Disconnect-NAK",
            Code::CoaRequest => "CoA-Request",
            Code::CoaAck => "CoA-ACK",
            Code::CoaNak => "CoA-NAK",
            Code::Other(_) => return None,
        })
    }
}

/// One attribute as it sits in a packet: its type and its value's bytes.
/// Vendor-specific sub-attributes and TLVs inside a value use the same
/// shape.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attribute {
    /// The attribute's type number, such as [`attr::USER_NAME`].
    pub kind: u8,
    /// The value's bytes. A value read from a packet is at most
    /// [`MAX_VALUE`] bytes long, and [`Packet::to_bytes`] refuses a
    /// packet holding a longer one.
    pub value: Vec<u8>,
}

impl Attribute {
    /// A standard attribute of type `kind` holding `value`'s bytes. It
    /// returns `None` unless [`Attribute::decode`] reads the result back
    /// as the same value: the value must be of the dictionary's data type
    /// for `kind` ([`DataType::String`] for a type it does not know), fit
    /// in [`MAX_VALUE`] bytes, and meet the attribute's own rules, such
    /// as CHAP-Password's 17 bytes. So an empty TLV list, an IPv4 prefix
    /// 0.0.0.0/0 (which would read back as 0.0.0.0/32) and a prefix with
    /// bits set past its length are all refused. A TLV or vendor
    /// sub-attribute is not in the standard space; make one with
    /// [`Attribute::from_value_as`].
    pub fn from_value(kind: u8, value: &Value) -> Option<Attribute> {
        let a = Attribute { kind, value: value.encode()? };
        (a.decode().as_ref() == Ok(value)).then_some(a)
    }

    /// An attribute of type `kind` holding `value`'s bytes, for a TLV, a
    /// vendor sub-attribute or any other attribute whose type the caller
    /// knows. It returns `None` unless the bytes read back as the same
    /// value of `data_type`, as for [`Attribute::from_value`].
    pub fn from_value_as(kind: u8, data_type: DataType, value: &Value) -> Option<Attribute> {
        if data_type != value.data_type()
            && !(data_type == DataType::Concat && matches!(value, Value::String(_)))
        {
            return None;
        }
        Some(Attribute { kind, value: value.encode()? })
    }

    /// Attributes of type `kind` that carry `data` between them, at most
    /// [`MAX_VALUE`] bytes each, as EAP-Message does for a long EAP
    /// packet. Empty data gives one empty attribute. It returns `None` if
    /// `data` is longer than [`MAX_CONCAT_VALUE`], since the attributes
    /// would not fit in one packet. Join them back with
    /// [`Packet::concat_consecutive`].
    pub fn split(kind: u8, data: &[u8]) -> Option<Vec<Attribute>> {
        if data.len() > MAX_CONCAT_VALUE {
            return None;
        }
        if data.is_empty() {
            return Some(vec![Attribute { kind, value: Vec::new() }]);
        }
        Some(data.chunks(MAX_VALUE).map(|c| Attribute { kind, value: c.to_vec() }).collect())
    }

    /// What the dictionary knows about this attribute's type, if
    /// anything.
    pub fn info(&self) -> Option<&'static AttributeInfo> {
        lookup(self.kind)
    }

    /// The value, read as the dictionary's data type for this attribute.
    /// A type the dictionary does not know is read as
    /// [`DataType::String`]. The dictionary is the standard attribute
    /// space, so this is for attributes of a packet. A TLV or vendor
    /// sub-attribute has types of its own: read its value with
    /// [`Value::decode`] and the type its specification gives.
    ///
    /// Besides the data type, it checks the lengths and ranges RFC 2865
    /// and RFC 3579 set for single attributes. Text and strings in the
    /// dictionary may not be empty (EAP-Message may, for EAP-Start).
    /// User-Password is 16 to 128 bytes in steps of 16, CHAP-Password 17
    /// bytes, CHAP-Challenge 5 bytes or more, Message-Authenticator 16
    /// bytes, and Login-TCP-Port at most 65535.
    pub fn decode(&self) -> Result<Value, Error> {
        let data_type = self.info().map_or(DataType::String, |i| i.data_type);
        let value = Value::decode(data_type, &self.value)?;
        let n = self.value.len();
        let length_ok = match self.kind {
            attr::USER_PASSWORD => (16..=128).contains(&n) && n.is_multiple_of(16),
            attr::CHAP_PASSWORD => n == 17,
            attr::CHAP_CHALLENGE => n >= 5,
            attr::MESSAGE_AUTHENTICATOR => n == 16,
            // Only a type the dictionary knows is known to be text or a
            // string.
            _ => n > 0 || self.info().is_none() || !matches!(data_type, DataType::Text | DataType::String),
        };
        if !length_ok {
            return Err(Error::ValueLength(n));
        }
        if self.kind == attr::LOGIN_TCP_PORT && matches!(value, Value::Integer(p) if p > 65535) {
            return Err(Error::Range);
        }
        Ok(value)
    }
}

/// One RADIUS packet. The length field is worked out from the attributes,
/// so it is not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// What kind of message this is.
    pub code: Code,
    /// Chosen by the client and copied into the answer, so it can match
    /// answers to requests.
    pub identifier: u8,
    /// The Request Authenticator or Response Authenticator. This module
    /// neither makes nor checks it.
    pub authenticator: [u8; AUTHENTICATOR_LEN],
    /// The attributes, in the order they came. Order matters for
    /// attributes of the same type, such as Proxy-State and EAP-Message.
    pub attributes: Vec<Attribute>,
}

/// Why bytes are not a RADIUS packet, or an attribute's value cannot be
/// read as its data type. RFC 2865 asks a server to drop a packet that
/// cannot be read, without an answer. RFC 6929 calls an attribute whose
/// value cannot be read invalid: a server treats it as unknown, and does
/// not drop the packet for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Fewer bytes than the 20-byte header. The value is how many came.
    Short(usize),
    /// The length field was below 20 or above 4096.
    Length {
        /// The declared packet length.
        length: usize,
        /// The largest accepted packet length.
        limit: usize,
    },
    /// The datagram was shorter than its length field says.
    Truncated {
        /// The length field.
        length: u16,
        /// How many bytes came.
        got: usize,
    },
    /// The attribute at this offset in the packet has a length below 2,
    /// or runs past the packet's length.
    Attribute(usize),
    /// Bytes follow the declared packet length, including datagram padding.
    Trailing {
        /// Number of trailing bytes.
        remaining: usize,
    },
    /// The value cannot be written without changing it.
    Unwritable,
    /// An attribute value had this many bytes, which its type does not
    /// allow.
    ValueLength(usize),
    /// An attribute value of type text that is not UTF-8.
    Text,
    /// A prefix length past the address's bits, too few prefix bytes for
    /// the length, bits set past the length, or an IPv4 prefix of
    /// 0.0.0.0 whose length is not 32.
    Prefix,
    /// A TLV whose length is below 3, a vendor sub-attribute whose length
    /// is below 2, or either running past the value.
    Nested,
    /// A long extended attribute's fragments do not join: a fragment with
    /// the More flag is not full length, or the next attribute does not
    /// continue the value, or none does. Also attributes of a concat
    /// value that are not consecutive.
    Fragment,
    /// A number outside the range its attribute allows, such as a
    /// Login-TCP-Port above 65535.
    Range,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Short(n) => write!(f, "{n} bytes, fewer than the 20-byte RADIUS header"),
            Error::Length { length, limit } => write!(f, "length field {length}, outside {HEADER_LEN}..={limit}"),
            Error::Trailing { remaining } => write!(f, "{remaining} bytes after RADIUS packet"),
            Error::Unwritable => f.write_str("RADIUS value cannot be written without changing it"),
            Error::Truncated { length, got } => write!(f, "length field {length}, but only {got} bytes came"),
            Error::Attribute(at) => write!(f, "the attribute at offset {at} does not fit the packet"),
            Error::ValueLength(n) => write!(f, "a value of {n} bytes, a length its type does not allow"),
            Error::Text => f.write_str("text that is not UTF-8"),
            Error::Prefix => f.write_str("a malformed address prefix"),
            Error::Nested => f.write_str("a TLV or vendor sub-attribute that does not fit its value"),
            Error::Fragment => f.write_str("long extended attribute fragments that do not join"),
            Error::Range => f.write_str("a number outside the range its attribute allows"),
        }
    }
}

impl std::error::Error for Error {}

impl Wire for Attribute {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one type-length-value attribute. Refuses lengths below two,
    /// incomplete attributes, and trailing bytes. Values remain opaque.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let [kind, length, ..] = bytes else { return Err(Error::Attribute(0)) };
        if *length < 2 || usize::from(*length) != bytes.len() {
            return Err(Error::Attribute(0));
        }
        Ok(Self { kind: *kind, value: bytes[2..].to_vec() })
    }

    /// Appends one attribute. Refuses values over [`MAX_VALUE`].
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.value.len() > MAX_VALUE {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&[self.kind, (self.value.len() + 2) as u8]);
        out.extend_from_slice(&self.value);
        Ok(())
    }
}

impl Packet {
    /// Reads one RADIUS datagram. Octets past the Length field are padding
    /// and are ignored on reception, as RFC 2865, section 3 requires.
    /// Refuses headers shorter than [`HEADER_LEN`], lengths outside
    /// `20..=4096`, truncated packets, and malformed attributes.
    /// Use [`Wire::parse`] when trailing bytes must be refused.
    pub fn parse_datagram(b: &[u8]) -> Result<Packet, Error> {
        if b.len() < HEADER_LEN {
            return Err(Error::Short(b.len()));
        }
        let length = u16::from_be_bytes([b[2], b[3]]);
        let end = usize::from(length);
        if !(HEADER_LEN..=MAX_PACKET).contains(&end) {
            return Err(Error::Length {
                length: end,
                limit: MAX_PACKET,
            });
        }
        if b.len() < end {
            return Err(Error::Truncated {
                length,
                got: b.len(),
            });
        }
        <Packet as Wire>::parse(&b[..end])
    }

    /// A packet with no attributes.
    pub fn new(code: Code, identifier: u8, authenticator: [u8; AUTHENTICATOR_LEN]) -> Packet {
        Packet { code, identifier, authenticator, attributes: Vec::new() }
    }

    /// How many bytes the packet takes, header included. When this is
    /// more than [`MAX_PACKET`], [`Packet::to_bytes`] refuses it.
    pub fn encoded_len(&self) -> usize {
        self.attributes.iter().fold(HEADER_LEN, |n, a| n.saturating_add(2).saturating_add(a.value.len()))
    }

    /// The first attribute of type `kind`.
    pub fn get(&self, kind: u8) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.kind == kind)
    }

    /// Every attribute of type `kind`, in order.
    pub fn all(&self, kind: u8) -> impl Iterator<Item = &Attribute> {
        self.attributes.iter().filter(move |a| a.kind == kind)
    }

    /// The values of every attribute of type `kind`, joined in order,
    /// wherever they sit in the packet. For a packet [`Packet::parse`]
    /// read, the result is never longer than a packet. To read an
    /// EAP-Message or another value of [`DataType::Concat`], use
    /// [`Packet::concat_consecutive`], which checks the attributes sit
    /// together.
    pub fn concat(&self, kind: u8) -> Vec<u8> {
        let mut out = Vec::new();
        for a in self.all(kind) {
            out.extend_from_slice(&a.value);
        }
        out
    }

    /// The values of the attributes of type `kind`, joined in order, as
    /// EAP-Message carries an EAP packet longer than one attribute holds.
    /// RFC 3579 (section 3.1) and RFC 8044 (section 3.6) ask for such
    /// attributes to be consecutive, so it gives [`Error::Fragment`]
    /// if another attribute sits between two of them. It returns `None`
    /// if the packet has no attribute of type `kind`.
    pub fn concat_consecutive(&self, kind: u8) -> Option<Result<Vec<u8>, Error>> {
        let first = self.attributes.iter().position(|a| a.kind == kind)?;
        let run = self.attributes[first..].iter().take_while(|a| a.kind == kind).count();
        if self.attributes[first + run..].iter().any(|a| a.kind == kind) {
            return Some(Err(Error::Fragment));
        }
        Some(Ok(self.attributes[first..first + run].iter().flat_map(|a| a.value.iter().copied()).collect()))
    }

    /// Adds an attribute, unless the packet would then be longer than
    /// [`MAX_PACKET`] or the value longer than [`MAX_VALUE`]. It refuses
    /// any attribute while the packet is already too long, as it can be
    /// after changes to [`Packet::attributes`].
    pub fn push(&mut self, attribute: Attribute) -> Result<(), Error> {
        if attribute.value.len() > MAX_VALUE
            || self.encoded_len().saturating_add(2 + attribute.value.len()) > MAX_PACKET
        {
            return Err(Error::Unwritable);
        }
        self.attributes.push(attribute);
        Ok(())
    }

    /// The answer to this packet, with `code`, the same identifier and no
    /// attributes but copies of the Proxy-State attributes, in order, as
    /// RFC 2865 and RFC 5176 ask.
    ///
    /// Its authenticator is this packet's. That is what the Response
    /// Authenticator is taken over: once the answer's attributes are in,
    /// the caller appends the shared secret to its bytes, takes the MD5,
    /// and puts that in the authenticator. An Accounting-Request,
    /// CoA-Request or Disconnect-Request is signed the same way, but over
    /// its bytes with an authenticator of 16 zero bytes. In an
    /// Access-Request the authenticator is 16 random bytes.
    pub fn reply(&self, code: Code) -> Packet {
        let proxy = self.all(attr::PROXY_STATE).cloned().collect();
        Packet { code, identifier: self.identifier, authenticator: self.authenticator, attributes: proxy }
    }

    /// The extended attributes (types 241 to 246) in packet order, with
    /// each long extended attribute's fragments joined. Each is read on
    /// its own, so an invalid one does not hide the others, as RFC 6929
    /// asks.
    ///
    /// RFC 6929 (section 2.2) asks for the attribute right after a
    /// fragment with the More flag to continue the value: the same Type
    /// and the same Extended-Type. An extended attribute is an error if
    /// it has no Extended-Type byte or no bytes after it. A long one is
    /// an error if it has no flags byte or no bytes after that. A long
    /// value is [`Error::Fragment`] if a fragment with the More flag
    /// is not full length, the next attribute does not continue it, or
    /// no attribute follows. That error sits where the value's first
    /// fragment was, and the attribute that broke the value is read on
    /// its own.
    pub fn extended(&self) -> Vec<Result<Extended, Error>> {
        let mut out: Vec<Result<Extended, Error>> = Vec::new();
        // The index in `out` of a long value whose last fragment had the
        // More flag, and that value's attribute type.
        let mut open: Option<(usize, u8)> = None;
        for a in &self.attributes {
            if let Some((i, kind)) = open.take()
                && let Ok(e) = &mut out[i]
            {
                match long_fragment(&a.value) {
                    Ok((t, more, data)) if a.kind == kind && t == e.ext_type => {
                        e.data.extend_from_slice(data);
                        if more {
                            open = Some((i, kind));
                        }
                        continue;
                    }
                    // The value was cut short; this attribute is read on
                    // its own below.
                    _ => out[i] = Err(Error::Fragment),
                }
            }
            match a.kind {
                attr::EXTENDED_TYPE_1..=attr::EXTENDED_TYPE_4 => out.push(match a.value.as_slice() {
                    [ext_type, data @ ..] if !data.is_empty() => {
                        Ok(Extended { kind: a.kind, ext_type: *ext_type, data: data.to_vec() })
                    }
                    v => Err(Error::ValueLength(v.len())),
                }),
                attr::LONG_EXTENDED_TYPE_1 | attr::LONG_EXTENDED_TYPE_2 => match long_fragment(&a.value) {
                    Ok((ext_type, more, data)) => {
                        out.push(Ok(Extended { kind: a.kind, ext_type, data: data.to_vec() }));
                        if more {
                            open = Some((out.len() - 1, a.kind));
                        }
                    }
                    Err(e) => out.push(Err(e)),
                },
                _ => {}
            }
        }
        if let Some((i, _)) = open {
            out[i] = Err(Error::Fragment);
        }
        out
    }

    /// Adds the attributes that carry `extended`, splitting a long value
    /// into fragments. Nothing is added if they would not fit in the
    /// packet, or if [`Extended::to_attributes`] cannot write them.
    pub fn push_extended(&mut self, extended: &Extended) -> Result<(), Error> {
        let attributes = extended.to_attributes().ok_or(Error::Unwritable)?;
        let need: usize = attributes.iter().map(|a| 2 + a.value.len()).sum();
        if self.encoded_len().saturating_add(need) > MAX_PACKET {
            return Err(Error::Unwritable);
        }
        self.attributes.extend(attributes);
        Ok(())
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one packet. Refuses lengths outside 20..=4096, truncated
    /// headers or attributes, and trailing bytes, including datagram padding.
    fn parse(b: &[u8]) -> Result<Packet, Error> {
        if b.len() < HEADER_LEN {
            return Err(Error::Short(b.len()));
        }
        let length = u16::from_be_bytes([b[2], b[3]]);
        let end = usize::from(length);
        if !(HEADER_LEN..=MAX_PACKET).contains(&end) {
            return Err(Error::Length { length: end, limit: MAX_PACKET });
        }
        if b.len() < end {
            return Err(Error::Truncated { length, got: b.len() });
        }
        if b.len() != end {
            return Err(Error::Trailing { remaining: b.len() - end });
        }
        let mut authenticator = [0u8; AUTHENTICATOR_LEN];
        authenticator.copy_from_slice(&b[4..HEADER_LEN]);
        let attributes =
            parse_attributes(&b[HEADER_LEN..end], 2).map_err(|at| Error::Attribute(HEADER_LEN + at))?;
        Ok(Packet { code: Code::from_u8(b[0]), identifier: b[1], authenticator, attributes })
    }

    /// Appends one packet. Refuses values over [`MAX_VALUE`] or packets over
    /// [`MAX_PACKET`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let length = self.encoded_len();
        if length > MAX_PACKET || self.attributes.iter().any(|a| a.value.len() > MAX_VALUE) {
            return Err(Error::Unwritable);
        }
        out.push(self.code.to_u8());
        out.push(self.identifier);
        // length is at most MAX_PACKET, so it fits in 16 bits.
        out.extend_from_slice(&(length as u16).to_be_bytes());
        out.extend_from_slice(&self.authenticator);
        for a in &self.attributes {
            out.push(a.kind);
            out.push((a.value.len() + 2) as u8);
            out.extend_from_slice(&a.value);
        }
        Ok(())
    }
}

/// Reads RADIUS over TCP or TLS packets without retaining input.
///
/// Use with [`fictionet::stdlib::codec::Stream`] for a buffer bounded by [`limit`](fictionet::stdlib::codec::Frames::limit).
/// The first four bytes suffice to refuse an invalid or excessive length. Partial packets
/// return [`fictionet::stdlib::codec::Step::Need`], including at EOF, so the driver reports truncation.
/// An invalid length or malformed attributes ends the stream.
/// [RFC 6613 §2.6.4] requires closing the connection on malformed attributes.
///
/// [RFC 6613 §2.6.4]: https://www.rfc-editor.org/rfc/rfc6613.html#section-2.6.4
///
/// ```
/// use fictionet::stdlib::codec::{Frames, Stream, Wire, finish, pump};
/// use fictionet::stdlib::radius::{Code, Packet};
/// let packet = Packet::new(Code::AccessRequest, 7, [0; 16]);
/// let bytes = Wire::to_bytes(&packet)?;
/// let mut stream = Stream::new(Frames::<Packet>::with_limit(1024));
/// let mut packets = Vec::new();
/// for chunk in bytes.chunks(3) {
///     pump(&mut stream, chunk, |item| packets.push(item))?;
/// }
/// finish(&mut stream, |item| packets.push(item))?;
/// assert_eq!(packets, vec![packet]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
impl Prefixed for Packet {
    type Item = Packet;
    type Error = Error;
    type Limit = usize;
    const NAME: &'static str = "RADIUS";

    #[inline]
    fn default_limit() -> Self::Limit { MAX_PACKET }

    #[inline]
    fn normalize_limit(limit: Self::Limit) -> Self::Limit { limit.clamp(HEADER_LEN, MAX_PACKET) }

    #[inline]
    fn capacity(limit: &Self::Limit) -> usize { *limit }

    #[inline]
    fn parse_prefix(input: &[u8], limit: &Self::Limit) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        let Some(&[_, _, hi, lo]) = input.get(..4) else { return Ok(None) };
        let length = u16::from_be_bytes([hi, lo]);
        let used = usize::from(length);
        if used < HEADER_LEN {
            return Err(Error::Length { length: used, limit });
        }
        if used > limit {
            return Err(Error::Length { length: used, limit });
        }
        let Some(bytes) = input.get(..used) else { return Ok(None) };
        Ok(Some((Packet::parse(bytes)?, used)))
    }
}


/// Reads attributes (type, length, value) filling all of `b`. Each
/// length must be at least `min`. On failure it gives the offset of the
/// attribute that broke.
fn parse_attributes(b: &[u8], min: usize) -> Result<Vec<Attribute>, usize> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < b.len() {
        let rest = &b[at..];
        let [kind, len, ..] = rest else { return Err(at) };
        let len = usize::from(*len);
        if len < min || len > rest.len() {
            return Err(at);
        }
        out.push(Attribute { kind: *kind, value: rest[2..len].to_vec() });
        at += len;
    }
    Ok(out)
}

/// Reads one long extended attribute's value: the Extended-Type, whether
/// the More flag is set, and this fragment's bytes. RFC 6929 asks for at
/// least one byte after the flags, and a full-length attribute when the
/// More flag is set. The reserved flag bits are ignored.
fn long_fragment(b: &[u8]) -> Result<(u8, bool, &[u8]), Error> {
    let [ext_type, flags, data @ ..] = b else { return Err(Error::ValueLength(b.len())) };
    if data.is_empty() {
        return Err(Error::ValueLength(b.len()));
    }
    let more = flags & MORE_FLAG != 0;
    if more && b.len() != MAX_VALUE {
        return Err(Error::Fragment);
    }
    Ok((*ext_type, more, data))
}

/// How many bytes [`write_attributes`] writes for `attributes`.
fn attributes_len(attributes: &[Attribute]) -> usize {
    attributes.iter().fold(0, |n: usize, a| n.saturating_add(2).saturating_add(a.value.len()))
}

/// Appends attributes and may stop partway on refusal. Both callers use a
/// fresh local Vec, so no partial result escapes.
fn write_attributes(out: &mut Vec<u8>, attributes: &[Attribute]) -> Option<()> {
    for a in attributes {
        a.write(out).ok()?;
    }
    Some(())
}

/// The data types attribute values come in (RFC 8044 names most of
/// them).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataType {
    /// UTF-8 text, such as User-Name.
    Text,
    /// Any bytes, such as State, Class or a hidden password.
    String,
    /// Bytes that may be spread over several attributes of the same type
    /// and joined, such as EAP-Message. One attribute reads as a string.
    Concat,
    /// An IPv4 address, 4 bytes.
    Address,
    /// A 32-bit unsigned integer.
    Integer,
    /// A 32-bit unsigned integer whose values have names, such as
    /// Service-Type. See [`enum_name`].
    Enum,
    /// Seconds since 1970-01-01 00:00 UTC, as a 32-bit unsigned integer.
    Time,
    /// A 64-bit unsigned integer (RFC 6929).
    Integer64,
    /// An IPv6 address, 16 bytes (RFC 3162).
    Ipv6Address,
    /// An IPv6 prefix: a reserved byte, a prefix length up to 128, and up
    /// to 16 bytes of prefix (RFC 3162).
    Ipv6Prefix,
    /// An IPv4 prefix: a reserved byte, a prefix length up to 32, and 4
    /// bytes of prefix (RFC 6572).
    Ipv4Prefix,
    /// An IPv6 interface identifier, 8 bytes (RFC 3162).
    InterfaceId,
    /// Vendor-Specific (type 26): a 4-byte vendor number and the vendor's
    /// bytes.
    Vsa,
    /// An extended vendor-specific value: a 4-byte vendor number, a
    /// 1-byte vendor type and the vendor's bytes (RFC 6929).
    Evs,
    /// An extended attribute's value: an Extended-Type byte and the rest
    /// (RFC 6929, types 241 to 244).
    Extended,
    /// A long extended attribute's value: an Extended-Type byte, a flags
    /// byte and one fragment of the rest (RFC 6929, types 245 and 246).
    LongExtended,
    /// A list of TLVs, each a type, a length and a value (RFC 6929).
    Tlv,
}

/// A value read as its data type. [`Value::decode`] reads one, and
/// [`Value::to_attribute`] constructs an attribute that holds it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// [`DataType::Text`].
    Text(String),
    /// [`DataType::String`] and [`DataType::Concat`].
    String(Vec<u8>),
    /// [`DataType::Address`].
    Address(Ipv4Addr),
    /// [`DataType::Integer`].
    Integer(u32),
    /// [`DataType::Enum`].
    Enum(u32),
    /// [`DataType::Time`], in seconds since 1970.
    Time(u32),
    /// [`DataType::Integer64`].
    Integer64(u64),
    /// [`DataType::Ipv6Address`].
    Ipv6Address(Ipv6Addr),
    /// [`DataType::Ipv6Prefix`]: `length` bits of `prefix`, with the bits
    /// past them zero.
    Ipv6Prefix {
        /// Number of significant prefix bits.
        length: u8,
        /// Address with all remaining bits zero.
        prefix: Ipv6Addr,
    },
    /// [`DataType::Ipv4Prefix`]: `length` bits of `prefix`, with the bits
    /// past them zero.
    Ipv4Prefix {
        /// Number of significant prefix bits.
        length: u8,
        /// Address with all remaining bits zero.
        prefix: Ipv4Addr,
    },
    /// [`DataType::InterfaceId`].
    InterfaceId([u8; 8]),
    /// [`DataType::Vsa`].
    Vsa(Vsa),
    /// [`DataType::Evs`].
    Evs(Evs),
    /// [`DataType::Extended`]: the Extended-Type and the bytes after it.
    Extended {
        /// Extended-Type number.
        ext_type: u8,
        /// Opaque value bytes.
        data: Vec<u8>,
    },
    /// [`DataType::LongExtended`]: the Extended-Type, whether the More
    /// flag is set, and this fragment's bytes.
    LongExtended {
        /// Extended-Type number.
        ext_type: u8,
        /// Whether another fragment follows.
        more: bool,
        /// Opaque value bytes.
        data: Vec<u8>,
    },
    /// [`DataType::Tlv`]: the TLVs, each as an [`Attribute`]. Their
    /// values are left as bytes; read a nested TLV list with
    /// [`Value::decode`] again.
    Tlv(Vec<Attribute>),
}

impl Value {
    /// Reads `b` as `data_type`. As RFC 6929 asks, an extended, long
    /// extended, extended vendor-specific or TLV value needs at least one
    /// byte after its header, each TLV in a list is at least 3 bytes
    /// long, and a long extended fragment with the More flag is full
    /// length. A Vendor-Specific value needs at least one byte after the
    /// vendor number (RFC 2865). An IPv4 prefix of 0.0.0.0 must have
    /// length 32 (RFC 8044).
    pub fn decode(data_type: DataType, b: &[u8]) -> Result<Value, Error> {
        let fixed = |n: usize| if b.len() == n { Ok(()) } else { Err(Error::ValueLength(b.len())) };
        Ok(match data_type {
            DataType::Text => Value::Text(std::str::from_utf8(b).map_err(|_| Error::Text)?.to_string()),
            DataType::String | DataType::Concat => Value::String(b.to_vec()),
            DataType::Address => {
                fixed(4)?;
                Value::Address(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            DataType::Integer | DataType::Enum | DataType::Time => {
                fixed(4)?;
                let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                match data_type {
                    DataType::Integer => Value::Integer(n),
                    DataType::Enum => Value::Enum(n),
                    _ => Value::Time(n),
                }
            }
            DataType::Integer64 => {
                fixed(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                Value::Integer64(u64::from_be_bytes(a))
            }
            DataType::Ipv6Address => {
                fixed(16)?;
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                Value::Ipv6Address(Ipv6Addr::from(a))
            }
            DataType::Ipv6Prefix => {
                // Reserved, length, then up to 16 bytes of prefix. The
                // reserved byte is ignored on receipt.
                if b.len() < 2 || b.len() > 18 {
                    return Err(Error::ValueLength(b.len()));
                }
                let length = b[1];
                let bytes = &b[2..];
                if length > 128 || bytes.len() < usize::from(length).div_ceil(8) {
                    return Err(Error::Prefix);
                }
                let mut a = [0u8; 16];
                a[..bytes.len()].copy_from_slice(bytes);
                if mask(&a, length) != a {
                    return Err(Error::Prefix);
                }
                Value::Ipv6Prefix { length, prefix: Ipv6Addr::from(a) }
            }
            DataType::Ipv4Prefix => {
                fixed(6)?;
                let length = b[1];
                let a = [b[2], b[3], b[4], b[5]];
                if length > 32 || mask(&a, length) != a || (a == [0; 4] && length != 32) {
                    return Err(Error::Prefix);
                }
                Value::Ipv4Prefix { length, prefix: Ipv4Addr::from(a) }
            }
            DataType::InterfaceId => {
                fixed(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                Value::InterfaceId(a)
            }
            DataType::Vsa => Value::Vsa(Vsa::parse(b)?),
            DataType::Evs => Value::Evs(Evs::parse(b)?),
            DataType::Extended => match b {
                [ext_type, data @ ..] if !data.is_empty() => {
                    Value::Extended { ext_type: *ext_type, data: data.to_vec() }
                }
                _ => return Err(Error::ValueLength(b.len())),
            },
            DataType::LongExtended => {
                let (ext_type, more, data) = long_fragment(b)?;
                Value::LongExtended { ext_type, more, data: data.to_vec() }
            }
            DataType::Tlv => {
                if b.is_empty() {
                    return Err(Error::ValueLength(0));
                }
                Value::Tlv(parse_attributes(b, 3).map_err(|_| Error::Nested)?)
            }
        })
    }

    /// The data type this value reads back as. [`Value::String`] gives
    /// [`DataType::String`], which reads the same bytes as
    /// [`DataType::Concat`].
    pub fn data_type(&self) -> DataType {
        match self {
            Value::Text(_) => DataType::Text,
            Value::String(_) => DataType::String,
            Value::Address(_) => DataType::Address,
            Value::Integer(_) => DataType::Integer,
            Value::Enum(_) => DataType::Enum,
            Value::Time(_) => DataType::Time,
            Value::Integer64(_) => DataType::Integer64,
            Value::Ipv6Address(_) => DataType::Ipv6Address,
            Value::Ipv6Prefix { .. } => DataType::Ipv6Prefix,
            Value::Ipv4Prefix { .. } => DataType::Ipv4Prefix,
            Value::InterfaceId(_) => DataType::InterfaceId,
            Value::Vsa(_) => DataType::Vsa,
            Value::Evs(_) => DataType::Evs,
            Value::Extended { .. } => DataType::Extended,
            Value::LongExtended { .. } => DataType::LongExtended,
            Value::Tlv(_) => DataType::Tlv,
        }
    }

    /// Makes a TLV or vendor attribute using this value's data type.
    /// Refuses values that exceed [`MAX_VALUE`] or would read back changed.
    /// Use [`Attribute::from_value`] for the standard attribute dictionary.
    pub fn to_attribute(&self, kind: u8) -> Option<Attribute> {
        Attribute::from_value_as(kind, self.data_type(), self)
    }

    fn encode(&self) -> Option<Vec<u8>> {
        if self.encoded_len() > MAX_VALUE {
            return None;
        }
        let out = self.raw_bytes()?;
        (Value::decode(self.data_type(), &out).as_ref() == Ok(self)).then_some(out)
    }

    /// How many bytes [`Value::raw_bytes`] writes, worked out without
    /// writing them.
    fn encoded_len(&self) -> usize {
        match self {
            Value::Text(s) => s.len(),
            Value::String(b) => b.len(),
            Value::Address(_) | Value::Integer(_) | Value::Enum(_) | Value::Time(_) => 4,
            Value::Integer64(_) | Value::InterfaceId(_) => 8,
            Value::Ipv6Address(_) => 16,
            Value::Ipv6Prefix { length, .. } => 2 + usize::from(*length).div_ceil(8),
            Value::Ipv4Prefix { .. } => 6,
            Value::Vsa(v) => v.data.len().saturating_add(4),
            Value::Evs(e) => e.data.len().saturating_add(5),
            Value::Extended { data, .. } => data.len().saturating_add(1),
            Value::LongExtended { data, .. } => data.len().saturating_add(2),
            Value::Tlv(tlvs) => attributes_len(tlvs),
        }
    }

    /// The value's bytes, unchecked. Call it only once
    /// [`Value::encoded_len`] is at most [`MAX_VALUE`].
    fn raw_bytes(&self) -> Option<Vec<u8>> {
        Some(match self {
            Value::Text(s) => s.as_bytes().to_vec(),
            Value::String(b) => b.clone(),
            Value::Address(a) => a.octets().to_vec(),
            Value::Integer(n) | Value::Enum(n) | Value::Time(n) => n.to_be_bytes().to_vec(),
            Value::Integer64(n) => n.to_be_bytes().to_vec(),
            Value::Ipv6Address(a) => a.octets().to_vec(),
            Value::Ipv6Prefix { length, prefix } => {
                if *length > 128 || mask(&prefix.octets(), *length) != prefix.octets() {
                    return None;
                }
                let length = *length;
                let a = prefix.octets();
                let mut out = vec![0, length];
                out.extend_from_slice(&a[..usize::from(length).div_ceil(8)]);
                out
            }
            Value::Ipv4Prefix { length, prefix } => {
                if *length > 32 || mask(&prefix.octets(), *length) != prefix.octets()
                    || (prefix.is_unspecified() && *length != 32) {
                    return None;
                }
                let a = prefix.octets();
                let length = *length;
                let mut out = vec![0, length];
                out.extend_from_slice(&a);
                out
            }
            Value::InterfaceId(a) => a.to_vec(),
            Value::Vsa(v) => v.to_bytes().ok()?,
            Value::Evs(e) => e.to_bytes().ok()?,
            Value::Extended { ext_type, data } => {
                let mut out = vec![*ext_type];
                out.extend_from_slice(data);
                out
            }
            Value::LongExtended { ext_type, more, data } => {
                let mut out = vec![*ext_type, if *more { MORE_FLAG } else { 0 }];
                out.extend_from_slice(data);
                out
            }
            Value::Tlv(tlvs) => {
                let mut out = Vec::new();
                write_attributes(&mut out, tlvs)?;
                out
            }
        })
    }
}

/// `a` with the bits past the first `length` cleared.
fn mask<const N: usize>(a: &[u8; N], length: u8) -> [u8; N] {
    let mut out = *a;
    let length = usize::from(length);
    for (i, byte) in out.iter_mut().enumerate() {
        let keep = length.saturating_sub(i * 8).min(8);
        // keep is 0..=8; shifting 0xff00 keeps that many high bits.
        *byte &= (0xff00u16 >> keep) as u8;
    }
    out
}

/// A Vendor-Specific attribute's value (type 26): the vendor's number,
/// from the IANA list of private enterprise numbers, and its bytes. RFC
/// 2865 suggests vendors lay their bytes out as sub-attributes, and most
/// do; [`Vsa::sub_attributes`] reads them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Vsa {
    /// The vendor's private enterprise number. RFC 2865 says its high
    /// byte is 0; this module keeps whatever came.
    pub vendor: u32,
    /// The vendor's bytes.
    pub data: Vec<u8>,
}

impl Wire for Vsa {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a vendor value. Refuses fewer than 5 bytes or more than
    /// [`MAX_VALUE`] bytes. Keeps the vendor number and opaque data.
    fn parse(b: &[u8]) -> Result<Vsa, Error> {
        if !(5..=MAX_VALUE).contains(&b.len()) {
            return Err(Error::ValueLength(b.len()));
        }
        Ok(Vsa { vendor: u32::from_be_bytes([b[0], b[1], b[2], b[3]]), data: b[4..].to_vec() })
    }

    /// Appends the vendor fields and data. Refuses empty data or values
    /// over [`MAX_VALUE`]. Leaves the destination unchanged on error.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        if self.data.is_empty() || self.data.len() > MAX_VALUE - 4 {
            return Err(Error::Unwritable);
        }
        let mut out = self.vendor.to_be_bytes().to_vec();
        out.extend_from_slice(&self.data);
        destination.extend_from_slice(&out);
        Ok(())
    }
}

impl Vsa {
    /// The vendor's bytes read as sub-attributes, each a 1-byte type, a
    /// 1-byte length (2 or more, counting both) and a value, as RFC 2865
    /// suggests. Vendors that lay their bytes out another way give
    /// [`Error::Nested`] or a wrong reading.
    pub fn sub_attributes(&self) -> Result<Vec<Attribute>, Error> {
        parse_attributes(&self.data, 2).map_err(|_| Error::Nested)
    }

    /// A Vendor-Specific value for `vendor` holding these sub-attributes.
    /// It returns `None` if there are none, since a Vendor-Specific value
    /// needs at least one byte after the vendor number, or if they would
    /// not fit in one attribute with the vendor number.
    pub fn from_sub_attributes(vendor: u32, attributes: &[Attribute]) -> Option<Vsa> {
        let n = attributes_len(attributes);
        if n == 0 || n > MAX_VALUE - 4 {
            return None;
        }
        let mut data = Vec::with_capacity(n);
        write_attributes(&mut data, attributes)?;
        Some(Vsa { vendor, data })
    }
}

/// An extended vendor-specific value (RFC 6929, section 2.4): what
/// Extended-Type 26 carries in any of the extended attribute spaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Evs {
    /// The vendor's private enterprise number.
    pub vendor: u32,
    /// The vendor's attribute type.
    pub evs_type: u8,
    /// The vendor's bytes.
    pub data: Vec<u8>,
}

impl Wire for Evs {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a vendor value. Refuses fewer than 6 bytes or more than
    /// [`MAX_LONG_EXTENDED_VALUE`] bytes. Keeps the vendor number and opaque data.
    fn parse(b: &[u8]) -> Result<Evs, Error> {
        if !(6..=MAX_LONG_EXTENDED_VALUE).contains(&b.len()) {
            return Err(Error::ValueLength(b.len()));
        }
        Ok(Evs { vendor: u32::from_be_bytes([b[0], b[1], b[2], b[3]]), evs_type: b[4], data: b[5..].to_vec() })
    }

    /// Appends the vendor fields and data. Refuses empty data or values
    /// over [`MAX_LONG_EXTENDED_VALUE`]. Leaves the destination unchanged on error.
    fn write(&self, destination: &mut Vec<u8>) -> Result<(), Error> {
        if self.data.is_empty() || self.data.len() > MAX_LONG_EXTENDED_VALUE - 5 {
            return Err(Error::Unwritable);
        }
        let mut out = self.vendor.to_be_bytes().to_vec();
        out.push(self.evs_type);
        out.extend_from_slice(&self.data);
        destination.extend_from_slice(&out);
        Ok(())
    }
}

/// The Extended-Type that carries extended vendor-specific values
/// ([`Evs`]) in each extended attribute space.
pub const EXTENDED_VENDOR_SPECIFIC: u8 = 26;

/// The first reserved Extended-Type: RFC 6929 (section 2.1) reserves 241
/// to 255, and says they must not be used.
pub const RESERVED_EXTENDED_TYPES: u8 = 241;

/// One extended attribute (RFC 6929), with a long one's fragments joined:
/// which space it is in, its Extended-Type, and its value's bytes.
/// [`Packet::extended`] reads them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Extended {
    /// The attribute type: 241 to 244 for extended attributes, 245 and 246
    /// for long extended ones.
    pub kind: u8,
    /// The Extended-Type, such as [`EXTENDED_VENDOR_SPECIFIC`]. RFC 6929
    /// reserves 241 to 255.
    pub ext_type: u8,
    /// The value's bytes.
    pub data: Vec<u8>,
}

impl Extended {
    /// Whether this is a long extended attribute, whose value may span
    /// several attributes.
    pub fn is_long(&self) -> bool {
        matches!(self.kind, attr::LONG_EXTENDED_TYPE_1 | attr::LONG_EXTENDED_TYPE_2)
    }

    /// The value read as an extended vendor-specific value, if the
    /// Extended-Type is [`EXTENDED_VENDOR_SPECIFIC`].
    pub fn evs(&self) -> Option<Result<Evs, Error>> {
        (self.ext_type == EXTENDED_VENDOR_SPECIFIC).then(|| Evs::parse(&self.data))
    }

    /// The attributes that carry this value. A long value is split into
    /// fragments of [`MAX_LONG_FRAGMENT`] bytes, all but the last with the
    /// More flag. It returns `None` if `kind` is not 241 to 246, the
    /// Extended-Type is 241 to 255 (RFC 6929, section 2.1, reserves
    /// them), the value is empty (RFC 6929 asks for at least one byte),
    /// or the value is longer than [`MAX_EXTENDED_VALUE`] (for 241 to
    /// 244) or [`MAX_LONG_EXTENDED_VALUE`] (for 245 and 246).
    /// [`Packet::extended`] still reads a reserved Extended-Type, so a
    /// world can see what came.
    pub fn to_attributes(&self) -> Option<Vec<Attribute>> {
        if self.data.is_empty() || self.ext_type >= RESERVED_EXTENDED_TYPES {
            return None;
        }
        match self.kind {
            attr::EXTENDED_TYPE_1..=attr::EXTENDED_TYPE_4 => {
                if self.data.len() > MAX_EXTENDED_VALUE {
                    return None;
                }
                let mut value = vec![self.ext_type];
                value.extend_from_slice(&self.data);
                Some(vec![Attribute { kind: self.kind, value }])
            }
            attr::LONG_EXTENDED_TYPE_1 | attr::LONG_EXTENDED_TYPE_2 => {
                if self.data.len() > MAX_LONG_EXTENDED_VALUE {
                    return None;
                }
                let chunks: Vec<&[u8]> = self.data.chunks(MAX_LONG_FRAGMENT).collect();
                let last = chunks.len() - 1;
                let out = chunks
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        let mut value = vec![self.ext_type, if i < last { MORE_FLAG } else { 0 }];
                        value.extend_from_slice(c);
                        Attribute { kind: self.kind, value }
                    })
                    .collect();
                Some(out)
            }
            _ => None,
        }
    }
}

/// Attribute type numbers: every standard type from 1 to 101 in the IANA
/// registry, and the extended types of RFC 6929. Each is in the
/// [`DICTIONARY`] under its RFC name, such as User-Name for
/// [`attr::USER_NAME`].
pub mod attr {
    /// The USER-NAME attribute type.
    pub const USER_NAME: u8 = 1;
    /// The USER-PASSWORD attribute type.
    pub const USER_PASSWORD: u8 = 2;
    /// The CHAP-PASSWORD attribute type.
    pub const CHAP_PASSWORD: u8 = 3;
    /// The NAS-IP-ADDRESS attribute type.
    pub const NAS_IP_ADDRESS: u8 = 4;
    /// The NAS-PORT attribute type.
    pub const NAS_PORT: u8 = 5;
    /// The SERVICE-TYPE attribute type.
    pub const SERVICE_TYPE: u8 = 6;
    /// The FRAMED-PROTOCOL attribute type.
    pub const FRAMED_PROTOCOL: u8 = 7;
    /// The FRAMED-IP-ADDRESS attribute type.
    pub const FRAMED_IP_ADDRESS: u8 = 8;
    /// The FRAMED-IP-NETMASK attribute type.
    pub const FRAMED_IP_NETMASK: u8 = 9;
    /// The FRAMED-ROUTING attribute type.
    pub const FRAMED_ROUTING: u8 = 10;
    /// The FILTER-ID attribute type.
    pub const FILTER_ID: u8 = 11;
    /// The FRAMED-MTU attribute type.
    pub const FRAMED_MTU: u8 = 12;
    /// The FRAMED-COMPRESSION attribute type.
    pub const FRAMED_COMPRESSION: u8 = 13;
    /// The LOGIN-IP-HOST attribute type.
    pub const LOGIN_IP_HOST: u8 = 14;
    /// The LOGIN-SERVICE attribute type.
    pub const LOGIN_SERVICE: u8 = 15;
    /// The LOGIN-TCP-PORT attribute type.
    pub const LOGIN_TCP_PORT: u8 = 16;
    /// The REPLY-MESSAGE attribute type.
    pub const REPLY_MESSAGE: u8 = 18;
    /// The CALLBACK-NUMBER attribute type.
    pub const CALLBACK_NUMBER: u8 = 19;
    /// The CALLBACK-ID attribute type.
    pub const CALLBACK_ID: u8 = 20;
    /// The FRAMED-ROUTE attribute type.
    pub const FRAMED_ROUTE: u8 = 22;
    /// The FRAMED-IPX-NETWORK attribute type.
    pub const FRAMED_IPX_NETWORK: u8 = 23;
    /// The STATE attribute type.
    pub const STATE: u8 = 24;
    /// The CLASS attribute type.
    pub const CLASS: u8 = 25;
    /// The VENDOR-SPECIFIC attribute type.
    pub const VENDOR_SPECIFIC: u8 = 26;
    /// The SESSION-TIMEOUT attribute type.
    pub const SESSION_TIMEOUT: u8 = 27;
    /// The IDLE-TIMEOUT attribute type.
    pub const IDLE_TIMEOUT: u8 = 28;
    /// The TERMINATION-ACTION attribute type.
    pub const TERMINATION_ACTION: u8 = 29;
    /// The CALLED-STATION-ID attribute type.
    pub const CALLED_STATION_ID: u8 = 30;
    /// The CALLING-STATION-ID attribute type.
    pub const CALLING_STATION_ID: u8 = 31;
    /// The NAS-IDENTIFIER attribute type.
    pub const NAS_IDENTIFIER: u8 = 32;
    /// The PROXY-STATE attribute type.
    pub const PROXY_STATE: u8 = 33;
    /// The LOGIN-LAT-SERVICE attribute type.
    pub const LOGIN_LAT_SERVICE: u8 = 34;
    /// The LOGIN-LAT-NODE attribute type.
    pub const LOGIN_LAT_NODE: u8 = 35;
    /// The LOGIN-LAT-GROUP attribute type.
    pub const LOGIN_LAT_GROUP: u8 = 36;
    /// The FRAMED-APPLETALK-LINK attribute type.
    pub const FRAMED_APPLETALK_LINK: u8 = 37;
    /// The FRAMED-APPLETALK-NETWORK attribute type.
    pub const FRAMED_APPLETALK_NETWORK: u8 = 38;
    /// The FRAMED-APPLETALK-ZONE attribute type.
    pub const FRAMED_APPLETALK_ZONE: u8 = 39;
    /// The ACCT-STATUS-TYPE attribute type.
    pub const ACCT_STATUS_TYPE: u8 = 40;
    /// The ACCT-DELAY-TIME attribute type.
    pub const ACCT_DELAY_TIME: u8 = 41;
    /// The ACCT-INPUT-OCTETS attribute type.
    pub const ACCT_INPUT_OCTETS: u8 = 42;
    /// The ACCT-OUTPUT-OCTETS attribute type.
    pub const ACCT_OUTPUT_OCTETS: u8 = 43;
    /// The ACCT-SESSION-ID attribute type.
    pub const ACCT_SESSION_ID: u8 = 44;
    /// The ACCT-AUTHENTIC attribute type.
    pub const ACCT_AUTHENTIC: u8 = 45;
    /// The ACCT-SESSION-TIME attribute type.
    pub const ACCT_SESSION_TIME: u8 = 46;
    /// The ACCT-INPUT-PACKETS attribute type.
    pub const ACCT_INPUT_PACKETS: u8 = 47;
    /// The ACCT-OUTPUT-PACKETS attribute type.
    pub const ACCT_OUTPUT_PACKETS: u8 = 48;
    /// The ACCT-TERMINATE-CAUSE attribute type.
    pub const ACCT_TERMINATE_CAUSE: u8 = 49;
    /// The ACCT-MULTI-SESSION-ID attribute type.
    pub const ACCT_MULTI_SESSION_ID: u8 = 50;
    /// The ACCT-LINK-COUNT attribute type.
    pub const ACCT_LINK_COUNT: u8 = 51;
    /// The ACCT-INPUT-GIGAWORDS attribute type.
    pub const ACCT_INPUT_GIGAWORDS: u8 = 52;
    /// The ACCT-OUTPUT-GIGAWORDS attribute type.
    pub const ACCT_OUTPUT_GIGAWORDS: u8 = 53;
    /// The EVENT-TIMESTAMP attribute type.
    pub const EVENT_TIMESTAMP: u8 = 55;
    /// The EGRESS-VLANID attribute type.
    pub const EGRESS_VLANID: u8 = 56;
    /// The INGRESS-FILTERS attribute type.
    pub const INGRESS_FILTERS: u8 = 57;
    /// The EGRESS-VLAN-NAME attribute type.
    pub const EGRESS_VLAN_NAME: u8 = 58;
    /// The USER-PRIORITY-TABLE attribute type.
    pub const USER_PRIORITY_TABLE: u8 = 59;
    /// The CHAP-CHALLENGE attribute type.
    pub const CHAP_CHALLENGE: u8 = 60;
    /// The NAS-PORT-TYPE attribute type.
    pub const NAS_PORT_TYPE: u8 = 61;
    /// The PORT-LIMIT attribute type.
    pub const PORT_LIMIT: u8 = 62;
    /// The LOGIN-LAT-PORT attribute type.
    pub const LOGIN_LAT_PORT: u8 = 63;
    /// The TUNNEL-TYPE attribute type.
    pub const TUNNEL_TYPE: u8 = 64;
    /// The TUNNEL-MEDIUM-TYPE attribute type.
    pub const TUNNEL_MEDIUM_TYPE: u8 = 65;
    /// The TUNNEL-CLIENT-ENDPOINT attribute type.
    pub const TUNNEL_CLIENT_ENDPOINT: u8 = 66;
    /// The TUNNEL-SERVER-ENDPOINT attribute type.
    pub const TUNNEL_SERVER_ENDPOINT: u8 = 67;
    /// The ACCT-TUNNEL-CONNECTION attribute type.
    pub const ACCT_TUNNEL_CONNECTION: u8 = 68;
    /// The TUNNEL-PASSWORD attribute type.
    pub const TUNNEL_PASSWORD: u8 = 69;
    /// The ARAP-PASSWORD attribute type.
    pub const ARAP_PASSWORD: u8 = 70;
    /// The ARAP-FEATURES attribute type.
    pub const ARAP_FEATURES: u8 = 71;
    /// The ARAP-ZONE-ACCESS attribute type.
    pub const ARAP_ZONE_ACCESS: u8 = 72;
    /// The ARAP-SECURITY attribute type.
    pub const ARAP_SECURITY: u8 = 73;
    /// The ARAP-SECURITY-DATA attribute type.
    pub const ARAP_SECURITY_DATA: u8 = 74;
    /// The PASSWORD-RETRY attribute type.
    pub const PASSWORD_RETRY: u8 = 75;
    /// The PROMPT attribute type.
    pub const PROMPT: u8 = 76;
    /// The CONNECT-INFO attribute type.
    pub const CONNECT_INFO: u8 = 77;
    /// The CONFIGURATION-TOKEN attribute type.
    pub const CONFIGURATION_TOKEN: u8 = 78;
    /// The EAP-MESSAGE attribute type.
    pub const EAP_MESSAGE: u8 = 79;
    /// The MESSAGE-AUTHENTICATOR attribute type.
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
    /// The TUNNEL-PRIVATE-GROUP-ID attribute type.
    pub const TUNNEL_PRIVATE_GROUP_ID: u8 = 81;
    /// The TUNNEL-ASSIGNMENT-ID attribute type.
    pub const TUNNEL_ASSIGNMENT_ID: u8 = 82;
    /// The TUNNEL-PREFERENCE attribute type.
    pub const TUNNEL_PREFERENCE: u8 = 83;
    /// The ARAP-CHALLENGE-RESPONSE attribute type.
    pub const ARAP_CHALLENGE_RESPONSE: u8 = 84;
    /// The ACCT-INTERIM-INTERVAL attribute type.
    pub const ACCT_INTERIM_INTERVAL: u8 = 85;
    /// The ACCT-TUNNEL-PACKETS-LOST attribute type.
    pub const ACCT_TUNNEL_PACKETS_LOST: u8 = 86;
    /// The NAS-PORT-ID attribute type.
    pub const NAS_PORT_ID: u8 = 87;
    /// The FRAMED-POOL attribute type.
    pub const FRAMED_POOL: u8 = 88;
    /// The CUI attribute type.
    pub const CUI: u8 = 89;
    /// The TUNNEL-CLIENT-AUTH-ID attribute type.
    pub const TUNNEL_CLIENT_AUTH_ID: u8 = 90;
    /// The TUNNEL-SERVER-AUTH-ID attribute type.
    pub const TUNNEL_SERVER_AUTH_ID: u8 = 91;
    /// The NAS-FILTER-RULE attribute type.
    pub const NAS_FILTER_RULE: u8 = 92;
    /// The ORIGINATING-LINE-INFO attribute type.
    pub const ORIGINATING_LINE_INFO: u8 = 94;
    /// The NAS-IPV6-ADDRESS attribute type.
    pub const NAS_IPV6_ADDRESS: u8 = 95;
    /// The FRAMED-INTERFACE-ID attribute type.
    pub const FRAMED_INTERFACE_ID: u8 = 96;
    /// The FRAMED-IPV6-PREFIX attribute type.
    pub const FRAMED_IPV6_PREFIX: u8 = 97;
    /// The LOGIN-IPV6-HOST attribute type.
    pub const LOGIN_IPV6_HOST: u8 = 98;
    /// The FRAMED-IPV6-ROUTE attribute type.
    pub const FRAMED_IPV6_ROUTE: u8 = 99;
    /// The FRAMED-IPV6-POOL attribute type.
    pub const FRAMED_IPV6_POOL: u8 = 100;
    /// The ERROR-CAUSE attribute type.
    pub const ERROR_CAUSE: u8 = 101;
    /// The EXTENDED-TYPE-1 attribute type.
    pub const EXTENDED_TYPE_1: u8 = 241;
    /// The EXTENDED-TYPE-2 attribute type.
    pub const EXTENDED_TYPE_2: u8 = 242;
    /// The EXTENDED-TYPE-3 attribute type.
    pub const EXTENDED_TYPE_3: u8 = 243;
    /// The EXTENDED-TYPE-4 attribute type.
    pub const EXTENDED_TYPE_4: u8 = 244;
    /// The LONG-EXTENDED-TYPE-1 attribute type.
    pub const LONG_EXTENDED_TYPE_1: u8 = 245;
    /// The LONG-EXTENDED-TYPE-2 attribute type.
    pub const LONG_EXTENDED_TYPE_2: u8 = 246;
}

/// What the dictionary knows about one attribute type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeInfo {
    /// The type number.
    pub kind: u8,
    /// The name, as its RFC writes it.
    pub name: &'static str,
    /// How its value is read.
    pub data_type: DataType,
}

const fn info(kind: u8, name: &'static str, data_type: DataType) -> AttributeInfo {
    AttributeInfo { kind, name, data_type }
}

/// The standard attributes, by type number, with the data types the IANA
/// registry gives them. They come from RFC 2865, RFC 2866, RFC 2867, RFC
/// 2868, RFC 2869, RFC 3162, RFC 4372, RFC 4675, RFC 4849, RFC 5176, RFC
/// 6929 and RFC 7155. User-Password, CHAP-Password, ARAP-Password and
/// Tunnel-Password are strings, since their values are hidden or hashed
/// with the shared secret. The RFC 2868 tunnel attributes are strings
/// too: their values start with a tag byte, which the caller reads.
pub const DICTIONARY: &[AttributeInfo] = {
    use DataType::*;
    use attr::*;
    &[
        info(USER_NAME, "User-Name", Text),
        info(USER_PASSWORD, "User-Password", String),
        info(CHAP_PASSWORD, "CHAP-Password", String),
        info(NAS_IP_ADDRESS, "NAS-IP-Address", Address),
        info(NAS_PORT, "NAS-Port", Integer),
        info(SERVICE_TYPE, "Service-Type", Enum),
        info(FRAMED_PROTOCOL, "Framed-Protocol", Enum),
        info(FRAMED_IP_ADDRESS, "Framed-IP-Address", Address),
        info(FRAMED_IP_NETMASK, "Framed-IP-Netmask", Address),
        info(FRAMED_ROUTING, "Framed-Routing", Enum),
        info(FILTER_ID, "Filter-Id", Text),
        info(FRAMED_MTU, "Framed-MTU", Integer),
        info(FRAMED_COMPRESSION, "Framed-Compression", Enum),
        info(LOGIN_IP_HOST, "Login-IP-Host", Address),
        info(LOGIN_SERVICE, "Login-Service", Enum),
        info(LOGIN_TCP_PORT, "Login-TCP-Port", Integer),
        info(REPLY_MESSAGE, "Reply-Message", Text),
        info(CALLBACK_NUMBER, "Callback-Number", Text),
        info(CALLBACK_ID, "Callback-Id", Text),
        info(FRAMED_ROUTE, "Framed-Route", Text),
        info(FRAMED_IPX_NETWORK, "Framed-IPX-Network", Address),
        info(STATE, "State", String),
        info(CLASS, "Class", String),
        info(VENDOR_SPECIFIC, "Vendor-Specific", Vsa),
        info(SESSION_TIMEOUT, "Session-Timeout", Integer),
        info(IDLE_TIMEOUT, "Idle-Timeout", Integer),
        info(TERMINATION_ACTION, "Termination-Action", Enum),
        info(CALLED_STATION_ID, "Called-Station-Id", Text),
        info(CALLING_STATION_ID, "Calling-Station-Id", Text),
        info(NAS_IDENTIFIER, "NAS-Identifier", Text),
        info(PROXY_STATE, "Proxy-State", String),
        info(LOGIN_LAT_SERVICE, "Login-LAT-Service", Text),
        info(LOGIN_LAT_NODE, "Login-LAT-Node", Text),
        info(LOGIN_LAT_GROUP, "Login-LAT-Group", String),
        info(FRAMED_APPLETALK_LINK, "Framed-AppleTalk-Link", Integer),
        info(FRAMED_APPLETALK_NETWORK, "Framed-AppleTalk-Network", Integer),
        info(FRAMED_APPLETALK_ZONE, "Framed-AppleTalk-Zone", Text),
        info(ACCT_STATUS_TYPE, "Acct-Status-Type", Enum),
        info(ACCT_DELAY_TIME, "Acct-Delay-Time", Integer),
        info(ACCT_INPUT_OCTETS, "Acct-Input-Octets", Integer),
        info(ACCT_OUTPUT_OCTETS, "Acct-Output-Octets", Integer),
        info(ACCT_SESSION_ID, "Acct-Session-Id", Text),
        info(ACCT_AUTHENTIC, "Acct-Authentic", Enum),
        info(ACCT_SESSION_TIME, "Acct-Session-Time", Integer),
        info(ACCT_INPUT_PACKETS, "Acct-Input-Frames::<Packet>", Integer),
        info(ACCT_OUTPUT_PACKETS, "Acct-Output-Frames::<Packet>", Integer),
        info(ACCT_TERMINATE_CAUSE, "Acct-Terminate-Cause", Enum),
        info(ACCT_MULTI_SESSION_ID, "Acct-Multi-Session-Id", Text),
        info(ACCT_LINK_COUNT, "Acct-Link-Count", Integer),
        info(ACCT_INPUT_GIGAWORDS, "Acct-Input-Gigawords", Integer),
        info(ACCT_OUTPUT_GIGAWORDS, "Acct-Output-Gigawords", Integer),
        info(EVENT_TIMESTAMP, "Event-Timestamp", Time),
        info(EGRESS_VLANID, "Egress-VLANID", Integer),
        info(INGRESS_FILTERS, "Ingress-Filters", Enum),
        info(EGRESS_VLAN_NAME, "Egress-VLAN-Name", Text),
        info(USER_PRIORITY_TABLE, "User-Priority-Table", String),
        info(CHAP_CHALLENGE, "CHAP-Challenge", String),
        info(NAS_PORT_TYPE, "NAS-Port-Type", Enum),
        info(PORT_LIMIT, "Port-Limit", Integer),
        info(LOGIN_LAT_PORT, "Login-LAT-Port", Text),
        info(TUNNEL_TYPE, "Tunnel-Type", String),
        info(TUNNEL_MEDIUM_TYPE, "Tunnel-Medium-Type", String),
        info(TUNNEL_CLIENT_ENDPOINT, "Tunnel-Client-Endpoint", String),
        info(TUNNEL_SERVER_ENDPOINT, "Tunnel-Server-Endpoint", String),
        info(ACCT_TUNNEL_CONNECTION, "Acct-Tunnel-Connection", Text),
        info(TUNNEL_PASSWORD, "Tunnel-Password", String),
        info(ARAP_PASSWORD, "ARAP-Password", String),
        info(ARAP_FEATURES, "ARAP-Features", String),
        info(ARAP_ZONE_ACCESS, "ARAP-Zone-Access", Enum),
        info(ARAP_SECURITY, "ARAP-Security", Integer),
        info(ARAP_SECURITY_DATA, "ARAP-Security-Data", Text),
        info(PASSWORD_RETRY, "Password-Retry", Integer),
        info(PROMPT, "Prompt", Enum),
        info(CONNECT_INFO, "Connect-Info", Text),
        info(CONFIGURATION_TOKEN, "Configuration-Token", Text),
        info(EAP_MESSAGE, "EAP-Message", Concat),
        info(MESSAGE_AUTHENTICATOR, "Message-Authenticator", String),
        info(TUNNEL_PRIVATE_GROUP_ID, "Tunnel-Private-Group-ID", String),
        info(TUNNEL_ASSIGNMENT_ID, "Tunnel-Assignment-ID", String),
        info(TUNNEL_PREFERENCE, "Tunnel-Preference", String),
        info(ARAP_CHALLENGE_RESPONSE, "ARAP-Challenge-Response", String),
        info(ACCT_INTERIM_INTERVAL, "Acct-Interim-Interval", Integer),
        info(ACCT_TUNNEL_PACKETS_LOST, "Acct-Tunnel-Frames::<Packet>-Lost", Integer),
        info(NAS_PORT_ID, "NAS-Port-Id", Text),
        info(FRAMED_POOL, "Framed-Pool", Text),
        info(CUI, "CUI", String),
        info(TUNNEL_CLIENT_AUTH_ID, "Tunnel-Client-Auth-ID", String),
        info(TUNNEL_SERVER_AUTH_ID, "Tunnel-Server-Auth-ID", String),
        info(NAS_FILTER_RULE, "NAS-Filter-Rule", Text),
        info(ORIGINATING_LINE_INFO, "Originating-Line-Info", String),
        info(NAS_IPV6_ADDRESS, "NAS-IPv6-Address", Ipv6Address),
        info(FRAMED_INTERFACE_ID, "Framed-Interface-Id", InterfaceId),
        info(FRAMED_IPV6_PREFIX, "Framed-IPv6-Prefix", Ipv6Prefix),
        info(LOGIN_IPV6_HOST, "Login-IPv6-Host", Ipv6Address),
        info(FRAMED_IPV6_ROUTE, "Framed-IPv6-Route", Text),
        info(FRAMED_IPV6_POOL, "Framed-IPv6-Pool", Text),
        info(ERROR_CAUSE, "Error-Cause", Enum),
        info(EXTENDED_TYPE_1, "Extended-Type-1", Extended),
        info(EXTENDED_TYPE_2, "Extended-Type-2", Extended),
        info(EXTENDED_TYPE_3, "Extended-Type-3", Extended),
        info(EXTENDED_TYPE_4, "Extended-Type-4", Extended),
        info(LONG_EXTENDED_TYPE_1, "Long-Extended-Type-1", LongExtended),
        info(LONG_EXTENDED_TYPE_2, "Long-Extended-Type-2", LongExtended),
    ]
};

/// The dictionary's entry for type `kind`, if it has one.
pub fn lookup(kind: u8) -> Option<&'static AttributeInfo> {
    DICTIONARY.iter().find(|i| i.kind == kind)
}

/// The dictionary's entry named `name`, ignoring ASCII case.
pub fn lookup_name(name: &str) -> Option<&'static AttributeInfo> {
    DICTIONARY.iter().find(|i| i.name.eq_ignore_ascii_case(name))
}

/// The name of value `value` of the enumerated attribute `kind`, as its
/// RFC writes it, such as "Login" for Service-Type 1. It covers
/// Service-Type, Framed-Protocol, Framed-Routing, Framed-Compression,
/// Login-Service, Termination-Action, Acct-Status-Type, Acct-Authentic,
/// Acct-Terminate-Cause, NAS-Port-Type, Prompt, Ingress-Filters and
/// Error-Cause.
pub fn enum_name(kind: u8, value: u32) -> Option<&'static str> {
    let names: &[(u32, &str)] = match kind {
        attr::SERVICE_TYPE => &[
            (1, "Login"),
            (2, "Framed"),
            (3, "Callback Login"),
            (4, "Callback Framed"),
            (5, "Outbound"),
            (6, "Administrative"),
            (7, "NAS Prompt"),
            (8, "Authenticate Only"),
            (9, "Callback NAS Prompt"),
            (10, "Call Check"),
            (11, "Callback Administrative"),
        ],
        attr::FRAMED_PROTOCOL => &[
            (1, "PPP"),
            (2, "SLIP"),
            (3, "AppleTalk Remote Access Protocol (ARAP)"),
            (4, "Gandalf proprietary SingleLink/MultiLink protocol"),
            (5, "Xylogics proprietary IPX/SLIP"),
            (6, "X.75 Synchronous"),
        ],
        attr::FRAMED_ROUTING => {
            &[(0, "None"), (1, "Send routing packets"), (2, "Listen for routing packets"), (3, "Send and Listen")]
        }
        attr::FRAMED_COMPRESSION => &[
            (0, "None"),
            (1, "VJ TCP/IP header compression"),
            (2, "IPX header compression"),
            (3, "Stac-LZS compression"),
        ],
        attr::LOGIN_SERVICE => &[
            (0, "Telnet"),
            (1, "Rlogin"),
            (2, "TCP Clear"),
            (3, "PortMaster"),
            (4, "LAT"),
            (5, "X25-PAD"),
            (6, "X25-T3POS"),
            (8, "TCP Clear Quiet"),
        ],
        attr::TERMINATION_ACTION => &[(0, "Default"), (1, "RADIUS-Request")],
        attr::ACCT_STATUS_TYPE => {
            &[(1, "Start"), (2, "Stop"), (3, "Interim-Update"), (7, "Accounting-On"), (8, "Accounting-Off")]
        }
        attr::ACCT_AUTHENTIC => &[(1, "RADIUS"), (2, "Local"), (3, "Remote")],
        attr::ACCT_TERMINATE_CAUSE => &[
            (1, "User Request"),
            (2, "Lost Carrier"),
            (3, "Lost Service"),
            (4, "Idle Timeout"),
            (5, "Session Timeout"),
            (6, "Admin Reset"),
            (7, "Admin Reboot"),
            (8, "Port Error"),
            (9, "NAS Error"),
            (10, "NAS Request"),
            (11, "NAS Reboot"),
            (12, "Port Unneeded"),
            (13, "Port Preempted"),
            (14, "Port Suspended"),
            (15, "Service Unavailable"),
            (16, "Callback"),
            (17, "User Error"),
            (18, "Host Request"),
        ],
        attr::NAS_PORT_TYPE => &[
            (0, "Async"),
            (1, "Sync"),
            (2, "ISDN Sync"),
            (3, "ISDN Async V.120"),
            (4, "ISDN Async V.110"),
            (5, "Virtual"),
            (6, "PIAFS"),
            (7, "HDLC Clear Channel"),
            (8, "X.25"),
            (9, "X.75"),
            (10, "G.3 Fax"),
            (11, "SDSL - Symmetric DSL"),
            (12, "ADSL-CAP - Asymmetric DSL, Carrierless Amplitude Phase Modulation"),
            (13, "ADSL-DMT - Asymmetric DSL, Discrete Multi-Tone"),
            (14, "IDSL - ISDN Digital Subscriber Line"),
            (15, "Ethernet"),
            (16, "xDSL - Digital Subscriber Line of unknown type"),
            (17, "Cable"),
            (18, "Wireless - Other"),
            (19, "Wireless - IEEE 802.11"),
        ],
        attr::PROMPT => &[(0, "No Echo"), (1, "Echo")],
        attr::INGRESS_FILTERS => &[(1, "Enabled"), (2, "Disabled")],
        attr::ERROR_CAUSE => &[
            (201, "Residual Session Context Removed"),
            (202, "Invalid EAP Packet (Ignored)"),
            (401, "Unsupported Attribute"),
            (402, "Missing Attribute"),
            (403, "NAS Identification Mismatch"),
            (404, "Invalid Request"),
            (405, "Unsupported Service"),
            (406, "Unsupported Extension"),
            (407, "Invalid Attribute Value"),
            (501, "Administratively Prohibited"),
            (502, "Request Not Routable (Proxy)"),
            (503, "Session Context Not Found"),
            (504, "Session Context Not Removable"),
            (505, "Other Proxy Processing Error"),
            (506, "Resources Unavailable"),
            (507, "Request Initiated"),
            (508, "Multiple Session Selection Unsupported"),
        ],
        _ => return None,
    };
    names.iter().find(|(v, _)| *v == value).map(|(_, n)| *n)
}

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::{Attribute, DataType, Error, Extended, Packet, RESERVED_EXTENDED_TYPES, Value, Vsa};
    use fictionet::stdlib::codec::Wire;

    /// Checks datagram, attribute, and extended-value round trips.
    pub fn check_datagram(data: &[u8]) {
        if let Ok(p) = Packet::parse_datagram(data) {
            // A packet read can be written, and reads back the same.
            let bytes = p.to_bytes().expect("a packet read can be written");
            assert_eq!(Packet::parse(&bytes).as_ref(), Ok(&p));
            let mut padded = bytes.clone();
            padded.extend_from_slice(&[9, 9, 9]);
            assert_eq!(Packet::parse_datagram(&padded).as_ref(), Ok(&p));
            assert_eq!(
                Packet::parse(&padded),
                Err(Error::Trailing { remaining: 3 })
            );
            for a in &p.attributes {
                // A value read as its type writes back to bytes that read the same.
                if let Ok(v) = a.decode() {
                    let t = a.info().map_or(DataType::String, |i| i.data_type);
                        assert_eq!(Value::decode(t, &v.to_attribute(1).map(|a| a.value).unwrap()), Ok(v.clone()));
                    let written = v.to_attribute(a.kind).map(|a| a.value).expect("a value read can be written");
                    assert_eq!(Value::decode(t, &written), Ok(v.clone()));
                    // A value read can be put in an attribute again, with the
                    // same bytes it came in or bytes that read the same.
                    let again = Attribute::from_value(a.kind, &v).expect("a value read can be written");
                    assert_eq!(again.decode().as_ref(), Ok(&v));
                    if let Value::Vsa(vsa) = &v
                        && let Ok(subs) = vsa.sub_attributes()
                    {
                        assert_eq!(Vsa::from_sub_attributes(vsa.vendor, &subs).as_ref(), Some(vsa));
                    }
                }
                for t in [DataType::Tlv, DataType::Ipv6Prefix, DataType::Ipv4Prefix, DataType::Evs] {
                    if let Ok(v) = Value::decode(t, &a.value) {
                            assert_eq!(Value::decode(t, &v.to_attribute(1).map(|a| a.value).unwrap()), Ok(v.clone()));
                        assert_eq!(Value::decode(t, &v.to_attribute(a.kind).map(|a| a.value).expect("a value read can be written")), Ok(v));
                    }
                }
            }
            // The valid extended attributes, joined, split again and joined
            // again. Reserved Extended-Types are read but not written.
            let ext: Vec<Extended> =
                p.extended().into_iter().flatten().filter(|e| e.ext_type < RESERVED_EXTENDED_TYPES).collect();
            let mut q = Packet::new(p.code, p.identifier, p.authenticator);
            for e in &ext {
                q.push_extended(e).unwrap();
            }
            let again: Vec<Extended> = q.extended().into_iter().map(Result::unwrap).collect();
            assert_eq!(again, ext);
            let _ = p.reply(p.code).to_bytes().expect("a reply to a packet read can be written");
        }

    }
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use super::harness::check_datagram;
    use super::*;
    use fictionet::stdlib::test_support::hex;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream,
    };
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{decode_all, mutate};


    // RFC 2865, section 7.1: User Telnet to Specified Host.
    const ACCESS_REQUEST: &str = "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb
        98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d
        93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8
        01 10 05 06 00 00 00 03";
    const ACCESS_ACCEPT: &str = "02 00 00 26 86 fe 22 0e 76 24 ba 2a 10 05 f6 bf
        9b 55 e0 b2 06 06 00 00 00 01 0f 06 00 00 00 00
        0e 06 c0 a8 01 03";
    // RFC 2865, section 7.2: Framed User Authenticating with CHAP.
    const CHAP_REQUEST: &str = "01 01 00 47 2a ee 86 f0 8d 0d 55 96 9c a5 97 8e
        0d 33 67 a2 01 08 66 6c 6f 70 73 79 03 13 16 e9
        75 57 c3 16 18 58 95 f2 93 ff 63 44 07 72 75 04
        06 c0 a8 01 10 05 06 00 00 00 14 06 06 00 00 00
        02 07 06 00 00 00 01";
    // RFC 2865, section 7.3: an Access-Challenge.
    const CHALLENGE: &str = "0b 02 00 4e 36 f3 c8 76 4a e8 c7 11 57 40 3c 0c
        71 ff 9c 45 12 30 43 68 61 6c 6c 65 6e 67 65 20
        33 32 37 36 39 34 33 30 2e 20 20 45 6e 74 65 72
        20 72 65 73 70 6f 6e 73 65 20 61 74 20 70 72 6f
        6d 70 74 2e 18 0a 33 32 37 36 39 34 33 30";

    fn decoded(p: &Packet, kind: u8) -> Value {
        p.get(kind).unwrap().decode().unwrap()
    }

    #[test]
    fn review_value_checks_have_distinct_roles() {
        let empty = Value::Tlv(vec![]);
        assert_eq!(empty.raw_bytes(), Some(vec![]));
        assert_eq!(empty.encode(), None);
        let short = Value::String(vec![1]);
        assert_eq!(short.encode(), Some(vec![1]));
        assert_eq!(Attribute::from_value(attr::CHAP_PASSWORD, &short), None);
        assert_eq!(Attribute::from_value_as(1, DataType::Integer, &short), None);
        for data_type in [DataType::String, DataType::Concat] {
            assert_eq!(Attribute::from_value_as(1, data_type, &short), Some(Attribute { kind: 1, value: vec![1] }));
        }
    }

    #[test]
    fn rfc_2865_telnet_example() {
        let bytes = hex(ACCESS_REQUEST);
        let req = Packet::parse(&bytes).unwrap();
        assert_eq!(req.code, Code::AccessRequest);
        assert_eq!(req.identifier, 0);
        assert_eq!(req.authenticator[..2], [0x0f, 0x40]);
        assert_eq!(req.attributes.len(), 4);
        assert_eq!(decoded(&req, attr::USER_NAME), Value::Text("nemo".into()));
        // The hidden password stays as its 16 bytes.
        let Value::String(pw) = decoded(&req, attr::USER_PASSWORD) else { panic!() };
        assert_eq!(pw.len(), 16);
        assert_eq!(pw[0], 0x0d);
        assert_eq!(decoded(&req, attr::NAS_IP_ADDRESS), Value::Address(Ipv4Addr::new(192, 168, 1, 16)));
        assert_eq!(decoded(&req, attr::NAS_PORT), Value::Integer(3));
        assert_eq!(req.to_bytes().unwrap(), bytes);

        let bytes = hex(ACCESS_ACCEPT);
        let accept = Packet::parse(&bytes).unwrap();
        assert_eq!(accept.code, Code::AccessAccept);
        assert_eq!(decoded(&accept, attr::SERVICE_TYPE), Value::Enum(1));
        assert_eq!(enum_name(attr::SERVICE_TYPE, 1), Some("Login"));
        assert_eq!(decoded(&accept, attr::LOGIN_SERVICE), Value::Enum(0));
        assert_eq!(enum_name(attr::LOGIN_SERVICE, 0), Some("Telnet"));
        assert_eq!(decoded(&accept, attr::LOGIN_IP_HOST), Value::Address(Ipv4Addr::new(192, 168, 1, 3)));
        assert_eq!(accept.to_bytes().unwrap(), bytes);

        // The same answer, built: its bytes match but for the
        // authenticator, which the caller computes.
        let mut built = req.reply(Code::AccessAccept);
        built.push(Attribute::from_value(attr::SERVICE_TYPE, &Value::Enum(1)).unwrap()).unwrap();
        built.push(Attribute::from_value(attr::LOGIN_SERVICE, &Value::Enum(0)).unwrap()).unwrap();
        let host = Value::Address(Ipv4Addr::new(192, 168, 1, 3));
        built.push(Attribute::from_value(attr::LOGIN_IP_HOST, &host).unwrap()).unwrap();
        assert_eq!(built.authenticator, req.authenticator);
        built.authenticator = accept.authenticator;
        assert_eq!(built.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn rfc_2865_chap_and_challenge_examples() {
        let bytes = hex(CHAP_REQUEST);
        let req = Packet::parse(&bytes).unwrap();
        assert_eq!(req.identifier, 1);
        assert_eq!(decoded(&req, attr::USER_NAME), Value::Text("flopsy".into()));
        let Value::String(chap) = decoded(&req, attr::CHAP_PASSWORD) else { panic!() };
        // A CHAP ID of 22, then the 16-byte response.
        assert_eq!((chap.len(), chap[0]), (17, 22));
        assert_eq!(decoded(&req, attr::NAS_PORT), Value::Integer(20));
        assert_eq!(decoded(&req, attr::SERVICE_TYPE), Value::Enum(2));
        assert_eq!(decoded(&req, attr::FRAMED_PROTOCOL), Value::Enum(1));
        assert_eq!(enum_name(attr::FRAMED_PROTOCOL, 1), Some("PPP"));
        assert_eq!(req.to_bytes().unwrap(), bytes);

        let bytes = hex(CHALLENGE);
        let ch = Packet::parse(&bytes).unwrap();
        assert_eq!(ch.code, Code::AccessChallenge);
        assert_eq!(
            decoded(&ch, attr::REPLY_MESSAGE),
            Value::Text("Challenge 32769430.  Enter response at prompt.".into())
        );
        assert_eq!(decoded(&ch, attr::STATE), Value::String(b"32769430".to_vec()));
        assert_eq!(ch.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn every_truncated_prefix_is_refused() {
        for s in [ACCESS_REQUEST, ACCESS_ACCEPT, CHAP_REQUEST, CHALLENGE] {
            let bytes = hex(s);
            for n in 0..bytes.len() {
                let e = Packet::parse(&bytes[..n]).unwrap_err();
                if n < HEADER_LEN {
                    assert_eq!(e, Error::Short(n));
                } else {
                    assert_eq!(e, Error::Truncated { length: bytes.len() as u16, got: n });
                }
                assert_eq!(Packet::parse_datagram(&bytes[..n]), Err(e));
            }
            contract::check_decode_with_alloc_limit(Frames::<Packet>::new, &bytes, 2 * MAX_PACKET);
            assert_eq!(decode_all(Frames::<Packet>::new, &bytes), (vec![Packet::parse(&bytes).unwrap()], None));
        }
    }

    #[test]
    fn packet_errors() {
        assert_eq!(Packet::parse(&[1, 0, 0]), Err(Error::Short(3)));
        assert_eq!(Packet::parse_datagram(&[1, 0, 0]), Err(Error::Short(3)));
        let mut b = vec![1, 0, 0, 19];
        b.extend_from_slice(&[0; 16]);
        assert_eq!(Packet::parse(&b), Err(Error::Length { length: 19, limit: MAX_PACKET }));
        assert_eq!(Packet::parse_datagram(&b), Packet::parse(&b));
        b[2..4].copy_from_slice(&4097u16.to_be_bytes());
        assert_eq!(Packet::parse(&b), Err(Error::Length { length: 4097, limit: MAX_PACKET }));
        assert_eq!(Packet::parse_datagram(&b), Packet::parse(&b));
        b[2..4].copy_from_slice(&22u16.to_be_bytes());
        assert_eq!(Packet::parse(&b), Err(Error::Truncated { length: 22, got: 20 }));
        assert_eq!(Packet::parse_datagram(&b), Packet::parse(&b));
        // An attribute of length 1, then one that runs past the length.
        b.extend_from_slice(&[1, 1]);
        assert_eq!(Packet::parse(&b), Err(Error::Attribute(20)));
        assert_eq!(Packet::parse_datagram(&b), Packet::parse(&b));
        b[21] = 3;
        assert_eq!(Packet::parse(&b), Err(Error::Attribute(20)));
        assert_eq!(Packet::parse_datagram(&b), Packet::parse(&b));
        // A lone type byte with no length.
        b[3] = 21;
        assert_eq!(Packet::parse(&b[..21]), Err(Error::Attribute(20)));
        assert_eq!(Packet::parse_datagram(&b[..21]), Packet::parse(&b[..21]));
        // Length 2 is an empty attribute. Exact parsing refuses padding.
        b[3] = 22;
        b[21] = 2;
        b.extend_from_slice(&[9, 9, 9]);
        assert_eq!(Packet::parse(&b), Err(Error::Trailing { remaining: 3 }));
        let p = Packet::parse(&b[..22]).unwrap();
        // Bytes past the length are padding.
        assert_eq!(Packet::parse_datagram(&b), Ok(p.clone()));
        assert_eq!(p.attributes, [Attribute { kind: 1, value: vec![] }]);
        assert_eq!(p.to_bytes().unwrap(), b[..22]);
        // Padding is outside the packet length limit too.
        b.resize(MAX_PACKET + 1, 9);
        assert_eq!(Packet::parse_datagram(&b), Ok(p));
        for e in [Error::Short(1), Error::Length { length: 1, limit: MAX_PACKET }, Error::Attribute(20)] {
            assert!(!e.to_string().is_empty());
        }
        assert!(!Error::Truncated { length: 1, got: 0 }.to_string().is_empty());
    }

    #[test]
    fn codes() {
        for c in 0..=255u8 {
            assert_eq!(Code::from_u8(c).to_u8(), c);
        }
        assert_eq!(Code::from_u8(43), Code::CoaRequest);
        assert_eq!(Code::CoaNak.name(), Some("CoA-NAK"));
        assert_eq!(Code::DisconnectAck.name(), Some("Disconnect-ACK"));
        assert_eq!(Code::Other(99).name(), None);
    }

    #[test]
    fn disconnect_and_coa() {
        // A Disconnect-Request for one session, which the NAS refuses with
        // Error-Cause 503, Session Context Not Found (RFC 5176).
        let mut req = Packet::new(Code::DisconnectRequest, 9, [0; 16]);
        req.push(Attribute { kind: attr::ACCT_SESSION_ID, value: b"s-1".to_vec() }).unwrap();
        req.push(Attribute { kind: attr::PROXY_STATE, value: vec![1, 2] }).unwrap();
        req.push(Attribute { kind: attr::PROXY_STATE, value: vec![3] }).unwrap();
        let req = Packet::parse(&req.to_bytes().unwrap()).unwrap();
        let mut nak = req.reply(Code::DisconnectNak);
        assert_eq!(nak.attributes.len(), 2);
        assert_eq!(nak.concat(attr::PROXY_STATE), [1, 2, 3]);
        nak.push(Attribute::from_value(attr::ERROR_CAUSE, &Value::Enum(503)).unwrap()).unwrap();
        let bytes = nak.to_bytes().unwrap();
        assert_eq!(bytes[..4], [42, 9, 0, 20 + 4 + 3 + 6]);
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(decoded(&back, attr::ERROR_CAUSE), Value::Enum(503));
        assert_eq!(enum_name(attr::ERROR_CAUSE, 503), Some("Session Context Not Found"));
        // A CoA-Request setting a new Session-Timeout, and its ACK.
        let mut coa = Packet::new(Code::CoaRequest, 10, [0; 16]);
        coa.push(Attribute::from_value(attr::SESSION_TIMEOUT, &Value::Integer(3600)).unwrap()).unwrap();
        let coa = Packet::parse(&coa.to_bytes().unwrap()).unwrap();
        assert_eq!(coa.code, Code::CoaRequest);
        assert_eq!(decoded(&coa, attr::SESSION_TIMEOUT), Value::Integer(3600));
        assert_eq!(coa.reply(Code::CoaAck).to_bytes().unwrap()[..4], [44, 10, 0, 20]);
    }

    #[test]
    fn accounting_attributes() {
        let mut p = Packet::new(Code::AccountingRequest, 1, [0; 16]);
        let values = [
            (attr::ACCT_STATUS_TYPE, Value::Enum(2)),
            (attr::ACCT_SESSION_TIME, Value::Integer(3600)),
            (attr::ACCT_INPUT_OCTETS, Value::Integer(1_000_000)),
            (attr::ACCT_TERMINATE_CAUSE, Value::Enum(1)),
            (attr::EVENT_TIMESTAMP, Value::Time(1_700_000_000)),
            (attr::ACCT_SESSION_ID, Value::Text("0001".into())),
        ];
        for (k, v) in &values {
            p.push(Attribute::from_value(*k, v).unwrap()).unwrap();
        }
        let back = Packet::parse(&p.to_bytes().unwrap()).unwrap();
        for (k, v) in &values {
            assert_eq!(&decoded(&back, *k), v);
        }
        assert_eq!(enum_name(attr::ACCT_STATUS_TYPE, 2), Some("Stop"));
        assert_eq!(enum_name(attr::ACCT_TERMINATE_CAUSE, 1), Some("User Request"));
        assert_eq!(enum_name(attr::ACCT_STATUS_TYPE, 99), None);
        assert_eq!(enum_name(attr::USER_NAME, 1), None);
    }

    #[test]
    fn every_data_type_round_trips() {
        let cases = [
            (DataType::Text, Value::Text("héllo".into())),
            (DataType::String, Value::String(vec![0, 255])),
            (DataType::Concat, Value::String(vec![1])),
            (DataType::Address, Value::Address(Ipv4Addr::new(10, 0, 0, 1))),
            (DataType::Integer, Value::Integer(u32::MAX)),
            (DataType::Enum, Value::Enum(7)),
            (DataType::Time, Value::Time(5)),
            (DataType::Integer64, Value::Integer64(u64::MAX - 1)),
            (DataType::Ipv6Address, Value::Ipv6Address("2001:db8::1".parse().unwrap())),
            (DataType::Ipv6Prefix, Value::Ipv6Prefix { length: 64, prefix: "2001:db8:1:2::".parse().unwrap() }),
            (DataType::Ipv6Prefix, Value::Ipv6Prefix { length: 0, prefix: Ipv6Addr::UNSPECIFIED }),
            (DataType::Ipv6Prefix, Value::Ipv6Prefix { length: 128, prefix: "::1".parse().unwrap() }),
            (DataType::Ipv6Prefix, Value::Ipv6Prefix { length: 3, prefix: "e000::".parse().unwrap() }),
            (DataType::Ipv4Prefix, Value::Ipv4Prefix { length: 24, prefix: Ipv4Addr::new(10, 1, 2, 0) }),
            (DataType::InterfaceId, Value::InterfaceId([1, 2, 3, 4, 5, 6, 7, 8])),
            (DataType::Vsa, Value::Vsa(Vsa { vendor: 9, data: vec![1, 3, b'x'] })),
            (DataType::Ipv4Prefix, Value::Ipv4Prefix { length: 32, prefix: Ipv4Addr::UNSPECIFIED }),
            (DataType::Evs, Value::Evs(Evs { vendor: 9, evs_type: 4, data: vec![1] })),
            (DataType::Extended, Value::Extended { ext_type: 1, data: vec![5] }),
            (
                DataType::LongExtended,
                Value::LongExtended { ext_type: 26, more: true, data: vec![5; MAX_LONG_FRAGMENT] },
            ),
            (DataType::LongExtended, Value::LongExtended { ext_type: 1, more: false, data: vec![1] }),
            (
                DataType::Tlv,
                Value::Tlv(vec![Attribute { kind: 1, value: vec![1, 2] }, Attribute { kind: 2, value: vec![3] }]),
            ),
        ];
        for (t, v) in cases {
            assert_eq!(v.data_type(), if t == DataType::Concat { DataType::String } else { t });
            assert_eq!(Value::decode(t, &v.to_attribute(1).map(|a| a.value).unwrap()), Ok(v.clone()), "{t:?}");
            assert_eq!(Attribute::from_value_as(1, t, &v).map(|a| a.value), Some(v.to_attribute(1).map(|a| a.value).unwrap()));
        }
        assert_eq!(Value::String(vec![]).data_type(), DataType::String);
        // Wire forms.
        let p = Value::Ipv6Prefix { length: 64, prefix: "2001:db8:1:2::".parse().unwrap() };
        assert_eq!(p.to_attribute(1).map(|a| a.value).unwrap(), hex("00 40 20 01 0d b8 00 01 00 02"));
        let p = Value::Ipv4Prefix { length: 24, prefix: Ipv4Addr::new(10, 1, 2, 0) };
        assert_eq!(p.to_attribute(1).map(|a| a.value).unwrap(), [0, 24, 10, 1, 2, 0]);
        // Prefixes with stray bits or excessive lengths are refused.
        let p = Value::Ipv4Prefix { length: 40, prefix: Ipv4Addr::new(1, 2, 3, 4) };
        assert_eq!(p.to_attribute(1), None);
        let p = Value::Ipv6Prefix { length: 4, prefix: "ffff::".parse().unwrap() };
        assert_eq!(p.to_attribute(1), None);
        // A full-length IPv6 prefix field is also read, and the reserved
        // byte is ignored.
        let mut b = vec![7, 64];
        b.extend_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(Value::decode(DataType::Ipv6Prefix, &b), Ok(Value::Ipv6Prefix { length: 64, .. })));
    }

    #[test]
    fn value_errors() {
        use DataType as T;
        assert_eq!(Value::decode(T::Text, &[0xff]), Err(Error::Text));
        for (t, n) in [(T::Address, 4), (T::Integer, 4), (T::Enum, 4), (T::Time, 4), (T::Integer64, 8)] {
            assert_eq!(Value::decode(t, &vec![0; n + 1]), Err(Error::ValueLength(n + 1)));
            assert_eq!(Value::decode(t, &vec![0; n - 1]), Err(Error::ValueLength(n - 1)));
        }
        assert_eq!(Value::decode(T::Ipv6Address, &[0; 15]), Err(Error::ValueLength(15)));
        assert_eq!(Value::decode(T::InterfaceId, &[0; 7]), Err(Error::ValueLength(7)));
        assert_eq!(Value::decode(T::Ipv4Prefix, &[0; 5]), Err(Error::ValueLength(5)));
        assert_eq!(Value::decode(T::Ipv6Prefix, &[0]), Err(Error::ValueLength(1)));
        assert_eq!(Value::decode(T::Ipv6Prefix, &[0; 19]), Err(Error::ValueLength(19)));
        // Prefix length past the address, too few bytes, bits past the
        // length.
        assert_eq!(Value::decode(T::Ipv6Prefix, &[0, 129]), Err(Error::Prefix));
        assert_eq!(Value::decode(T::Ipv6Prefix, &[0, 17, 1, 2]), Err(Error::Prefix));
        assert_eq!(Value::decode(T::Ipv6Prefix, &[0, 4, 0xf8]), Err(Error::Prefix));
        assert_eq!(Value::decode(T::Ipv4Prefix, &[0, 33, 0, 0, 0, 0]), Err(Error::Prefix));
        assert_eq!(Value::decode(T::Ipv4Prefix, &[0, 8, 1, 1, 0, 0]), Err(Error::Prefix));
        assert_eq!(Value::decode(T::Vsa, &[0, 0, 1]), Err(Error::ValueLength(3)));
        assert_eq!(Value::decode(T::Evs, &[0, 0, 0, 1]), Err(Error::ValueLength(4)));
        assert_eq!(Value::decode(T::Extended, &[]), Err(Error::ValueLength(0)));
        assert_eq!(Value::decode(T::LongExtended, &[1]), Err(Error::ValueLength(1)));
        assert_eq!(Value::decode(T::Tlv, &[1, 1]), Err(Error::Nested));
        assert_eq!(Value::decode(T::Tlv, &[1, 4, 0]), Err(Error::Nested));
        assert_eq!(Value::decode(T::Tlv, &[1]), Err(Error::Nested));
        for e in [Error::ValueLength(1), Error::Text, Error::Prefix, Error::Nested, Error::Fragment]
        {
            assert!(!e.to_string().is_empty());
        }
        assert!(!Error::Unwritable.to_string().is_empty());
        // An attribute the dictionary does not know reads as bytes.
        assert_eq!(Attribute { kind: 200, value: vec![1] }.decode(), Ok(Value::String(vec![1])));
    }

    #[test]
    fn vendor_specific() {
        // Vendor 311 (Microsoft), sub-attribute 1 holding "ab".
        let vsa = Vsa::from_sub_attributes(311, &[Attribute { kind: 1, value: b"ab".to_vec() }]).unwrap();
        let a = Attribute::from_value(attr::VENDOR_SPECIFIC, &Value::Vsa(vsa.clone())).unwrap();
        assert_eq!(a.value, [0, 0, 1, 0x37, 1, 4, b'a', b'b']);
        let Ok(Value::Vsa(back)) = a.decode() else { panic!() };
        assert_eq!(back, vsa);
        assert_eq!(back.sub_attributes().unwrap(), [Attribute { kind: 1, value: b"ab".to_vec() }]);
        // Bytes that are not sub-attributes.
        let odd = Vsa { vendor: 1, data: vec![1, 9] };
        assert_eq!(odd.sub_attributes(), Err(Error::Nested));
        // Sub-attributes that do not fit in one attribute, or none at all,
        // are refused rather than cut.
        assert_eq!(Vsa::from_sub_attributes(1, &[Attribute { kind: 1, value: vec![0; 300] }]), None);
        assert_eq!(Vsa::from_sub_attributes(1, &[Attribute { kind: 1, value: vec![0; 248] }]), None);
        assert!(Vsa::from_sub_attributes(1, &[Attribute { kind: 1, value: vec![0; 247] }]).is_some());
        assert_eq!(Vsa::from_sub_attributes(1, &[]), None);
        let big = Vsa { vendor: 1, data: vec![0; 250] };
        assert_eq!(big.to_bytes(), Err(Error::Unwritable));
        assert!(Attribute::from_value(attr::VENDOR_SPECIFIC, &Value::Vsa(big)).is_none());
    }

    /// A type 246 attribute with `ext_type`, the More flag if `more`, and
    /// `n` bytes after the flags.
    fn f(ext_type: u8, more: bool, n: usize) -> Attribute {
        let mut value = vec![ext_type, if more { MORE_FLAG } else { 0 }];
        value.extend(std::iter::repeat_n(ext_type, n));
        Attribute { kind: attr::LONG_EXTENDED_TYPE_2, value }
    }

    #[test]
    fn extended_attributes() {
        let mut p = Packet::new(Code::AccessRequest, 1, [0; 16]);
        let short = Extended { kind: attr::EXTENDED_TYPE_1, ext_type: 3, data: vec![1, 2, 3] };
        let evs = Evs { vendor: 9, evs_type: 1, data: vec![7; 600] };
        let long = Extended {
            kind: attr::LONG_EXTENDED_TYPE_1,
            ext_type: EXTENDED_VENDOR_SPECIFIC,
            data: evs.to_bytes().unwrap(),
        };
        p.push_extended(&short).unwrap();
        p.push(Attribute { kind: attr::USER_NAME, value: b"u".to_vec() }).unwrap();
        p.push_extended(&long).unwrap();
        // 605 bytes take three fragments: 251, 251 and 103.
        let frags: Vec<_> = p.all(attr::LONG_EXTENDED_TYPE_1).collect();
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[0].value.len(), MAX_VALUE);
        assert_eq!(frags[0].value[1], MORE_FLAG);
        assert_eq!(frags[2].value[1], 0);
        assert_eq!(
            frags[0].decode().unwrap(),
            Value::LongExtended { ext_type: 26, more: true, data: frags[0].value[2..].to_vec() }
        );
        let back = Packet::parse(&p.to_bytes().unwrap()).unwrap();
        let ext: Vec<Extended> = back.extended().into_iter().map(Result::unwrap).collect();
        assert_eq!(ext, [short.clone(), long.clone()]);
        assert!(!ext[0].is_long() && ext[1].is_long());
        assert_eq!(ext[1].evs(), Some(Ok(evs)));
        assert_eq!(ext[0].evs(), None);
        assert_eq!(
            back.get(attr::EXTENDED_TYPE_1).unwrap().decode(),
            Ok(Value::Extended { ext_type: 3, data: vec![1, 2, 3] })
        );

        // RFC 6929, section 2.2: the attribute right after a fragment with
        // the More flag continues it. One of another type, or a value in
        // the other long extended type, in between breaks the value.
        let mut q = Packet::new(Code::AccessAccept, 1, [0; 16]);
        let mut other = f(2, false, 1);
        other.kind = attr::LONG_EXTENDED_TYPE_1;
        let one = |kind, ext_type, data: Vec<u8>| Ok(Extended { kind, ext_type, data });
        q.attributes = vec![f(1, true, 251), other, f(1, false, 2)];
        assert_eq!(q.extended(), [Err(Error::Fragment), one(245, 2, vec![2]), one(246, 1, vec![1, 1])]);
        q.attributes = vec![f(1, true, 251), Attribute { kind: 1, value: b"u".to_vec() }, f(1, false, 2)];
        assert_eq!(q.extended(), [Err(Error::Fragment), one(246, 1, vec![1, 1])]);
        q.attributes = vec![f(1, true, 251), f(1, false, 2)];
        assert_eq!(q.extended(), [one(246, 1, vec![1; 253])]);

        // Errors: More on a short fragment, More on the last, no header,
        // no bytes after the header.
        q.attributes = vec![f(1, true, 10), f(1, false, 1)];
        assert_eq!(q.extended(), [Err(Error::Fragment), Ok(Extended { kind: 246, ext_type: 1, data: vec![1] })]);
        q.attributes = vec![f(1, true, 251)];
        assert_eq!(q.extended(), [Err(Error::Fragment)]);
        q.attributes = vec![Attribute { kind: 246, value: vec![1] }];
        assert_eq!(q.extended(), [Err(Error::ValueLength(1))]);
        q.attributes = vec![f(1, false, 0)];
        assert_eq!(q.extended(), [Err(Error::ValueLength(2))]);
        q.attributes = vec![Attribute { kind: 241, value: vec![] }, Attribute { kind: 242, value: vec![7] }];
        assert_eq!(q.extended(), [Err(Error::ValueLength(0)), Err(Error::ValueLength(1))]);
        assert_eq!(Extended { kind: 241, ext_type: 26, data: vec![1] }.evs(), Some(Err(Error::ValueLength(1))));

        // Values that cannot be written: wrong type, empty, too long.
        assert_eq!(Extended { kind: 1, ext_type: 1, data: vec![1] }.to_attributes(), None);
        assert_eq!(Extended { kind: 241, ext_type: 1, data: vec![] }.to_attributes(), None);
        assert_eq!(Extended { kind: 246, ext_type: 1, data: vec![] }.to_attributes(), None);
        assert_eq!(Extended { kind: 241, ext_type: 1, data: vec![0; 253] }.to_attributes(), None);
        assert!(Extended { kind: 241, ext_type: 1, data: vec![0; 252] }.to_attributes().is_some());
        let huge = Extended { kind: 245, ext_type: 1, data: vec![0; MAX_LONG_EXTENDED_VALUE + 1] };
        assert_eq!(huge.to_attributes(), None);
        // The largest long value fills a packet exactly as far as it can.
        let most = Extended { kind: 245, ext_type: 1, data: vec![0; MAX_LONG_EXTENDED_VALUE] };
        let mut r = Packet::new(Code::AccessAccept, 1, [0; 16]);
        r.push_extended(&most).unwrap();
        assert_eq!(r.encoded_len(), MAX_PACKET);
        assert_eq!(MAX_LONG_EXTENDED_VALUE, 4012);
        assert_eq!(Packet::parse(&r.to_bytes().unwrap()).unwrap().extended(), [Ok(most.clone())]);
        // A second one does not fit, and nothing is added.
        let before = r.attributes.len();
        assert_eq!(r.push_extended(&most), Err(Error::Unwritable));
        assert_eq!(r.attributes.len(), before);
    }

    #[test]
    fn rfc_6929_minimum_lengths() {
        use DataType as T;
        // Extended: Length 4 or more, so a byte after the Extended-Type.
        assert_eq!(Value::decode(T::Extended, &[1]), Err(Error::ValueLength(1)));
        assert_eq!(Value::decode(T::Extended, &[1, 0]), Ok(Value::Extended { ext_type: 1, data: vec![0] }));
        // Long extended: Length 5 or more.
        assert_eq!(Value::decode(T::LongExtended, &[1, 0]), Err(Error::ValueLength(2)));
        assert!(Value::decode(T::LongExtended, &[1, 0x7f, 0]).is_ok());
        // The More flag only on a full-length fragment.
        assert_eq!(Value::decode(T::LongExtended, &[1, MORE_FLAG, 9]), Err(Error::Fragment));
        // TLV: each TLV-Length 3 or more, and the value one or more bytes.
        assert_eq!(Value::decode(T::Tlv, &[1, 2]), Err(Error::Nested));
        assert_eq!(Value::decode(T::Tlv, &[1, 3, 0, 2, 2]), Err(Error::Nested));
        assert_eq!(Value::decode(T::Tlv, &[]), Err(Error::ValueLength(0)));
        // EVS: one or more bytes of EVS-Value.
        assert_eq!(Value::decode(T::Evs, &[0, 0, 0, 9, 1]), Err(Error::ValueLength(5)));
        // Vendor-Specific: Length 7 or more (RFC 2865).
        assert_eq!(Value::decode(T::Vsa, &[0, 0, 0, 9]), Err(Error::ValueLength(4)));
        assert!(Value::decode(T::Vsa, &[0, 0, 0, 9, 1]).is_ok());
        // Writers refuse what readers refuse.
        let empty_tlv = Value::Tlv(vec![Attribute { kind: 1, value: vec![] }]);
        assert_eq!(Attribute::from_value_as(1, T::Tlv, &empty_tlv), None);
        assert_eq!(Attribute::from_value_as(1, T::Tlv, &Value::Tlv(vec![])), None);
        assert_eq!(Value::Tlv(vec![]).to_attribute(1).map(|a| a.value), None);
        assert_eq!(Vsa::from_sub_attributes(9, &[]), None);
        assert_eq!(Vsa { vendor: 9, data: vec![] }.to_bytes(), Err(Error::Unwritable));
        assert_eq!(Value::Vsa(Vsa { vendor: 9, data: vec![] }).to_attribute(1).map(|a| a.value), None);
        assert_eq!(Evs { vendor: 9, evs_type: 1, data: vec![] }.to_bytes(), Err(Error::Unwritable));
        assert_eq!(Value::Evs(Evs { vendor: 9, evs_type: 1, data: vec![] }).to_attribute(1).map(|a| a.value), None);
        assert_eq!(Value::Extended { ext_type: 1, data: vec![] }.to_attribute(1).map(|a| a.value), None);
        let short_more = Value::LongExtended { ext_type: 1, more: true, data: vec![1] };
        assert_eq!(short_more.to_attribute(1).map(|a| a.value), None);
        assert_eq!(Attribute::from_value(245, &short_more), None);
        let mut p = Packet::new(Code::AccessRequest, 1, [0; 16]);
        assert_eq!(p.push_extended(&Extended { kind: 241, ext_type: 1, data: vec![] }), Err(Error::Unwritable));
    }

    #[test]
    fn long_extended_fragments_continue_in_the_next_attribute_of_their_type() {
        // RFC 6929, section 2.2: the attribute after a fragment with the
        // More flag must have the same Type and Extended-Type.
        let mut q = Packet::new(Code::AccessAccept, 1, [0; 16]);
        q.attributes = vec![f(1, true, 251), f(2, false, 1), f(1, false, 2)];
        let one = |data: Vec<u8>, ext_type| Ok(Extended { kind: 246, ext_type, data });
        assert_eq!(q.extended(), [Err(Error::Fragment), one(vec![2], 2), one(vec![1, 1], 1)]);
        // A broken fragment ends the value it would continue.
        q.attributes = vec![f(1, true, 251), Attribute { kind: 246, value: vec![1] }];
        assert_eq!(q.extended(), [Err(Error::Fragment), Err(Error::ValueLength(1))]);
        // Two values one after the other.
        q.attributes = vec![f(1, true, 251), f(1, false, 1), f(1, false, 1)];
        assert_eq!(q.extended(), [one(vec![1; 252], 1), one(vec![1], 1)]);
    }

    #[test]
    fn an_invalid_extended_attribute_does_not_hide_the_others() {
        // RFC 6929, section 2.8.
        let mut q = Packet::new(Code::AccessAccept, 1, [0; 16]);
        q.attributes = vec![
            Attribute { kind: 241, value: vec![5, 1] },
            Attribute { kind: 241, value: vec![] },
            f(3, true, 251),
            Attribute { kind: 242, value: vec![6, 2] },
        ];
        assert_eq!(
            q.extended(),
            [
                Ok(Extended { kind: 241, ext_type: 5, data: vec![1] }),
                Err(Error::ValueLength(0)),
                Err(Error::Fragment),
                Ok(Extended { kind: 242, ext_type: 6, data: vec![2] }),
            ]
        );
    }

    #[test]
    fn ipv4_prefix_of_zeros_requires_length_32() {
        // RFC 8044, section 3.11.
        assert_eq!(Value::decode(DataType::Ipv4Prefix, &[0, 8, 0, 0, 0, 0]), Err(Error::Prefix));
        assert_eq!(Value::decode(DataType::Ipv4Prefix, &[0, 0, 0, 0, 0, 0]), Err(Error::Prefix));
        let zero = Value::Ipv4Prefix { length: 0, prefix: Ipv4Addr::new(10, 0, 0, 0) };
        assert_eq!(zero.to_attribute(1), None);
    }

    #[test]
    fn dictionary_matches_the_iana_registry() {
        // Data types and names the IANA RADIUS Attribute Types registry
        // gives.
        let cases = [
            (attr::FRAMED_IPX_NETWORK, "Framed-IPX-Network", DataType::Address),
            (attr::ARAP_SECURITY_DATA, "ARAP-Security-Data", DataType::Text),
            (attr::CONFIGURATION_TOKEN, "Configuration-Token", DataType::Text),
            (attr::EGRESS_VLANID, "Egress-VLANID", DataType::Integer),
            (attr::INGRESS_FILTERS, "Ingress-Filters", DataType::Enum),
            (attr::TUNNEL_PRIVATE_GROUP_ID, "Tunnel-Private-Group-ID", DataType::String),
            (attr::ACCT_TUNNEL_PACKETS_LOST, "Acct-Tunnel-Frames::<Packet>-Lost", DataType::Integer),
            (attr::CUI, "CUI", DataType::String),
            (attr::NAS_FILTER_RULE, "NAS-Filter-Rule", DataType::Text),
            (attr::LONG_EXTENDED_TYPE_1, "Long-Extended-Type-1", DataType::LongExtended),
            (attr::LONG_EXTENDED_TYPE_2, "Long-Extended-Type-2", DataType::LongExtended),
        ];
        for (kind, name, data_type) in cases {
            assert_eq!(lookup(kind), Some(&AttributeInfo { kind, name, data_type }));
        }
        // Every assigned type from 1 to 101 is known; 17, 21, 54 and 93
        // are unassigned.
        for kind in 1..=101u8 {
            assert_eq!(lookup(kind).is_some(), ![17, 21, 54, 93].contains(&kind), "{kind}");
        }
        assert_eq!(enum_name(attr::INGRESS_FILTERS, 2), Some("Disabled"));
        // The IPX network reads as an address: RFC 2865's example
        // 0xFFFFFFFE.
        let a = Attribute { kind: attr::FRAMED_IPX_NETWORK, value: vec![255, 255, 255, 254] };
        assert_eq!(a.decode(), Ok(Value::Address(Ipv4Addr::new(255, 255, 255, 254))));
    }

    #[test]
    fn eap_message_split_and_joined() {
        let eap: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
        let mut p = Packet::new(Code::AccessRequest, 1, [0; 16]);
        for a in Attribute::split(attr::EAP_MESSAGE, &eap).unwrap() {
            p.push(a).unwrap();
        }
        assert_eq!(p.all(attr::EAP_MESSAGE).count(), 3);
        let back = Packet::parse(&p.to_bytes().unwrap()).unwrap();
        assert_eq!(back.concat(attr::EAP_MESSAGE), eap);
        assert_eq!(Attribute::split(attr::EAP_MESSAGE, &[]).unwrap().len(), 1);
    }

    #[test]
    fn dictionary() {
        assert_eq!(lookup(attr::USER_NAME).unwrap().name, "User-Name");
        assert_eq!(lookup_name("framed-ipv6-prefix").unwrap().data_type, DataType::Ipv6Prefix);
        assert_eq!(lookup(17), None);
        assert_eq!(lookup_name("No-Such-Attribute"), None);
        // Each type and each name appears once.
        for (i, a) in DICTIONARY.iter().enumerate() {
            for b in &DICTIONARY[i + 1..] {
                assert_ne!(a.kind, b.kind);
                assert_ne!(a.name, b.name);
            }
            assert_eq!(lookup(a.kind), Some(a));
            assert_eq!(lookup_name(a.name), Some(a));
        }
        assert_eq!(Attribute { kind: 1, value: vec![] }.info().unwrap().data_type, DataType::Text);
    }

    #[test]
    fn writers_refuse_what_does_not_fit() {
        // A value past MAX_VALUE is refused, not cut: cutting
        // "é".repeat(127) would leave text that is not UTF-8.
        let mut p = Packet::new(Code::AccessAccept, 1, [0; 16]);
        p.attributes.push(Attribute { kind: attr::USER_NAME, value: "é".repeat(127).into_bytes() });
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        assert!(Attribute::from_value(attr::CLASS, &Value::String(vec![0; 254])).is_none());
        assert_eq!(Value::String(vec![0; 254]).to_attribute(1).map(|a| a.value), None);
        assert_eq!(p.push(Attribute { kind: 1, value: vec![0; 254] }), Err(Error::Unwritable));
        // A packet past MAX_PACKET is refused, not cut: the Session-Timeout
        // after fifteen 253-byte Class values and one of 249 bytes is not
        // left out.
        let mut p = Packet::new(Code::AccessAccept, 1, [0; 16]);
        for _ in 0..15 {
            p.attributes.push(Attribute { kind: attr::CLASS, value: vec![2; MAX_VALUE] });
        }
        p.attributes.push(Attribute { kind: attr::CLASS, value: vec![2; 249] });
        assert_eq!(p.to_bytes().unwrap().len(), MAX_PACKET);
        p.attributes.push(Attribute::from_value(attr::SESSION_TIMEOUT, &Value::Integer(60)).unwrap());
        assert_eq!(p.encoded_len(), MAX_PACKET + 6);
        assert_eq!(p.to_bytes(), Err(Error::Unwritable));
        // push refuses anything once the packet is too long, however it
        // got so.
        let mut p = Packet::new(Code::AccessAccept, 1, [0; 16]);
        for _ in 0..16 {
            p.attributes.push(Attribute { kind: attr::CLASS, value: vec![1; MAX_VALUE] });
        }
        assert_eq!(p.encoded_len(), 4100);
        assert_eq!(p.push(Attribute { kind: attr::CLASS, value: vec![1] }), Err(Error::Unwritable));
        let e = Extended { kind: 241, ext_type: 1, data: vec![1] };
        assert_eq!(p.push_extended(&e), Err(Error::Unwritable));
        assert_eq!(p.attributes.len(), 16);
        // push stops at the limit.
        let mut p = Packet::new(Code::AccessAccept, 1, [0; 16]);
        while p.push(Attribute { kind: 1, value: vec![] }).is_ok() {}
        assert_eq!(p.attributes.len(), MAX_ATTRIBUTES);
        assert_eq!(p.to_bytes().unwrap().len(), MAX_PACKET);
        // TLVs past MAX_VALUE are refused, not cut.
        let t = Value::Tlv(vec![Attribute { kind: 1, value: vec![0; 300] }]);
        assert_eq!(t.to_attribute(1).map(|a| a.value), None);
        let t = Value::Tlv(vec![Attribute { kind: 1, value: vec![0; 100] }; 3]);
        assert_eq!(t.to_attribute(1).map(|a| a.value), None);
        let t = Value::Tlv(vec![Attribute { kind: 1, value: vec![0; 251] }]);
        assert_eq!(t.to_attribute(1).map(|a| a.value).unwrap().len(), MAX_VALUE);
        // Values too long for an attribute are refused before they are
        // copied.
        assert_eq!(Value::Text("x".repeat(254)).to_attribute(1).map(|a| a.value), None);
        assert_eq!(Value::Extended { ext_type: 1, data: vec![0; 253] }.to_attribute(1).map(|a| a.value), None);
        assert_eq!(Value::LongExtended { ext_type: 1, more: false, data: vec![0; 252] }.to_attribute(1).map(|a| a.value), None);
        assert_eq!(Value::Evs(Evs { vendor: 1, evs_type: 1, data: vec![0; 249] }).to_attribute(1).map(|a| a.value), None);
        assert!(Value::Evs(Evs { vendor: 1, evs_type: 1, data: vec![0; 248] }).to_attribute(1).map(|a| a.value).is_some());
        // An extended vendor-specific value can be as long as a long
        // extended attribute carries.
        assert!(Evs { vendor: 1, evs_type: 1, data: vec![0; MAX_LONG_EXTENDED_VALUE - 5] }.to_bytes().is_ok());
        assert_eq!(Evs { vendor: 1, evs_type: 1, data: vec![0; MAX_LONG_EXTENDED_VALUE - 4] }.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn stream_splits_packets() {
        let a = hex(ACCESS_REQUEST);
        let data = [a.clone(), hex(ACCESS_ACCEPT)].concat();
        contract::check_decode_with_alloc_limit(Frames::<Packet>::new, &data, 2 * MAX_PACKET);
        let (packets, error) = decode_all(Frames::<Packet>::new, &data);
        assert_eq!(error, None);
        assert_eq!(packets.iter().map(|p| p.code).collect::<Vec<_>>(), [Code::AccessRequest, Code::AccessAccept]);
        assert_eq!(decode_all(Frames::<Packet>::new, &[1, 0, 0, 5]).1,
            Some(Fail::Protocol(Error::Length { length: 5, limit: MAX_PACKET })));
        let mut bad = a;
        bad[21] = 1;
        assert_eq!(decode_all(Frames::<Packet>::new, &bad).1, Some(Fail::Protocol(Error::Attribute(20))));
    }

    #[test]
    fn stream_holds_at_most_one_packet() {
        // A stream pushed in one call is taken a packet's worth at a time.
        let one = Packet::new(Code::StatusServer, 1, [0; 16]).to_bytes().unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 1000).collect();
        let mut d = Stream::new(Frames::<Packet>::new());
        assert_eq!(d.push(&stream), MAX_PACKET);
        assert_eq!(d.push(&stream[MAX_PACKET..]), 0);
        assert_eq!(d.buffered(), MAX_PACKET);
        let (packets, error) = decode_all(Frames::<Packet>::new, &stream);
        assert_eq!((packets.len(), error), (1000, None));
        // A packet of the longest length fills the decoder, and is read.
        let mut big = Packet::new(Code::AccessAccept, 2, [0; 16]);
        while big.push(Attribute { kind: attr::CLASS, value: vec![1; MAX_VALUE] }).is_ok() {}
        let room = MAX_PACKET - big.encoded_len() - 2;
        big.push(Attribute { kind: attr::CLASS, value: vec![2; room] }).unwrap();
        let bytes = big.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_PACKET);
        let mut d = Stream::new(Frames::<Packet>::new());
        assert_eq!(d.push(&[bytes.clone(), bytes.clone()].concat()), MAX_PACKET);
        assert_eq!(d.next(), Some(Ok(big)));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn stream_takes_many_small_packets_in_linear_time() {
        assert_linear("stream_takes_many_small_packets_in_linear_time", rounds(25_000), |size| {
            let one = Packet::new(Code::StatusServer, 1, [0; 16]).to_bytes().unwrap();
            let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * size).collect();
            let (packets, error) = decode_all(Frames::<Packet>::new, &stream);
            assert_eq!((packets.len(), error), (size, None));
        });
    }

    #[test]
    fn from_value_refuses_values_that_read_back_changed() {
        // 0.0.0.0/0 would be written as 0.0.0.0/32, a different route.
        let default_route = Value::Ipv4Prefix { length: 0, prefix: Ipv4Addr::UNSPECIFIED };
        assert_eq!(Attribute::from_value_as(1, DataType::Ipv4Prefix, &default_route), None);
        // Bits past the length, or a length past the address.
        let stray = Value::Ipv4Prefix { length: 8, prefix: Ipv4Addr::new(10, 1, 0, 0) };
        assert_eq!(Attribute::from_value_as(1, DataType::Ipv4Prefix, &stray), None);
        let past = Value::Ipv4Prefix { length: 40, prefix: Ipv4Addr::new(1, 2, 3, 4) };
        assert_eq!(Attribute::from_value_as(1, DataType::Ipv4Prefix, &past), None);
        let stray = Value::Ipv6Prefix { length: 4, prefix: "ffff::".parse().unwrap() };
        assert_eq!(Attribute::from_value(97, &stray), None);
        let past = Value::Ipv6Prefix { length: 200, prefix: Ipv6Addr::UNSPECIFIED };
        assert_eq!(Attribute::from_value(97, &past), None);
        // A TLV value past MAX_VALUE.
        let cut = Value::Tlv(vec![Attribute { kind: 1, value: vec![0; 260] }]);
        assert_eq!(Attribute::from_value_as(1, DataType::Tlv, &cut), None);
        // The same values, written cleanly, are taken.
        let clean = Value::Ipv4Prefix { length: 8, prefix: Ipv4Addr::new(10, 0, 0, 0) };
        assert_eq!(Attribute::from_value_as(1, DataType::Ipv4Prefix, &clean).unwrap().value, [0, 8, 10, 0, 0, 0]);
    }

    #[test]
    fn from_value_checks_the_attributes_own_type() {
        // NAS-IP-Address is an address, so text is refused even though it
        // reads back as text.
        assert_eq!(Attribute::from_value(attr::NAS_IP_ADDRESS, &Value::Text("x".into())), None);
        // Service-Type is an enumeration, and an Integer would read back
        // as an Enum.
        assert_eq!(Attribute::from_value(attr::SERVICE_TYPE, &Value::Integer(1)), None);
        assert!(Attribute::from_value(attr::SERVICE_TYPE, &Value::Enum(1)).is_some());
        // A type the dictionary does not know holds bytes.
        assert_eq!(Attribute::from_value(200, &Value::Integer(1)), None);
        assert_eq!(Attribute::from_value(200, &Value::String(vec![1])).unwrap().value, [1]);
        // Every attribute from_value makes reads back as its value.
        for v in [Value::Text("a".into()), Value::Integer(1), Value::Enum(1), Value::String(vec![1; 17])] {
            for kind in 0..=255u8 {
                if let Some(a) = Attribute::from_value(kind, &v) {
                    assert_eq!(a.decode(), Ok(v.clone()), "{kind}");
                }
            }
        }
    }

    #[test]
    fn attribute_lengths_and_ranges() {
        // RFC 2865, section 5: text and strings are never empty.
        let empty = |kind| Attribute { kind, value: vec![] }.decode();
        assert_eq!(empty(attr::USER_NAME), Err(Error::ValueLength(0)));
        assert_eq!(empty(attr::STATE), Err(Error::ValueLength(0)));
        assert_eq!(Attribute::from_value(attr::USER_NAME, &Value::Text(String::new())), None);
        // EAP-Start is an empty EAP-Message (RFC 3579, section 3.1), and
        // a type the dictionary does not know may be empty.
        assert_eq!(empty(attr::EAP_MESSAGE), Ok(Value::String(vec![])));
        assert_eq!(empty(200), Ok(Value::String(vec![])));
        // RFC 2865, sections 5.2 and 5.3; RFC 3579, section 3.2.
        let sized = |kind, n| Attribute { kind, value: vec![0; n] }.decode().is_ok();
        assert!(!sized(attr::CHAP_PASSWORD, 1) && sized(attr::CHAP_PASSWORD, 17) && !sized(attr::CHAP_PASSWORD, 18));
        let auth = attr::MESSAGE_AUTHENTICATOR;
        assert!(!sized(auth, 1) && sized(auth, 16) && !sized(auth, 17));
        let pw = attr::USER_PASSWORD;
        assert!(!sized(pw, 15) && sized(pw, 16) && !sized(pw, 17) && sized(pw, 128) && !sized(pw, 144));
        assert!(!sized(attr::CHAP_CHALLENGE, 4) && sized(attr::CHAP_CHALLENGE, 5));
        // RFC 2865, section 5.16: a TCP port.
        let port = |p: u32| Attribute { kind: attr::LOGIN_TCP_PORT, value: p.to_be_bytes().to_vec() }.decode();
        assert_eq!(port(65535), Ok(Value::Integer(65535)));
        assert_eq!(port(65536), Err(Error::Range));
        assert_eq!(Attribute::from_value(attr::LOGIN_TCP_PORT, &Value::Integer(65536)), None);
        assert!(!Error::Range.to_string().is_empty());
    }

    #[test]
    fn concat_values_are_consecutive() {
        // RFC 3579, section 3.1, and RFC 8044, section 3.6.
        let eap = |v: u8| Attribute { kind: attr::EAP_MESSAGE, value: vec![v] };
        let user = Attribute { kind: attr::USER_NAME, value: b"u".to_vec() };
        let mut p = Packet::new(Code::AccessRequest, 1, [0; 16]);
        p.attributes = vec![user.clone(), eap(1), eap(2), user.clone()];
        assert_eq!(p.concat_consecutive(attr::EAP_MESSAGE), Some(Ok(vec![1, 2])));
        p.attributes = vec![eap(1), user.clone(), eap(2)];
        assert_eq!(p.concat_consecutive(attr::EAP_MESSAGE), Some(Err(Error::Fragment)));
        p.attributes = vec![user];
        assert_eq!(p.concat_consecutive(attr::EAP_MESSAGE), None);
        // EAP-Start.
        p.attributes = Attribute::split(attr::EAP_MESSAGE, &[]).unwrap();
        assert_eq!(p.concat_consecutive(attr::EAP_MESSAGE), Some(Ok(vec![])));
    }

    #[test]
    fn split_fits_in_one_packet() {
        assert_eq!(MAX_CONCAT_VALUE, 4044);
        let mut p = Packet::new(Code::AccessChallenge, 1, [0; 16]);
        for a in Attribute::split(attr::EAP_MESSAGE, &[7; MAX_CONCAT_VALUE]).unwrap() {
            p.push(a).unwrap();
        }
        assert_eq!(p.encoded_len(), MAX_PACKET);
        let back = Packet::parse(&p.to_bytes().unwrap()).unwrap();
        assert_eq!(back.concat_consecutive(attr::EAP_MESSAGE), Some(Ok(vec![7; MAX_CONCAT_VALUE])));
        assert_eq!(Attribute::split(attr::EAP_MESSAGE, &[7; MAX_CONCAT_VALUE + 1]), None);
        assert_eq!(Attribute::split(attr::EAP_MESSAGE, &vec![0; 1 << 20]), None);
    }

    #[test]
    fn reserved_extended_types_are_not_written() {
        // RFC 6929, section 2.1: Extended-Type 241 to 255 must not be used.
        for ext_type in [241, 255] {
            for kind in [241, 245] {
                let e = Extended { kind, ext_type, data: vec![1] };
                assert_eq!(e.to_attributes(), None);
                let mut p = Packet::new(Code::AccessRequest, 1, [0; 16]);
                assert_eq!(p.push_extended(&e), Err(Error::Unwritable));
            }
        }
        assert!(Extended { kind: 241, ext_type: 240, data: vec![1] }.to_attributes().is_some());
        // Reading one still works, so a world sees what came.
        let mut p = Packet::new(Code::AccessRequest, 1, [0; 16]);
        p.attributes = vec![Attribute { kind: 241, value: vec![255, 1] }];
        assert_eq!(p.extended(), [Ok(Extended { kind: 241, ext_type: 255, data: vec![1] })]);
    }

    #[test]
    fn codes_compare_by_number() {
        // A packet built with Code::Other(1) reads back as itself.
        let p = Packet::new(Code::Other(1), 1, [0; 16]);
        let back = Packet::parse(&p.to_bytes().unwrap()).unwrap();
        assert_eq!(back, p);
        assert_eq!(Code::Other(1), Code::AccessRequest);
        assert_eq!(Code::Other(1).name(), Some("Access-Request"));
        assert_ne!(Code::Other(99), Code::AccessRequest);
        use std::hash::{BuildHasher, RandomState};
        let s = RandomState::new();
        assert_eq!(s.hash_one(Code::Other(43)), s.hash_one(Code::CoaRequest));
    }

    /// Checks everything a reader gives back writes and reads back the
    /// same.
    fn check(data: &[u8]) {
        check_datagram(data);
        contract::check_decode_with_alloc_limit(Frames::<Packet>::new, data, 2 * MAX_PACKET);
        contract::check_wire::<Packet>(data);
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x5eed);
        let seeds = [hex(ACCESS_REQUEST), hex(ACCESS_ACCEPT), hex(CHAP_REQUEST), hex(CHALLENGE)];
        for i in 0..fictionet::stdlib::test_support::rounds(2750) {
            let mut data = if i % 3 == 0 {
                // Random bytes behind a plausible header.
                let n = 20 + rng.index(300);
                let mut d = vec![0; n];
                rng.fill(&mut d);
                d[2..4].copy_from_slice(&(n as u16).to_be_bytes());
                d
            } else if i % 3 == 1 {
                // A real packet with some bytes changed.
                let mut d = seeds[i % seeds.len()].clone();
                mutate(&mut rng, &mut d);
                d
            } else {
                // Well-formed attributes of random types.
                let mut d = vec![rng.next() as u8, rng.next() as u8, 0, 0];
                d.extend_from_slice(&[0; 16]);
                for _ in 0..rng.index(8) {
                    let kinds = [26, 97, 241, 245, 246, 1, 4, 55, 79, 200];
                    let kind = kinds[rng.index(kinds.len())];
                    let more = rng.coin();
                    // A fragment with the More flag is valid only at full
                    // length, so make most of them so.
                    let full = more && kind >= 245 && rng.index(4) != 0;
                    let len = if full { MAX_VALUE } else { rng.index(40) };
                    d.push(kind);
                    d.push(len as u8 + 2);
                    for j in 0..len {
                        d.push(if j == 1 && more { MORE_FLAG } else { rng.index(8) as u8 });
                    }
                }
                let n = d.len() as u16;
                d[2..4].copy_from_slice(&n.to_be_bytes());
                d
            };
            check(&data);
            // Every prefix too.
            if i % 50 == 0 {
                while !data.is_empty() {
                    data.pop();
                    check(&data);
                }
            }
        }
    }
}
