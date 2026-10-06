//! QUIC: reading and writing packets and frames, with no I/O and no
//! cryptography.
//!
//! QUIC carries HTTP/3 and other protocols over UDP, usually on port 443.
//! Each UDP datagram holds one or more QUIC packets. A packet has a long
//! header while a connection is being set up (Initial, 0-RTT, Handshake
//! and Retry packets, and Version Negotiation) and a short header after
//! that. Inside a packet, the payload is a list of frames: stream data,
//! acknowledgments, flow control limits, new connection IDs and so on.
//! This module follows RFC 9000 (QUIC version 1) and RFC 9369 (QUIC
//! version 2). Apart from their keys, which this module does not use,
//! the two differ only in their version number and in how long header
//! packet types are numbered.
//!
//! Nothing here reads a socket, and nothing here encrypts or decrypts.
//! Real QUIC protects every packet but Version Negotiation and Retry: the
//! payload with AEAD, and some header bits and the packet number with
//! header protection. This module reads and writes packets whose header
//! protection the caller has already removed, or will add after.
//! [`Packet`] says where the AEAD tag goes. A world that plays a QUIC
//! server reads a datagram with [`split_datagram`],
//! reads each packet's frames with [`Payload`], and puts CRYPTO and
//! STREAM data back in order with a [`Reassembler`]. It writes answers as
//! [`Datagram`] values. The short-header connection-ID length is `Datagram`'s
//! const parameter and the `short_dcid_len` argument to [`split_datagram`].
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. Every limit on what a reader keeps is a named constant.
//! An [`Error`] says which rule bytes broke, and
//! [`Error::transport_code`] gives the code a real endpoint would close
//! the connection with.
//!
//! ```
//! use fictionet::stdlib::quic::{
//!     Datagram, Frame, Packet, PacketNumber, Payload, VERSION_1, VERSION_2,
//! };
//! use fictionet::stdlib::codec::Wire;
//!
//! // A client's first packet in a version this server does not speak:
//! // a long header, version 0x1a2a3a4a, an 8-byte destination connection
//! // ID, a 4-byte source connection ID, then bytes only that version
//! // can read.
//! let mut datagram = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8, 1, 2, 3, 4, 5, 6, 7, 8, 4, 9, 9, 9, 9];
//! datagram.resize(1200, 0);
//! let (packet, used) = Packet::parse(&datagram, 0).unwrap();
//! assert_eq!(used, 1200);
//! let Packet::OtherVersion { dcid, scid, .. } = packet else { panic!("not another version") };
//!
//! // The answer lists the versions the server speaks, with the
//! // connection IDs swapped and the 0x40 bit set, as RFC 9000 advises.
//! let reply = Packet::VersionNegotiation {
//!     unused: 0x40,
//!     dcid: scid,
//!     scid: dcid,
//!     versions: vec![VERSION_1, VERSION_2],
//! };
//! let bytes = Datagram::<0>(vec![reply]).to_bytes().unwrap();
//! assert_eq!(bytes[..10], [0xc0, 0, 0, 0, 0, 4, 9, 9, 9, 9]);
//! assert_eq!(bytes.len(), 1 + 4 + 1 + 4 + 1 + 8 + 4 + 4);
//!
//! // A version 1 Initial packet, unprotected, holding a CRYPTO frame and
//! // some padding.
//! let hello = Frame::Crypto { offset: 0, data: b"hello".to_vec() };
//! let payload = Payload(vec![hello.clone(), Frame::Padding(10)]).to_bytes().unwrap();
//! let initial = Packet::Initial {
//!     version: VERSION_1,
//!     dcid: vec![0x83; 8],
//!     scid: vec![],
//!     token: vec![],
//!     number: PacketNumber { value: 0, len: 1 },
//!     payload,
//! };
//! let bytes = Datagram::<0>(vec![initial.clone()]).to_bytes().unwrap();
//! let (back, used) = Packet::parse(&bytes, 0).unwrap();
//! assert_eq!(used, bytes.len());
//! assert_eq!(back, initial);
//! let Packet::Initial { payload, .. } = &back else { panic!("not an Initial") };
//! assert_eq!(Payload::parse(payload).unwrap().0, [hello, Frame::Padding(10)]);
//! ```

use fictionet::stdlib::codec::Wire;

/// The UDP port QUIC servers for HTTP/3 listen on.
pub const PORT: u16 = 443;
/// QUIC version 1 (RFC 9000).
pub const VERSION_1: u32 = 0x0000_0001;
/// QUIC version 2 (RFC 9369).
pub const VERSION_2: u32 = 0x6b33_43cf;
/// The version field of a Version Negotiation packet.
pub const VERSION_NEGOTIATION: u32 = 0;
/// The largest value a variable-length integer can hold: 2^62 - 1.
pub const MAX_VARINT: u64 = (1 << 62) - 1;
/// The longest connection ID in QUIC versions 1 and 2.
pub const MAX_CID_LEN: usize = 20;
/// The longest connection ID any QUIC version may use, as Version
/// Negotiation and packets of other versions carry them.
pub const MAX_ANY_CID_LEN: usize = 255;
/// The largest datagram a reader accepts or a writer makes: the largest
/// UDP payload.
pub const MAX_DATAGRAM: usize = 65_527;
/// The longest packet payload [`Payload`] reads or writes.
pub const MAX_PAYLOAD: usize = MAX_DATAGRAM;
/// The most frames one payload may hold. A run of PADDING bytes counts
/// as one frame.
pub const MAX_FRAMES: usize = 1024;
/// The most extra ranges one ACK frame may carry, past the first.
pub const MAX_ACK_RANGES: usize = 1024;
/// The most packets one datagram may hold.
pub const MAX_COALESCED: usize = 16;
/// The largest stream count MAX_STREAMS and STREAMS_BLOCKED may carry:
/// 2^60.
pub const MAX_STREAM_COUNT: u64 = 1 << 60;
/// The length of a stateless reset token.
pub const RESET_TOKEN_LEN: usize = 16;
/// The length of the integrity tag that ends a Retry packet.
pub const RETRY_TAG_LEN: usize = 16;
/// How far past what has been read a [`Reassembler`] holds data, in
/// bytes.
pub const MAX_REASSEMBLY: usize = 65_536;

/// Frame types (RFC 9000, section 19 and table 3).
pub mod frame_type {
    /// Padding bytes.
    pub const PADDING: u64 = 0x00;
    /// A request for acknowledgment.
    pub const PING: u64 = 0x01;
    /// Acknowledged packet ranges.
    pub const ACK: u64 = 0x02;
    /// Acknowledged ranges with ECN counts.
    pub const ACK_ECN: u64 = 0x03;
    /// Abandon a stream.
    pub const RESET_STREAM: u64 = 0x04;
    /// Ask the peer to stop a stream.
    pub const STOP_SENDING: u64 = 0x05;
    /// TLS handshake data.
    pub const CRYPTO: u64 = 0x06;
    /// A token for a later Initial packet.
    pub const NEW_TOKEN: u64 = 0x07;
    /// STREAM frames are 0x08 to 0x0f. The low three bits are flags.
    pub const STREAM: u64 = 0x08;
    /// In a STREAM frame type: an offset field is present.
    pub const STREAM_OFF: u64 = 0x04;
    /// In a STREAM frame type: a length field is present.
    pub const STREAM_LEN: u64 = 0x02;
    /// In a STREAM frame type: this frame ends the stream.
    pub const STREAM_FIN: u64 = 0x01;
    /// The connection flow-control limit.
    pub const MAX_DATA: u64 = 0x10;
    /// A stream flow-control limit.
    pub const MAX_STREAM_DATA: u64 = 0x11;
    /// The bidirectional stream count limit.
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    /// The unidirectional stream count limit.
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    /// The sender reached its connection limit.
    pub const DATA_BLOCKED: u64 = 0x14;
    /// The sender reached a stream limit.
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    /// The sender reached its bidirectional stream count limit.
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    /// The sender reached its unidirectional stream count limit.
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    /// A new connection ID and reset token.
    pub const NEW_CONNECTION_ID: u64 = 0x18;
    /// Retire a connection ID.
    pub const RETIRE_CONNECTION_ID: u64 = 0x19;
    /// A path-validation challenge.
    pub const PATH_CHALLENGE: u64 = 0x1a;
    /// A path-validation response.
    pub const PATH_RESPONSE: u64 = 0x1b;
    /// A transport connection close.
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    /// An application connection close.
    pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
    /// The server completed the handshake.
    pub const HANDSHAKE_DONE: u64 = 0x1e;
}

/// Transport error codes, sent in a CONNECTION_CLOSE frame of type 0x1c
/// (RFC 9000, section 20.1).
pub mod error_code {
    /// Normal connection closure.
    pub const NO_ERROR: u64 = 0x00;
    /// An internal endpoint error.
    pub const INTERNAL_ERROR: u64 = 0x01;
    /// The endpoint refused the connection.
    pub const CONNECTION_REFUSED: u64 = 0x02;
    /// A flow-control limit was exceeded.
    pub const FLOW_CONTROL_ERROR: u64 = 0x03;
    /// A stream-count limit was exceeded.
    pub const STREAM_LIMIT_ERROR: u64 = 0x04;
    /// A frame is invalid for this stream state.
    pub const STREAM_STATE_ERROR: u64 = 0x05;
    /// The stream final size is inconsistent.
    pub const FINAL_SIZE_ERROR: u64 = 0x06;
    /// A frame is malformed.
    pub const FRAME_ENCODING_ERROR: u64 = 0x07;
    /// A transport parameter is invalid.
    pub const TRANSPORT_PARAMETER_ERROR: u64 = 0x08;
    /// Too many connection IDs are active.
    pub const CONNECTION_ID_LIMIT_ERROR: u64 = 0x09;
    /// A transport protocol rule was broken.
    pub const PROTOCOL_VIOLATION: u64 = 0x0a;
    /// An address-validation token is invalid.
    pub const INVALID_TOKEN: u64 = 0x0b;
    /// The application caused closure.
    pub const APPLICATION_ERROR: u64 = 0x0c;
    /// Too much CRYPTO data is buffered.
    pub const CRYPTO_BUFFER_EXCEEDED: u64 = 0x0d;
    /// A key update is invalid.
    pub const KEY_UPDATE_ERROR: u64 = 0x0e;
    /// The packet-protection usage limit was reached.
    pub const AEAD_LIMIT_REACHED: u64 = 0x0f;
    /// No path can carry the connection.
    pub const NO_VIABLE_PATH: u64 = 0x10;
    /// TLS alerts are sent as this plus the alert number.
    pub const CRYPTO_ERROR: u64 = 0x0100;
}

/// Why bytes are not a QUIC packet or frame, or why a value cannot be
/// written as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// Bytes follow the complete wire value.
    Trailing,
    /// The bytes ended before a field did, or a length field asks for
    /// more bytes than there are. Inside a frame, this is
    /// [`Error::FrameEncoding`] instead, which names the frame's type.
    Truncated,
    /// A datagram or payload is longer than [`MAX_DATAGRAM`] or
    /// [`MAX_PAYLOAD`]. It holds the length.
    TooLong(usize),
    /// The fixed bit (0x40 of the first byte) is 0.
    FixedBit,
    /// The reserved bits of the first byte are not 0 once protection is
    /// removed.
    ReservedBits,
    /// A connection ID is longer than the version allows. It holds the
    /// length.
    ConnectionIdLength(usize),
    /// A long header's Length field is too small to hold the packet
    /// number. It holds the field.
    Length(u64),
    /// A Version Negotiation packet's version list is empty or not a
    /// whole number of 4-byte versions. It holds the list's length in
    /// bytes. RFC 8999 has a receiver ignore a packet with no versions.
    VersionList(usize),
    /// A Retry packet has no token.
    EmptyToken,
    /// A payload holds no frames, or a datagram no packets.
    Empty,
    /// A frame type this module does not know. It holds the type.
    UnknownFrame(u64),
    /// A frame's fields break its rules, or the payload ends inside it.
    /// It holds the frame type.
    FrameEncoding(u64),
    /// A frame type is written in more bytes than it needs. RFC 9000
    /// requires the shortest form. It holds the frame type.
    LongFrameType(u64),
    /// A payload holds more than [`MAX_FRAMES`] frames.
    TooManyFrames,
    /// An ACK frame has more than [`MAX_ACK_RANGES`] extra ranges. It
    /// holds the frame type, 0x02 or 0x03.
    TooManyAckRanges(u64),
    /// A datagram holds more than [`MAX_COALESCED`] packets.
    TooManyPackets,
    /// A packet's destination connection ID differs from that of the
    /// first packet in its datagram. RFC 9000 forbids a sender to mix
    /// them, and a receiver ignores the packets after one that differs.
    MixedConnectionIds,
    /// Data ends past what a [`Reassembler`] may hold, or past
    /// [`MAX_VARINT`]. It holds the offset the data ends at.
    Window(u64),
}

impl Error {
    /// The transport error code a real endpoint sends in CONNECTION_CLOSE
    /// for this error. Errors in a packet's header usually mean the packet
    /// is dropped instead. [`Error::Truncated`] gives FRAME_ENCODING_ERROR,
    /// the code for a payload that ends inside a frame's type.
    /// [`Error::Window`] gives CRYPTO_BUFFER_EXCEEDED, which is the code for
    /// CRYPTO data. For STREAM data a world would send FLOW_CONTROL_ERROR.
    pub fn transport_code(&self) -> u64 {
        match self {
            Error::Truncated
            | Error::UnknownFrame(_)
            | Error::FrameEncoding(_)
            | Error::TooManyFrames
            | Error::TooManyAckRanges(_) => error_code::FRAME_ENCODING_ERROR,
            Error::Unwritable => error_code::INTERNAL_ERROR,
            Error::Window(_) => error_code::CRYPTO_BUFFER_EXCEEDED,
            _ => error_code::PROTOCOL_VIOLATION,
        }
    }

    /// The frame type a CONNECTION_CLOSE frame names for this error, when
    /// a frame caused it.
    pub fn frame_type(&self) -> Option<u64> {
        match self {
            Error::UnknownFrame(t)
            | Error::FrameEncoding(t)
            | Error::LongFrameType(t)
            | Error::TooManyAckRanges(t) => Some(*t),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Trailing => f.write_str("bytes follow the QUIC value"),
            Error::Truncated => f.write_str("the bytes end before the packet or frame does"),
            Error::TooLong(n) => write!(f, "{n} bytes, more than a datagram holds"),
            Error::FixedBit => f.write_str("the fixed bit is 0"),
            Error::ReservedBits => f.write_str("the reserved bits are not 0"),
            Error::ConnectionIdLength(n) => write!(f, "a {n}-byte connection ID is too long"),
            Error::Length(n) => write!(f, "Length field {n} cannot hold the packet number"),
            Error::VersionList(n) => write!(f, "a {n}-byte version list is empty or not whole versions"),
            Error::EmptyToken => f.write_str("a Retry packet with no token"),
            Error::Empty => f.write_str("no frames or packets"),
            Error::UnknownFrame(t) => write!(f, "unknown frame type {t:#x}"),
            Error::FrameEncoding(t) => write!(f, "frame of type {t:#x} breaks its rules"),
            Error::LongFrameType(t) => write!(f, "frame type {t:#x} is not in its shortest form"),
            Error::TooManyFrames => write!(f, "more than {MAX_FRAMES} frames"),
            Error::TooManyAckRanges(_) => write!(f, "more than {MAX_ACK_RANGES} ACK ranges"),
            Error::TooManyPackets => write!(f, "more than {MAX_COALESCED} packets in a datagram"),
            Error::MixedConnectionIds => f.write_str("packets in one datagram have different connection IDs"),
            Error::Window(end) => write!(f, "data ending at offset {end} is past what may be held"),
        }
    }
}

impl std::error::Error for Error {}

// Variable-length integers (RFC 9000, section 16).

/// How many bytes the shortest encoding of `v` takes: 1, 2, 4 or 8. It
/// returns `None` if `v` is above [`MAX_VARINT`].
pub fn varint_len(v: u64) -> Option<usize> {
    match v {
        0..=0x3f => Some(1),
        0x40..=0x3fff => Some(2),
        0x4000..=0x3fff_ffff => Some(4),
        0x4000_0000..=MAX_VARINT => Some(8),
        _ => None,
    }
}

/// Reads the variable-length integer at the start of `b`, and returns it
/// with how many bytes it took. Longer encodings than needed are
/// accepted, as RFC 9000 allows.
pub fn read_varint(b: &[u8]) -> Result<(u64, usize), Error> {
    let first = *b.first().ok_or(Error::Truncated)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(..len).ok_or(Error::Truncated)?;
    let mut v = u64::from(first & 0x3f);
    for &x in bytes.iter().skip(1) {
        v = (v << 8) | u64::from(x);
    }
    Ok((v, len))
}

/// Appends the shortest encoding of `v` to `out`. It fails if `v` is
/// above [`MAX_VARINT`].
fn put_varint(v: u64, out: &mut Vec<u8>) -> Result<(), Error> {
    match varint_len(v) {
        Some(1) => out.push(v as u8),
        Some(2) => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        Some(4) => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        Some(_) => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
        None => return Err(Error::Unwritable),
    }
    Ok(())
}

/// A QUIC variable-length integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VarInt(
    /// The value, at most [`MAX_VARINT`].
    pub u64,
);

fn exact<T>(result: Result<(T, usize), Error>, len: usize) -> Result<T, Error> {
    let (value, used) = result?;
    if used != len {
        return Err(Error::Trailing);
    }
    Ok(value)
}

impl Wire for VarInt {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one integer. Refuses truncation and trailing bytes; accepts longer encodings.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(read_varint(bytes), bytes.len()).map(Self)
    }

    /// Writes the shortest encoding. Refuses values above [`MAX_VARINT`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        put_varint(self.0, out).map_err(|_| Error::Unwritable)
    }
}

// Packet numbers (RFC 9000, section 17.1 and appendix A).

/// A packet number as a packet header carries it: its low `len` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PacketNumber {
    /// The truncated packet number. It must fit in `len` bytes.
    pub value: u32,
    /// How many bytes it takes on the wire: 1 to 4.
    pub len: u8,
}

impl PacketNumber {
    /// The truncated form of packet number `full`, given the largest
    /// packet number the peer has acknowledged. It is long enough to
    /// cover more than twice the packets not yet acknowledged, as RFC
    /// 9000 asks. It returns `None` if `full` is not above `largest_acked`,
    /// is above [`MAX_VARINT`], or needs more than 4 bytes.
    pub fn encode(full: u64, largest_acked: Option<u64>) -> Option<PacketNumber> {
        if full > MAX_VARINT {
            return None;
        }
        let unacked = match largest_acked {
            Some(a) => full.checked_sub(a).filter(|d| *d > 0)?,
            None => full + 1,
        };
        let bits = 64 - unacked.leading_zeros() + 1;
        let len = bits.div_ceil(8);
        if len > 4 {
            return None;
        }
        let mask = (1u64 << (8 * len)) - 1;
        Some(PacketNumber { value: (full & mask) as u32, len: len as u8 })
    }

    /// The full packet number this one stands for, given the largest
    /// packet number received so far in its space. It returns `None` if
    /// the length is not 1 to 4, the value does not fit it, or the result
    /// would pass [`MAX_VARINT`].
    pub fn decode(self, largest: Option<u64>) -> Option<u64> {
        if !self.is_valid() {
            return None;
        }
        let expected = match largest {
            Some(l) if l <= MAX_VARINT => l + 1,
            Some(_) => return None,
            None => 0,
        };
        let win = 1u64 << (8 * u32::from(self.len));
        let hwin = win / 2;
        let candidate = (expected & !(win - 1)) | u64::from(self.value);
        let full = if candidate + hwin <= expected && candidate < (1 << 62) - win {
            candidate + win
        } else if candidate > expected + hwin && candidate >= win {
            candidate - win
        } else {
            candidate
        };
        (full <= MAX_VARINT).then_some(full)
    }

    fn is_valid(self) -> bool {
        (1..=4).contains(&self.len) && (self.len == 4 || self.value < 1 << (8 * u32::from(self.len)))
    }

    fn write(self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !self.is_valid() {
            return Err(Error::Unwritable);
        }
        let bytes = self.value.to_be_bytes();
        out.extend_from_slice(&bytes[4 - usize::from(self.len)..]);
        Ok(())
    }
}

// Packets (RFC 9000, section 17; RFC 9369, section 3.2).

/// Which kind of packet, and so which keys, carries a frame: the
/// encryption level. Frames are allowed in some and not others
/// ([`Frame::allowed_in`]). 0-RTT and 1-RTT packets have different keys
/// but share one packet number space (RFC 9000, section 12.3), so packet
/// numbers and acknowledgments are kept per [`Space::number_space`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Space {
    /// Initial packets.
    Initial,
    /// 0-RTT packets.
    ZeroRtt,
    /// Handshake packets.
    Handshake,
    /// 1-RTT packets: those with a short header.
    OneRtt,
}

impl Space {
    /// The packet number space packets of this kind number from and are
    /// acknowledged in. It is [`Space::OneRtt`] for 0-RTT, the
    /// application data space both share, and the kind itself otherwise.
    pub fn number_space(self) -> Space {
        match self {
            Space::ZeroRtt => Space::OneRtt,
            s => s,
        }
    }
}

/// One QUIC packet, with its header protection removed. The payload is
/// kept as bytes; [`Payload`] reads the frames in it once the AEAD
/// protection is removed. In Initial, 0-RTT and Handshake packets, the
/// payload is what the Length field covers past the packet number, so on
/// the wire it ends with the 16-byte AEAD tag. A reader decrypts the
/// payload [`Packet::parse`] gives and reads the frames from the
/// plaintext. A writer appends 16 bytes to the plaintext frames, so the
/// Length field counts the tag, writes the packet, then protects it in
/// place.
/// Connection IDs are byte vectors. Long header packets of versions 1 and
/// 2 allow up to [`MAX_CID_LEN`] bytes, and the other kinds up to
/// [`MAX_ANY_CID_LEN`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// A server's list of the `versions` it supports, sent when a client
    /// asks for one it does not. `unused` is the low 7 bits of the first
    /// byte. A server may set them to anything, but should set 0x40 so the
    /// packet looks like it has a fixed bit. `dcid` and `scid` echo the
    /// client's source and destination connection IDs.
    VersionNegotiation {
        /// Unused low bits of the first byte.
        unused: u8,
        /// Destination connection ID.
        dcid: Vec<u8>,
        /// Source connection ID.
        scid: Vec<u8>,
        /// Supported version numbers in wire order.
        versions: Vec<u32>,
    },
    /// The first packets of a connection, carrying the TLS handshake's
    /// start. `token` is from a Retry or NEW_TOKEN frame, or empty. A
    /// server's Initial packets must have an empty token, which a client
    /// checks itself.
    Initial {
        /// The QUIC version number.
        version: u32,
        /// Destination connection ID.
        dcid: Vec<u8>,
        /// Source connection ID.
        scid: Vec<u8>,
        /// The address-validation token.
        token: Vec<u8>,
        /// The truncated packet number.
        number: PacketNumber,
        /// Payload bytes after the packet number.
        payload: Vec<u8>,
    },
    /// Early data a client sends before the handshake ends.
    ZeroRtt {
        /// The QUIC version number.
        version: u32,
        /// Destination connection ID.
        dcid: Vec<u8>,
        /// Source connection ID.
        scid: Vec<u8>,
        /// The truncated packet number.
        number: PacketNumber,
        /// Payload bytes after the packet number.
        payload: Vec<u8>,
    },
    /// The rest of the TLS handshake.
    Handshake {
        /// The QUIC version number.
        version: u32,
        /// Destination connection ID.
        dcid: Vec<u8>,
        /// Source connection ID.
        scid: Vec<u8>,
        /// The truncated packet number.
        number: PacketNumber,
        /// Payload bytes after the packet number.
        payload: Vec<u8>,
    },
    /// A server's request that the client prove its address by sending
    /// `token` back. `unused` is the low 4 bits of the first byte. `tag`
    /// is the integrity tag, computed with AES-GCM; this module keeps it
    /// as bytes and does not check it.
    Retry {
        /// The QUIC version number.
        version: u32,
        /// Unused low bits of the first byte.
        unused: u8,
        /// Destination connection ID.
        dcid: Vec<u8>,
        /// Source connection ID.
        scid: Vec<u8>,
        /// The address-validation token.
        token: Vec<u8>,
        /// Retry integrity tag bytes.
        tag: [u8; RETRY_TAG_LEN],
    },
    /// A packet after the handshake. Its destination connection ID has no
    /// length on the wire, so a reader must know it. `spin` is the latency
    /// spin bit and `key_phase` says which keys protect it.
    Short {
        /// The latency spin bit.
        spin: bool,
        /// The packet-protection key phase.
        key_phase: bool,
        /// Destination connection ID.
        dcid: Vec<u8>,
        /// The truncated packet number.
        number: PacketNumber,
        /// Payload bytes after the packet number.
        payload: Vec<u8>,
    },
    /// A long header packet of a version other than 1 or 2. Only the
    /// parts all versions share are read (RFC 8999): the low 7 bits of the
    /// first byte, the version and the connection IDs. `rest` is the
    /// datagram's remaining bytes.
    OtherVersion {
        /// The low seven bits of the first byte.
        bits: u8,
        /// The QUIC version number.
        version: u32,
        /// Destination connection ID.
        dcid: Vec<u8>,
        /// Source connection ID.
        scid: Vec<u8>,
        /// Remaining bytes of the datagram.
        rest: Vec<u8>,
    },
}

impl Packet {
    /// Reads the packet at the start of `b`, a datagram or what is left
    /// of one, and returns it with how many bytes it took. Initial, 0-RTT
    /// and Handshake packets end where their Length field says. The other
    /// kinds take the rest of `b`. `short_dcid_len` is the length of the
    /// connection ID this endpoint gave its peer, which a short header
    /// does not carry.
    pub fn parse(b: &[u8], short_dcid_len: usize) -> Result<(Packet, usize), Error> {
        if b.len() > MAX_DATAGRAM {
            return Err(Error::TooLong(b.len()));
        }
        let mut r = Reader::new(b);
        let first = r.u8()?;
        if first & 0x80 == 0 {
            return parse_short(first, &mut r, short_dcid_len);
        }
        let version = r.u32()?;
        let dcid = r.cid()?;
        let scid = r.cid()?;
        if version == VERSION_NEGOTIATION {
            let rest = r.rest();
            if rest.is_empty() || !rest.len().is_multiple_of(4) {
                return Err(Error::VersionList(rest.len()));
            }
            let versions = rest.chunks_exact(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect();
            let p = Packet::VersionNegotiation { unused: first & 0x7f, dcid, scid, versions };
            return Ok((p, b.len()));
        }
        if version != VERSION_1 && version != VERSION_2 {
            let rest = r.rest().to_vec();
            return Ok((Packet::OtherVersion { bits: first & 0x7f, version, dcid, scid, rest }, b.len()));
        }
        for cid in [&dcid, &scid] {
            if cid.len() > MAX_CID_LEN {
                return Err(Error::ConnectionIdLength(cid.len()));
            }
        }
        if first & 0x40 == 0 {
            return Err(Error::FixedBit);
        }
        let kind = long_kind(version, (first >> 4) & 0x03);
        if kind == LongKind::Retry {
            let rest = r.rest();
            let split = rest.len().checked_sub(RETRY_TAG_LEN).ok_or(Error::Truncated)?;
            let (token, tag) = rest.split_at(split);
            if token.is_empty() {
                return Err(Error::EmptyToken);
            }
            let mut t = [0; RETRY_TAG_LEN];
            t.copy_from_slice(tag);
            let p = Packet::Retry { version, unused: first & 0x0f, dcid, scid, token: token.to_vec(), tag: t };
            return Ok((p, b.len()));
        }
        if first & 0x0c != 0 {
            return Err(Error::ReservedBits);
        }
        let pn_len = (first & 0x03) + 1;
        let token = if kind == LongKind::Initial {
            let n = r.varint()?;
            r.take_u64(n)?.to_vec()
        } else {
            Vec::new()
        };
        let length = r.varint()?;
        if length < u64::from(pn_len) {
            return Err(Error::Length(length));
        }
        let body = r.take_u64(length)?;
        let (pn, payload) = body.split_at(usize::from(pn_len));
        let number = pn_from(pn, pn_len);
        let payload = payload.to_vec();
        let p = match kind {
            LongKind::Initial => Packet::Initial { version, dcid, scid, token, number, payload },
            LongKind::ZeroRtt => Packet::ZeroRtt { version, dcid, scid, number, payload },
            _ => Packet::Handshake { version, dcid, scid, number, payload },
        };
        Ok((p, r.pos))
    }

    /// The packet's bytes. It fails if a field cannot be written: a
    /// connection ID or packet number too long, a version that does not
    /// fit the packet type, first-byte bits that do not fit their field, a
    /// Version Negotiation packet with no versions, a Retry with no token,
    /// or a packet longer than
    /// [`MAX_DATAGRAM`]. Anything it writes, [`Packet::parse`] reads back
    /// the same, given the short header's connection ID length.
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self {
            Packet::VersionNegotiation { unused, dcid, scid, versions } => {
                if versions.is_empty() {
                    return Err(Error::VersionList(0));
                }
                check_len(versions.len().saturating_mul(4))?;
                out.push(0x80 | fits(*unused, 0x7f)?);
                out.extend_from_slice(&VERSION_NEGOTIATION.to_be_bytes());
                write_cid(dcid, MAX_ANY_CID_LEN, &mut out)?;
                write_cid(scid, MAX_ANY_CID_LEN, &mut out)?;
                for v in versions {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            Packet::Initial { version, dcid, scid, token, number, payload } => {
                write_long(*version, LongKind::Initial, dcid, scid, Some(token), *number, payload, &mut out)?;
            }
            Packet::ZeroRtt { version, dcid, scid, number, payload } => {
                write_long(*version, LongKind::ZeroRtt, dcid, scid, None, *number, payload, &mut out)?;
            }
            Packet::Handshake { version, dcid, scid, number, payload } => {
                write_long(*version, LongKind::Handshake, dcid, scid, None, *number, payload, &mut out)?;
            }
            Packet::Retry { version, unused, dcid, scid, token, tag } => {
                let bits = long_bits(*version, LongKind::Retry)?;
                if token.is_empty() {
                    return Err(Error::EmptyToken);
                }
                check_len(token.len())?;
                out.push(0xc0 | bits << 4 | fits(*unused, 0x0f)?);
                out.extend_from_slice(&version.to_be_bytes());
                write_cid(dcid, MAX_CID_LEN, &mut out)?;
                write_cid(scid, MAX_CID_LEN, &mut out)?;
                out.extend_from_slice(token);
                out.extend_from_slice(tag);
            }
            Packet::Short { spin, key_phase, dcid, number, payload } => {
                if dcid.len() > MAX_CID_LEN {
                    return Err(Error::ConnectionIdLength(dcid.len()));
                }
                check_len(payload.len())?;
                let mut first = 0x40 | (number.len.wrapping_sub(1) & 0x03);
                if *spin {
                    first |= 0x20;
                }
                if *key_phase {
                    first |= 0x04;
                }
                out.push(first);
                out.extend_from_slice(dcid);
                number.write(&mut out)?;
                out.extend_from_slice(payload);
            }
            Packet::OtherVersion { bits, version, dcid, scid, rest } => {
                if [VERSION_NEGOTIATION, VERSION_1, VERSION_2].contains(version) {
                    return Err(Error::Unwritable);
                }
                check_len(rest.len())?;
                out.push(0x80 | fits(*bits, 0x7f)?);
                out.extend_from_slice(&version.to_be_bytes());
                write_cid(dcid, MAX_ANY_CID_LEN, &mut out)?;
                write_cid(scid, MAX_ANY_CID_LEN, &mut out)?;
                out.extend_from_slice(rest);
            }
        }
        check_len(out.len())?;
        Ok(out)
    }

    /// The destination connection ID, which says which connection a
    /// packet is for.
    pub fn dcid(&self) -> &[u8] {
        match self {
            Packet::VersionNegotiation { dcid, .. }
            | Packet::Initial { dcid, .. }
            | Packet::ZeroRtt { dcid, .. }
            | Packet::Handshake { dcid, .. }
            | Packet::Retry { dcid, .. }
            | Packet::Short { dcid, .. }
            | Packet::OtherVersion { dcid, .. } => dcid,
        }
    }

    /// The source connection ID, for the long header kinds. A short header
    /// carries none.
    pub fn scid(&self) -> Option<&[u8]> {
        match self {
            Packet::VersionNegotiation { scid, .. }
            | Packet::Initial { scid, .. }
            | Packet::ZeroRtt { scid, .. }
            | Packet::Handshake { scid, .. }
            | Packet::Retry { scid, .. }
            | Packet::OtherVersion { scid, .. } => Some(scid),
            Packet::Short { .. } => None,
        }
    }

    /// The version field, for the long header kinds. It is
    /// [`VERSION_NEGOTIATION`] for Version Negotiation. A short header
    /// carries none.
    pub fn version(&self) -> Option<u32> {
        match self {
            Packet::VersionNegotiation { .. } => Some(VERSION_NEGOTIATION),
            Packet::Initial { version, .. }
            | Packet::ZeroRtt { version, .. }
            | Packet::Handshake { version, .. }
            | Packet::Retry { version, .. }
            | Packet::OtherVersion { version, .. } => Some(*version),
            Packet::Short { .. } => None,
        }
    }

    /// The packet number, for the kinds that carry one.
    pub fn number(&self) -> Option<PacketNumber> {
        match self {
            Packet::Initial { number, .. }
            | Packet::ZeroRtt { number, .. }
            | Packet::Handshake { number, .. }
            | Packet::Short { number, .. } => Some(*number),
            _ => None,
        }
    }

    /// The kind of packet for the rules on which frames it may carry, for
    /// the kinds that carry frames. Its [`Space::number_space`] is the
    /// packet number space.
    pub fn space(&self) -> Option<Space> {
        match self {
            Packet::Initial { .. } => Some(Space::Initial),
            Packet::ZeroRtt { .. } => Some(Space::ZeroRtt),
            Packet::Handshake { .. } => Some(Space::Handshake),
            Packet::Short { .. } => Some(Space::OneRtt),
            _ => None,
        }
    }

    /// The packet's payload: its frames as bytes, for the kinds that
    /// carry frames.
    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Packet::Initial { payload, .. }
            | Packet::ZeroRtt { payload, .. }
            | Packet::Handshake { payload, .. }
            | Packet::Short { payload, .. } => Some(payload),
            _ => None,
        }
    }

    /// Whether the packet says where it ends, so another can follow it in
    /// the same datagram.
    fn has_length(&self) -> bool {
        matches!(self, Packet::Initial { .. } | Packet::ZeroRtt { .. } | Packet::Handshake { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LongKind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

/// The long packet type for type bits `bits` in `version`, which is 1 or
/// 2.
fn long_kind(version: u32, bits: u8) -> LongKind {
    let kinds = if version == VERSION_2 {
        [LongKind::Retry, LongKind::Initial, LongKind::ZeroRtt, LongKind::Handshake]
    } else {
        [LongKind::Initial, LongKind::ZeroRtt, LongKind::Handshake, LongKind::Retry]
    };
    kinds[usize::from(bits & 0x03)]
}

/// The type bits for `kind` in `version`, which must be 1 or 2.
fn long_bits(version: u32, kind: LongKind) -> Result<u8, Error> {
    let bits = match kind {
        LongKind::Initial => 0,
        LongKind::ZeroRtt => 1,
        LongKind::Handshake => 2,
        LongKind::Retry => 3,
    };
    match version {
        VERSION_1 => Ok(bits),
        VERSION_2 => Ok((bits + 1) & 0x03),
        _ => Err(Error::Unwritable),
    }
}

fn parse_short(first: u8, r: &mut Reader<'_>, dcid_len: usize) -> Result<(Packet, usize), Error> {
    if first & 0x40 == 0 {
        return Err(Error::FixedBit);
    }
    if first & 0x18 != 0 {
        return Err(Error::ReservedBits);
    }
    if dcid_len > MAX_CID_LEN {
        return Err(Error::ConnectionIdLength(dcid_len));
    }
    let dcid = r.take(dcid_len)?.to_vec();
    let pn_len = (first & 0x03) + 1;
    let number = pn_from(r.take(usize::from(pn_len))?, pn_len);
    let payload = r.rest().to_vec();
    let p = Packet::Short { spin: first & 0x20 != 0, key_phase: first & 0x04 != 0, dcid, number, payload };
    Ok((p, r.pos))
}

fn pn_from(bytes: &[u8], len: u8) -> PacketNumber {
    let value = bytes.iter().fold(0u32, |v, &x| (v << 8) | u32::from(x));
    PacketNumber { value, len }
}

/// `v`, if it has no bits outside `mask`.
fn fits(v: u8, mask: u8) -> Result<u8, Error> {
    if v & !mask == 0 { Ok(v) } else { Err(Error::Unwritable) }
}

fn check_len(n: usize) -> Result<(), Error> {
    if n > MAX_DATAGRAM { Err(Error::TooLong(n)) } else { Ok(()) }
}

fn write_cid(cid: &[u8], max: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    if cid.len() > max {
        return Err(Error::ConnectionIdLength(cid.len()));
    }
    out.push(cid.len() as u8);
    out.extend_from_slice(cid);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_long(
    version: u32,
    kind: LongKind,
    dcid: &[u8],
    scid: &[u8],
    token: Option<&[u8]>,
    number: PacketNumber,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let bits = long_bits(version, kind)?;
    let token_len = token.map_or(0, <[u8]>::len);
    check_len(payload.len())?;
    check_len(token_len)?;
    out.push(0xc0 | bits << 4 | (number.len.wrapping_sub(1) & 0x03));
    out.extend_from_slice(&version.to_be_bytes());
    write_cid(dcid, MAX_CID_LEN, out)?;
    write_cid(scid, MAX_CID_LEN, out)?;
    if let Some(t) = token {
        put_varint(t.len() as u64, out)?;
        out.extend_from_slice(t);
    }
    // Both lengths are at most MAX_DATAGRAM, so neither sum overflows.
    put_varint(u64::from(number.len) + payload.len() as u64, out)?;
    number.write(out)?;
    out.extend_from_slice(payload);
    Ok(())
}

/// Reads every packet in a datagram, in order. It returns the packets
/// read before the first that failed, and why that one failed, if one
/// did. A receiver drops the failed packet and the rest of the datagram,
/// and keeps the packets before it. A packet whose destination connection
/// ID differs from the first packet's fails with
/// [`Error::MixedConnectionIds`]. An empty datagram fails with
/// [`Error::Empty`].
pub fn split_datagram(b: &[u8], short_dcid_len: usize) -> (Vec<Packet>, Option<Error>) {
    let mut packets = Vec::new();
    if b.is_empty() {
        return (packets, Some(Error::Empty));
    }
    if b.len() > MAX_DATAGRAM {
        return (packets, Some(Error::TooLong(b.len())));
    }
    let mut pos = 0;
    while let Some(rest) = b.get(pos..).filter(|r| !r.is_empty()) {
        if packets.len() == MAX_COALESCED {
            return (packets, Some(Error::TooManyPackets));
        }
        match Packet::parse(rest, short_dcid_len) {
            Ok((p, used)) => {
                if packets.first().is_some_and(|f: &Packet| f.dcid() != p.dcid()) {
                    return (packets, Some(Error::MixedConnectionIds));
                }
                packets.push(p);
                pos += used;
            }
            Err(e) => return (packets, Some(e)),
        }
    }
    (packets, None)
}

/// A complete UDP datagram containing packets with one destination connection ID.
/// `SHORT_DCID_LEN` is the connection's short-header destination-ID length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram<const SHORT_DCID_LEN: usize>(
    /// Packets in transmitted order. Only the last may omit its Length field.
    pub Vec<Packet>,
);

impl<const SHORT_DCID_LEN: usize> Wire for Datagram<SHORT_DCID_LEN> {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads the whole datagram. Refuses empty, oversized, malformed, or excessive packets
    /// and mixed destination IDs. Short headers use `SHORT_DCID_LEN` bytes for the ID.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (packets, error) = split_datagram(bytes, SHORT_DCID_LEN);
        match error {
            Some(error) => Err(error),
            None => Ok(Self(packets)),
        }
    }

    /// Writes one datagram. Refuses invalid packet fields, lengthless packets before the end,
    /// mixed IDs, a short-header ID of the wrong length, and size or packet-count limits.
    /// Packet checks reject oversized IDs or packet numbers, mismatched versions, invalid first-byte
    /// bits, an empty version list, and a Retry without a token. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.0.is_empty() || self.0.len() > MAX_COALESCED {
            return Err(Error::Unwritable);
        }
        let mut bytes = Vec::new();
        for (i, packet) in self.0.iter().enumerate() {
            if (i + 1 < self.0.len() && !packet.has_length())
                || packet.dcid() != self.0[0].dcid()
                || matches!(packet, Packet::Short { dcid, .. } if dcid.len() != SHORT_DCID_LEN)
            {
                return Err(Error::Unwritable);
            }
            let encoded = packet.encode().map_err(|_| Error::Unwritable)?;
            if encoded.len() > MAX_DATAGRAM.saturating_sub(bytes.len()) {
                return Err(Error::Unwritable);
            }
            bytes.extend_from_slice(&encoded);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

// Frames (RFC 9000, section 19).

/// One acknowledged range past the first in an ACK frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRange {
    /// How many packets are skipped below the previous range, less one.
    pub gap: u64,
    /// How many packets this range covers, less one.
    pub len: u64,
}

/// The ECN counts an ACK frame of type 0x03 carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcnCounts {
    /// Packets received with the ECT(0) codepoint.
    pub ect0: u64,
    /// Packets received with the ECT(1) codepoint.
    pub ect1: u64,
    /// Packets received with the CE codepoint.
    pub ce: u64,
}

/// An ACK frame: which packets of one space have arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    /// The largest packet number acknowledged.
    pub largest: u64,
    /// How long the acknowledgment was held back, in units set by the
    /// ack_delay_exponent transport parameter.
    pub delay: u64,
    /// How many packets below `largest` the first range covers.
    pub first_range: u64,
    /// The ranges below the first, from largest to smallest.
    pub ranges: Vec<AckRange>,
    /// ECN counts, which make the frame type 0x03.
    pub ecn: Option<EcnCounts>,
}

impl Ack {
    /// The acknowledged packet numbers as (smallest, largest) pairs, from
    /// the largest down. It returns `None` if a range runs below 0 or
    /// there are more than [`MAX_ACK_RANGES`] extra ranges.
    pub fn packets(&self) -> Option<Vec<(u64, u64)>> {
        if self.ranges.len() > MAX_ACK_RANGES || self.largest > MAX_VARINT {
            return None;
        }
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        let mut smallest = self.largest.checked_sub(self.first_range)?;
        out.push((smallest, self.largest));
        for r in &self.ranges {
            let largest = smallest.checked_sub(r.gap)?.checked_sub(2)?;
            smallest = largest.checked_sub(r.len)?;
            out.push((smallest, largest));
        }
        Some(out)
    }

    /// An ACK frame for `ranges`: (smallest, largest) pairs from the
    /// largest down, with at least one packet between neighbors. It
    /// returns `None` if `ranges` is empty or out of order, or has more
    /// than [`MAX_ACK_RANGES`] ranges past the first.
    pub fn from_ranges(ranges: &[(u64, u64)], delay: u64) -> Option<Ack> {
        let (&(low, high), rest) = ranges.split_first()?;
        if rest.len() > MAX_ACK_RANGES || high > MAX_VARINT {
            return None;
        }
        let first_range = high.checked_sub(low)?;
        let mut prev = low;
        let mut out = Vec::with_capacity(rest.len());
        for &(low, high) in rest {
            let gap = prev.checked_sub(high)?.checked_sub(2)?;
            out.push(AckRange { gap, len: high.checked_sub(low)? });
            prev = low;
        }
        Some(Ack { largest: high, delay, first_range, ranges: out, ecn: None })
    }

    /// Whether packet number `pn` is acknowledged.
    pub fn contains(&self, pn: u64) -> bool {
        self.packets().is_some_and(|ps| ps.iter().any(|&(lo, hi)| (lo..=hi).contains(&pn)))
    }
}

/// A STREAM frame: bytes of one stream at an offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFrame {
    /// The stream ID.
    pub id: u64,
    /// Where `data` starts in the stream. When 0, the offset field is
    /// left out.
    pub offset: u64,
    /// The stream bytes.
    pub data: Vec<u8>,
    /// Whether this frame ends the stream.
    pub fin: bool,
    /// Whether a length field is written. Without one, the data runs to
    /// the end of the packet. [`Payload`] refuses such a frame before the last.
    pub length: bool,
}

/// One frame. PADDING bytes in a row are read as one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// This many PADDING bytes (type 0x00), at least 1.
    Padding(usize),
    /// PING (0x01): asks for an acknowledgment.
    Ping,
    /// ACK (0x02, or 0x03 with ECN counts).
    Ack(Ack),
    /// RESET_STREAM (0x04): the sender abandons `stream` at `final_size`
    /// bytes, with an application `error_code`.
    ResetStream {
        /// The QUIC stream ID.
        stream: u64,
        /// The application or transport error code.
        error_code: u64,
        /// The final stream size in bytes.
        final_size: u64,
    },
    /// STOP_SENDING (0x05): asks the peer to stop sending on `stream`.
    StopSending {
        /// The QUIC stream ID.
        stream: u64,
        /// The application or transport error code.
        error_code: u64,
    },
    /// CRYPTO (0x06): TLS handshake bytes at `offset`.
    Crypto {
        /// The starting byte offset.
        offset: u64,
        /// The frame data.
        data: Vec<u8>,
    },
    /// NEW_TOKEN (0x07): a token, never empty, for a later Initial.
    NewToken(Vec<u8>),
    /// STREAM (0x08 to 0x0f).
    Stream(StreamFrame),
    /// MAX_DATA (0x10): the connection's flow control limit in bytes.
    MaxData(u64),
    /// MAX_STREAM_DATA (0x11): `stream`'s flow control limit in bytes.
    MaxStreamData {
        /// The QUIC stream ID.
        stream: u64,
        /// The advertised limit.
        max: u64,
    },
    /// MAX_STREAMS (0x12 when `bidi`, 0x13 if not): how many streams the
    /// peer may open, at most [`MAX_STREAM_COUNT`].
    MaxStreams {
        /// Whether the limit applies to bidirectional streams.
        bidi: bool,
        /// The advertised limit.
        max: u64,
    },
    /// DATA_BLOCKED (0x14): the sender is held at this connection limit.
    DataBlocked(u64),
    /// STREAM_DATA_BLOCKED (0x15): the sender is held at `limit` on
    /// `stream`.
    StreamDataBlocked {
        /// The QUIC stream ID.
        stream: u64,
        /// The limit that blocked transmission.
        limit: u64,
    },
    /// STREAMS_BLOCKED (0x16 when `bidi`, 0x17 if not): the sender wants
    /// more streams than `limit`, at most [`MAX_STREAM_COUNT`].
    StreamsBlocked {
        /// Whether the limit applies to bidirectional streams.
        bidi: bool,
        /// The limit that blocked transmission.
        limit: u64,
    },
    /// NEW_CONNECTION_ID (0x18): another connection ID, of 1 to
    /// [`MAX_CID_LEN`] bytes, numbered `sequence`. The peer retires those
    /// numbered below `retire_prior_to`, which is at most `sequence`.
    NewConnectionId {
        /// The connection-ID sequence number.
        sequence: u64,
        /// Retire connection IDs with smaller sequence numbers.
        retire_prior_to: u64,
        /// The new connection ID.
        id: Vec<u8>,
        /// The stateless reset token.
        reset_token: [u8; RESET_TOKEN_LEN],
    },
    /// RETIRE_CONNECTION_ID (0x19): the sequence number to retire.
    RetireConnectionId(u64),
    /// PATH_CHALLENGE (0x1a): 8 bytes the peer must echo.
    PathChallenge([u8; 8]),
    /// PATH_RESPONSE (0x1b): the echoed bytes.
    PathResponse([u8; 8]),
    /// CONNECTION_CLOSE: 0x1c with the `frame_type` that caused a
    /// transport error, or 0x1d, an application close, when it is `None`.
    /// `reason` should be UTF-8, and is kept as bytes.
    ConnectionClose {
        /// The application or transport error code.
        error_code: u64,
        /// The offending frame type for a transport close, or None for an application close.
        frame_type: Option<u64>,
        /// Reason bytes, normally UTF-8.
        reason: Vec<u8>,
    },
    /// HANDSHAKE_DONE (0x1e): the server says the handshake is confirmed.
    HandshakeDone,
}

impl Frame {
    /// Reads the frame at the start of `b`, a packet payload or what is
    /// left of one, and returns it with how many bytes it took. A run of
    /// PADDING takes every 0x00 byte in a row. Like [`Payload`], it
    /// refuses more than [`MAX_PAYLOAD`] bytes.
    fn parse_prefix(b: &[u8]) -> Result<(Frame, usize), Error> {
        if b.len() > MAX_PAYLOAD {
            return Err(Error::TooLong(b.len()));
        }
        let mut r = Reader::new(b);
        let frame = parse_frame(&mut r)?;
        Ok((frame, r.pos))
    }

    /// The frame's type. A STREAM frame's type has its flags set as
    /// [`Wire::write`] would write them.
    pub fn frame_type(&self) -> u64 {
        use frame_type as t;
        match self {
            Frame::Padding(_) => t::PADDING,
            Frame::Ping => t::PING,
            Frame::Ack(a) => {
                if a.ecn.is_some() {
                    t::ACK_ECN
                } else {
                    t::ACK
                }
            }
            Frame::ResetStream { .. } => t::RESET_STREAM,
            Frame::StopSending { .. } => t::STOP_SENDING,
            Frame::Crypto { .. } => t::CRYPTO,
            Frame::NewToken(_) => t::NEW_TOKEN,
            Frame::Stream(s) => stream_type(s),
            Frame::MaxData(_) => t::MAX_DATA,
            Frame::MaxStreamData { .. } => t::MAX_STREAM_DATA,
            Frame::MaxStreams { bidi: true, .. } => t::MAX_STREAMS_BIDI,
            Frame::MaxStreams { bidi: false, .. } => t::MAX_STREAMS_UNI,
            Frame::DataBlocked(_) => t::DATA_BLOCKED,
            Frame::StreamDataBlocked { .. } => t::STREAM_DATA_BLOCKED,
            Frame::StreamsBlocked { bidi: true, .. } => t::STREAMS_BLOCKED_BIDI,
            Frame::StreamsBlocked { bidi: false, .. } => t::STREAMS_BLOCKED_UNI,
            Frame::NewConnectionId { .. } => t::NEW_CONNECTION_ID,
            Frame::RetireConnectionId(_) => t::RETIRE_CONNECTION_ID,
            Frame::PathChallenge(_) => t::PATH_CHALLENGE,
            Frame::PathResponse(_) => t::PATH_RESPONSE,
            Frame::ConnectionClose { frame_type: Some(_), .. } => t::CONNECTION_CLOSE,
            Frame::ConnectionClose { frame_type: None, .. } => t::CONNECTION_CLOSE_APP,
            Frame::HandshakeDone => t::HANDSHAKE_DONE,
        }
    }

    /// Whether RFC 9000 (table 3) allows this frame in packets of `space`.
    /// A peer that sends one where it is not allowed has broken the
    /// protocol.
    pub fn allowed_in(&self, space: Space) -> bool {
        let one_rtt = space == Space::OneRtt;
        let app = matches!(space, Space::ZeroRtt | Space::OneRtt);
        match self {
            Frame::Padding(_) | Frame::Ping => true,
            Frame::ConnectionClose { frame_type: Some(_), .. } => true,
            Frame::Ack(_) | Frame::Crypto { .. } => space != Space::ZeroRtt,
            // RFC 9000, section 12.5, and erratum 7365, which corrects
            // table 3: RETIRE_CONNECTION_ID is not allowed in 0-RTT.
            Frame::NewToken(_) | Frame::PathResponse(_) | Frame::HandshakeDone | Frame::RetireConnectionId(_) => {
                one_rtt
            }
            _ => app,
        }
    }

    /// Whether a frame asks the peer for an acknowledgment. All do but
    /// ACK, PADDING and CONNECTION_CLOSE.
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(self, Frame::Ack(_) | Frame::Padding(_) | Frame::ConnectionClose { .. })
    }

    // Appends a checked frame into a temporary payload buffer.
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        use frame_type as t;
        let ty = self.frame_type();
        match self {
            Frame::Padding(n) => {
                if *n == 0 {
                    return Err(Error::FrameEncoding(t::PADDING));
                }
                if *n > MAX_PAYLOAD {
                    return Err(Error::TooLong(*n));
                }
                out.resize(out.len().checked_add(*n).ok_or(Error::Unwritable)?, 0);
            }
            Frame::Ping | Frame::HandshakeDone => out.push(ty as u8),
            Frame::Ack(a) => {
                if a.ranges.len() > MAX_ACK_RANGES {
                    return Err(Error::TooManyAckRanges(ty));
                }
                if a.packets().is_none() {
                    return Err(Error::FrameEncoding(ty));
                }
                out.push(ty as u8);
                put(out, &[a.largest, a.delay, a.ranges.len() as u64, a.first_range])?;
                for r in &a.ranges {
                    put(out, &[r.gap, r.len])?;
                }
                if let Some(e) = a.ecn {
                    put(out, &[e.ect0, e.ect1, e.ce])?;
                }
            }
            Frame::ResetStream { stream, error_code, final_size } => {
                out.push(ty as u8);
                put(out, &[*stream, *error_code, *final_size])?;
            }
            Frame::StopSending { stream, error_code } => {
                out.push(ty as u8);
                put(out, &[*stream, *error_code])?;
            }
            Frame::Crypto { offset, data } => {
                check_len(data.len())?;
                check_end(ty, *offset, data.len())?;
                out.push(ty as u8);
                put(out, &[*offset, data.len() as u64])?;
                out.extend_from_slice(data);
            }
            Frame::NewToken(token) => {
                if token.is_empty() {
                    return Err(Error::FrameEncoding(ty));
                }
                check_len(token.len())?;
                out.push(ty as u8);
                put(out, &[token.len() as u64])?;
                out.extend_from_slice(token);
            }
            Frame::Stream(s) => {
                let ty = stream_type(s);
                check_len(s.data.len())?;
                check_end(ty, s.offset, s.data.len())?;
                out.push(ty as u8);
                put(out, &[s.id])?;
                if ty & t::STREAM_OFF != 0 {
                    put(out, &[s.offset])?;
                }
                if ty & t::STREAM_LEN != 0 {
                    put(out, &[s.data.len() as u64])?;
                }
                out.extend_from_slice(&s.data);
            }
            Frame::MaxData(v) | Frame::DataBlocked(v) | Frame::RetireConnectionId(v) => {
                out.push(ty as u8);
                put(out, &[*v])?;
            }
            Frame::MaxStreamData { stream, max: v } | Frame::StreamDataBlocked { stream, limit: v } => {
                out.push(ty as u8);
                put(out, &[*stream, *v])?;
            }
            Frame::MaxStreams { max: v, .. } | Frame::StreamsBlocked { limit: v, .. } => {
                if *v > MAX_STREAM_COUNT {
                    return Err(Error::FrameEncoding(ty));
                }
                out.push(ty as u8);
                put(out, &[*v])?;
            }
            Frame::NewConnectionId { sequence, retire_prior_to, id, reset_token } => {
                if id.is_empty() || id.len() > MAX_CID_LEN || retire_prior_to > sequence {
                    return Err(Error::FrameEncoding(ty));
                }
                out.push(ty as u8);
                put(out, &[*sequence, *retire_prior_to])?;
                out.push(id.len() as u8);
                out.extend_from_slice(id);
                out.extend_from_slice(reset_token);
            }
            Frame::PathChallenge(d) | Frame::PathResponse(d) => {
                out.push(ty as u8);
                out.extend_from_slice(d);
            }
            Frame::ConnectionClose { error_code, frame_type, reason } => {
                check_len(reason.len())?;
                out.push(ty as u8);
                put(out, &[*error_code])?;
                if let Some(f) = frame_type {
                    put(out, &[*f])?;
                }
                put(out, &[reason.len() as u64])?;
                out.extend_from_slice(reason);
            }
        }
        Ok(())
    }
}

/// The type byte a STREAM frame is written with.
fn stream_type(s: &StreamFrame) -> u64 {
    use frame_type as t;
    let mut ty = t::STREAM;
    if s.offset != 0 {
        ty |= t::STREAM_OFF;
    }
    if s.length {
        ty |= t::STREAM_LEN;
    }
    if s.fin {
        ty |= t::STREAM_FIN;
    }
    ty
}

/// Checks that data of `len` bytes at `offset` ends at or below
/// [`MAX_VARINT`].
fn check_end(ty: u64, offset: u64, len: usize) -> Result<(), Error> {
    match offset.checked_add(len as u64) {
        Some(end) if end <= MAX_VARINT => Ok(()),
        _ => Err(Error::FrameEncoding(ty)),
    }
}

fn put(out: &mut Vec<u8>, values: &[u64]) -> Result<(), Error> {
    values.iter().try_for_each(|v| put_varint(*v, out))
}

fn parse_frame(r: &mut Reader<'_>) -> Result<Frame, Error> {
    let start = r.pos;
    let ty = r.varint()?;
    if varint_len(ty) != Some(r.pos - start) {
        return Err(Error::LongFrameType(ty));
    }
    // A frame cut short by the payload's end is badly formatted.
    parse_body(ty, r).map_err(|e| if e == Error::Truncated { Error::FrameEncoding(ty) } else { e })
}

fn parse_body(ty: u64, r: &mut Reader<'_>) -> Result<Frame, Error> {
    use frame_type as t;
    let frame = match ty {
        t::PADDING => {
            let mut n = 1;
            while r.peek() == Some(0) {
                r.pos += 1;
                n += 1;
            }
            Frame::Padding(n)
        }
        t::PING => Frame::Ping,
        t::ACK | t::ACK_ECN => {
            let largest = r.varint()?;
            let delay = r.varint()?;
            let count = r.varint()?;
            if count > MAX_ACK_RANGES as u64 {
                return Err(Error::TooManyAckRanges(ty));
            }
            let first_range = r.varint()?;
            // Each range takes at least 2 bytes.
            let mut ranges = Vec::with_capacity((count as usize).min(r.left() / 2));
            for _ in 0..count {
                ranges.push(AckRange { gap: r.varint()?, len: r.varint()? });
            }
            let ecn = if ty == t::ACK_ECN {
                Some(EcnCounts { ect0: r.varint()?, ect1: r.varint()?, ce: r.varint()? })
            } else {
                None
            };
            let ack = Ack { largest, delay, first_range, ranges, ecn };
            if ack.packets().is_none() {
                return Err(Error::FrameEncoding(ty));
            }
            Frame::Ack(ack)
        }
        t::RESET_STREAM => Frame::ResetStream { stream: r.varint()?, error_code: r.varint()?, final_size: r.varint()? },
        t::STOP_SENDING => Frame::StopSending { stream: r.varint()?, error_code: r.varint()? },
        t::CRYPTO => {
            let offset = r.varint()?;
            let len = r.varint()?;
            let data = r.take_u64(len)?.to_vec();
            check_end(ty, offset, data.len())?;
            Frame::Crypto { offset, data }
        }
        t::NEW_TOKEN => {
            let len = r.varint()?;
            if len == 0 {
                return Err(Error::FrameEncoding(ty));
            }
            Frame::NewToken(r.take_u64(len)?.to_vec())
        }
        0x08..=0x0f => {
            let id = r.varint()?;
            let offset = if ty & t::STREAM_OFF != 0 { r.varint()? } else { 0 };
            let length = ty & t::STREAM_LEN != 0;
            let data = if length {
                let len = r.varint()?;
                r.take_u64(len)?
            } else {
                r.rest()
            };
            check_end(ty, offset, data.len())?;
            Frame::Stream(StreamFrame { id, offset, data: data.to_vec(), fin: ty & t::STREAM_FIN != 0, length })
        }
        t::MAX_DATA => Frame::MaxData(r.varint()?),
        t::MAX_STREAM_DATA => Frame::MaxStreamData { stream: r.varint()?, max: r.varint()? },
        t::MAX_STREAMS_BIDI | t::MAX_STREAMS_UNI => {
            let max = r.varint()?;
            if max > MAX_STREAM_COUNT {
                return Err(Error::FrameEncoding(ty));
            }
            Frame::MaxStreams { bidi: ty == t::MAX_STREAMS_BIDI, max }
        }
        t::DATA_BLOCKED => Frame::DataBlocked(r.varint()?),
        t::STREAM_DATA_BLOCKED => Frame::StreamDataBlocked { stream: r.varint()?, limit: r.varint()? },
        t::STREAMS_BLOCKED_BIDI | t::STREAMS_BLOCKED_UNI => {
            let limit = r.varint()?;
            if limit > MAX_STREAM_COUNT {
                return Err(Error::FrameEncoding(ty));
            }
            Frame::StreamsBlocked { bidi: ty == t::STREAMS_BLOCKED_BIDI, limit }
        }
        t::NEW_CONNECTION_ID => {
            let sequence = r.varint()?;
            let retire_prior_to = r.varint()?;
            let len = usize::from(r.u8()?);
            if len == 0 || len > MAX_CID_LEN || retire_prior_to > sequence {
                return Err(Error::FrameEncoding(ty));
            }
            let id = r.take(len)?.to_vec();
            let reset_token = r.array::<RESET_TOKEN_LEN>()?;
            Frame::NewConnectionId { sequence, retire_prior_to, id, reset_token }
        }
        t::RETIRE_CONNECTION_ID => Frame::RetireConnectionId(r.varint()?),
        t::PATH_CHALLENGE => Frame::PathChallenge(r.array::<8>()?),
        t::PATH_RESPONSE => Frame::PathResponse(r.array::<8>()?),
        t::CONNECTION_CLOSE | t::CONNECTION_CLOSE_APP => {
            let error_code = r.varint()?;
            let frame_type = if ty == t::CONNECTION_CLOSE { Some(r.varint()?) } else { None };
            let len = r.varint()?;
            let reason = r.take_u64(len)?.to_vec();
            Frame::ConnectionClose { error_code, frame_type, reason }
        }
        t::HANDSHAKE_DONE => Frame::HandshakeDone,
        _ => return Err(Error::UnknownFrame(ty)),
    };
    Ok(frame)
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one frame. Refuses trailing bytes, malformed fields, nonminimal frame types,
    /// and payloads larger than [`MAX_PAYLOAD`]. A padding run is one frame.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(Self::parse_prefix(bytes), bytes.len())
    }

    /// Writes a frame. Refuses invalid fields, zero padding, and excessive payload size.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes).map_err(|_| Error::Unwritable)?;
        if bytes.len() > MAX_PAYLOAD {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// A packet's complete frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload(
    /// Frames in transmitted order.
    pub Vec<Frame>,
);

impl Wire for Payload {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads all frames. Refuses empty or oversized payloads, excessive frame counts,
    /// malformed fields, and frame types that are unknown or use a longer encoding.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::Empty);
        }
        if bytes.len() > MAX_PAYLOAD {
            return Err(Error::TooLong(bytes.len()));
        }
        let mut reader = Reader::new(bytes);
        let mut frames = Vec::new();
        while reader.left() > 0 {
            if frames.len() == MAX_FRAMES {
                return Err(Error::TooManyFrames);
            }
            frames.push(parse_frame(&mut reader)?);
        }
        Ok(Self(frames))
    }

    /// Writes all frames. Refuses invalid frames, empty or excessive lists, oversized payloads,
    /// adjacent padding frames, and a lengthless STREAM frame before the last frame.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.0.is_empty() || self.0.len() > MAX_FRAMES {
            return Err(Error::Unwritable);
        }
        let mut bytes = Vec::new();
        for (i, frame) in self.0.iter().enumerate() {
            if matches!(frame, Frame::Stream(s) if !s.length && i + 1 < self.0.len())
                || (matches!(frame, Frame::Padding(_))
                    && self.0.get(i + 1).is_some_and(|f| matches!(f, Frame::Padding(_))))
            {
                return Err(Error::Unwritable);
            }
            frame.write(&mut bytes)?;
            if bytes.len() > MAX_PAYLOAD {
                return Err(Error::Unwritable);
            }
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

// Putting stream data back in order.

/// Puts CRYPTO or STREAM data back in order. Frames may arrive out of
/// order, more than once, or overlapping. Pass each frame's offset and
/// bytes to [`Reassembler::insert`], and take the bytes that are now in
/// order with [`Reassembler::read`]. Where two frames overlap, the bytes
/// that came first are kept. It holds at most [`MAX_REASSEMBLY`] bytes
/// past what has been read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reassembler {
    /// The stream offset of `buf[0]`: how many bytes have been read.
    start: u64,
    // Queues, so reading a few bytes off the front does not move the
    // rest of what is held.
    buf: std::collections::VecDeque<u8>,
    have: std::collections::VecDeque<bool>,
}

impl Reassembler {
    /// A reassembler that has read nothing.
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// Adds `data`, which starts at stream offset `offset`. Bytes already
    /// read are ignored. It fails, keeping nothing, if the data ends past
    /// [`MAX_VARINT`] or more than [`MAX_REASSEMBLY`] bytes past what has
    /// been read.
    pub fn insert(&mut self, offset: u64, data: &[u8]) -> Result<(), Error> {
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Window(u64::MAX))?;
        if end > MAX_VARINT {
            return Err(Error::Window(end));
        }
        if end <= self.start {
            return Ok(());
        }
        // end > start, so neither subtraction underflows.
        let rel_end = end - self.start;
        if rel_end > MAX_REASSEMBLY as u64 {
            return Err(Error::Window(end));
        }
        let rel_end = rel_end as usize;
        let from = offset.max(self.start);
        let rel_from = (from - self.start) as usize;
        let skip = (from - offset) as usize;
        if self.buf.len() < rel_end {
            self.buf.resize(rel_end, 0);
            self.have.resize(rel_end, false);
        }
        // rel_from < rel_end <= buf.len(), as from < end, so neither range
        // is out of bounds.
        let dst = self.buf.range_mut(rel_from..rel_end);
        let got = self.have.range_mut(rel_from..rel_end);
        let src = data.get(skip..).unwrap_or_default();
        for ((d, h), s) in dst.zip(got).zip(src) {
            if !*h {
                *d = *s;
                *h = true;
            }
        }
        Ok(())
    }

    /// Takes the bytes that are now in order, past those already read.
    pub fn read(&mut self) -> Vec<u8> {
        let n = self.have.iter().take_while(|h| **h).count();
        self.have.drain(..n);
        self.start += n as u64;
        self.buf.drain(..n).collect()
    }

    /// How many bytes have been read: the stream offset the next byte
    /// read will have.
    pub fn offset(&self) -> u64 {
        self.start
    }

    /// How many bytes past the read offset are held, counting gaps.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

/// Reads fields from a byte slice. `pos` never passes the slice's end.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, pos: 0 }
    }

    fn left(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.b.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn take_u64(&mut self, n: u64) -> Result<&'a [u8], Error> {
        self.take(usize::try_from(n).map_err(|_| Error::Truncated)?)
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = self.b.get(self.pos..).unwrap_or_default();
        self.pos = self.b.len();
        s
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut a = [0; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn varint(&mut self) -> Result<u64, Error> {
        let (v, n) = read_varint(self.b.get(self.pos..).unwrap_or_default())?;
        self.pos += n;
        Ok(v)
    }

    fn cid(&mut self) -> Result<Vec<u8>, Error> {
        let n = usize::from(self.u8()?);
        Ok(self.take(n)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::codec::{
        contract,
        Lcg, test_support::{mutate},
    };
    use super::*;

    fn datagram(packets: &[Packet]) -> Result<Vec<u8>, Error> {
        let len = packets
            .iter()
            .find_map(|packet| match packet {
                Packet::Short { dcid, .. } => Some(dcid.len()),
                _ => None,
            })
            .unwrap_or(0);
        macro_rules! dispatch {
            ($($n:literal),* $(,)?) => {
                match len {
                    $($n => Datagram::<$n>(packets.to_vec()).to_bytes(),)*
                    _ => Err(Error::Unwritable),
                }
            };
        }
        dispatch!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20)
    }

    fn check_payload(bytes: &[u8]) {
        contract::check_wire::<Payload>(bytes);
        if let Ok(payload) = Payload::parse(bytes) {
            assert!(payload.to_bytes().unwrap().len() <= bytes.len());
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
        s.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
    }

    fn roundtrip_frames(frames: &[Frame]) {
        let bytes = Payload((frames).to_vec()).to_bytes().unwrap();
        assert_eq!(Payload::parse(&bytes).map(|payload| payload.0).unwrap(), frames, "{bytes:02x?}");
    }

    // RFC 9000, appendix A.1.
    #[test]
    fn varint_examples() {
        for (bytes, value) in [
            ("c2197c5eff14e88c", 151_288_809_941_952_652u64),
            ("9d7f3e7d", 494_878_333),
            ("7bbd", 15_293),
            ("25", 37),
            ("4025", 37),
        ] {
            let b = hex(bytes);
            assert_eq!(read_varint(&b), Ok((value, b.len())));
        }
        let mut out = Vec::new();
        VarInt(151_288_809_941_952_652).write(&mut out).unwrap();
        VarInt(494_878_333).write(&mut out).unwrap();
        VarInt(15_293).write(&mut out).unwrap();
        VarInt(37).write(&mut out).unwrap();
        assert_eq!(out, hex("c2197c5eff14e88c 9d7f3e7d 7bbd 25"));
    }

    #[test]
    fn varint_bounds() {
        for v in [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, MAX_VARINT] {
            let mut out = Vec::new();
            VarInt(v).write(&mut out).unwrap();
            assert_eq!(Some(out.len()), varint_len(v));
            assert_eq!(read_varint(&out), Ok((v, out.len())));
            for cut in 0..out.len() {
                assert_eq!(read_varint(&out[..cut]), Err(Error::Truncated));
            }
        }
        let mut out = Vec::new();
        assert_eq!(VarInt(MAX_VARINT + 1).write(&mut out), Err(Error::Unwritable));
        assert_eq!(varint_len(u64::MAX), None);
        assert!(out.is_empty());
    }

    // RFC 9000, appendix A.2 and A.3.
    #[test]
    fn packet_number_examples() {
        let pn = PacketNumber { value: 0x9b32, len: 2 };
        assert_eq!(pn.decode(Some(0xa82f_30ea)), Some(0xa82f_9b32));
        assert_eq!(PacketNumber::encode(0xac5c02, Some(0xabe8b3)).unwrap().len, 2);
        assert_eq!(PacketNumber::encode(0xace8fe, Some(0xabe8b3)).unwrap().len, 3);
        assert_eq!(PacketNumber::encode(0, None), Some(PacketNumber { value: 0, len: 1 }));
        assert_eq!(PacketNumber::encode(5, Some(5)), None);
        assert_eq!(PacketNumber::encode(1 << 40, None), None);
        assert_eq!(PacketNumber::encode(MAX_VARINT + 1, None), None);
        assert_eq!(PacketNumber { value: 0, len: 5 }.decode(None), None);
        assert_eq!(PacketNumber { value: 256, len: 1 }.decode(None), None);
        assert_eq!(PacketNumber { value: 0, len: 1 }.decode(Some(u64::MAX)), None);
        assert_eq!(PacketNumber { value: 3, len: 1 }.decode(None), Some(3));
        // Near the top of the space, the decoder does not wrap past it.
        let top = PacketNumber { value: 0xff, len: 1 };
        assert_eq!(top.decode(Some(MAX_VARINT)), Some(MAX_VARINT));
        assert_eq!(PacketNumber { value: 0, len: 1 }.decode(Some(MAX_VARINT - 1)), Some((1 << 62) - 256));
        // Every encoding decodes back to the full number.
        let mut largest = None;
        for full in (0..2_000_000u64).step_by(997) {
            let pn = PacketNumber::encode(full, largest).unwrap();
            assert_eq!(pn.decode(largest), Some(full));
            largest = Some(full);
        }
    }

    // RFC 9001, appendix A.2: the client Initial, unprotected.
    #[test]
    fn rfc9001_client_initial() {
        let mut b = hex("c300000001088394c8f03e5157080000449e00000002");
        let crypto = Frame::Crypto { offset: 0, data: vec![0x01; 241] };
        let mut payload = crypto.to_bytes().unwrap();
        assert_eq!(payload[..4], hex("060040f1"));
        payload.resize(1182 - 4, 0);
        b.extend_from_slice(&payload);
        let (p, used) = Packet::parse(&b, 0).unwrap();
        assert_eq!(used, b.len());
        assert_eq!(
            p,
            Packet::Initial {
                version: VERSION_1,
                dcid: hex("8394c8f03e515708"),
                scid: vec![],
                token: vec![],
                number: PacketNumber { value: 2, len: 4 },
                payload: payload.clone(),
            }
        );
        assert_eq!(p.space(), Some(Space::Initial));
        assert_eq!(p.dcid(), hex("8394c8f03e515708"));
        assert_eq!(datagram(std::slice::from_ref(&p)).unwrap(), b);
        let frames = Payload::parse(p.payload().unwrap()).map(|payload| payload.0).unwrap();
        assert_eq!(frames, [crypto, Frame::Padding(1182 - 4 - 245)]);
        assert!(frames.iter().all(|f| f.allowed_in(Space::Initial)));
    }

    // RFC 9001, appendix A.3: the server Initial, unprotected, with an ACK
    // and a CRYPTO frame. The last 16 bytes stand in for the AEAD tag.
    #[test]
    fn rfc9001_server_initial() {
        let mut b = hex("c1000000010008f067a5502a4262b50040750001");
        let mut frames = hex("02000000000600405a");
        frames.extend_from_slice(&[0x02; 90]);
        b.extend_from_slice(&frames);
        b.extend_from_slice(&[0xee; 16]);
        let (p, used) = Packet::parse(&b, 0).unwrap();
        assert_eq!(used, b.len());
        let Packet::Initial { scid, number, payload, .. } = &p else { panic!("{p:?}") };
        assert_eq!(scid, &hex("f067a5502a4262b5"));
        assert_eq!(*number, PacketNumber { value: 1, len: 2 });
        assert_eq!(payload.len(), 0x75 - 2);
        let read = Payload::parse(&payload[..payload.len() - 16]).map(|payload| payload.0).unwrap();
        let ack = Ack { largest: 0, delay: 0, first_range: 0, ranges: vec![], ecn: None };
        assert_eq!(read, [Frame::Ack(ack), Frame::Crypto { offset: 0, data: vec![0x02; 90] }]);
        assert_eq!(Payload((read).to_vec()).to_bytes().unwrap(), frames);
        assert_eq!(datagram(std::slice::from_ref(&p)).unwrap(), b);
    }

    // RFC 9001, appendix A.4 and RFC 9369, appendix A.4: Retry packets.
    #[test]
    fn retry_examples() {
        for (bytes, version, tag) in [
            (
                "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
                VERSION_1,
                "04a265ba2eff4d829058fb3f0f2496ba",
            ),
            (
                "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6",
                VERSION_2,
                "c8646ce8bfe33952d955543665dcc7b6",
            ),
        ] {
            let b = hex(bytes);
            let (p, used) = Packet::parse(&b, 0).unwrap();
            assert_eq!(used, b.len());
            let mut t = [0; 16];
            t.copy_from_slice(&hex(tag));
            let want = Packet::Retry {
                version,
                unused: 0x0f,
                dcid: vec![],
                scid: hex("f067a5502a4262b5"),
                token: b"token".to_vec(),
                tag: t,
            };
            assert_eq!(p, want);
            assert_eq!(p.space(), None);
            assert_eq!(p.payload(), None);
            assert_eq!(datagram(std::slice::from_ref(&p)).unwrap(), b);
        }
    }

    // RFC 9001, appendix A.5: a short header packet holding a PING.
    #[test]
    fn rfc9001_short_header() {
        let b = hex("4200bff401");
        let (p, used) = Packet::parse(&b, 0).unwrap();
        assert_eq!(used, 5);
        let number = PacketNumber { value: 0xbff4, len: 3 };
        assert_eq!(p, Packet::Short { spin: false, key_phase: false, dcid: vec![], number, payload: vec![1] });
        assert_eq!(number.decode(Some(654_360_563)), Some(654_360_564));
        assert_eq!(Payload::parse(p.payload().unwrap()).map(|payload| payload.0).unwrap(), [Frame::Ping]);
        assert_eq!(datagram(std::slice::from_ref(&p)).unwrap(), b);
        // The spin and key phase bits, with a connection ID.
        let p = Packet::Short {
            spin: true,
            key_phase: true,
            dcid: vec![7; 8],
            number: PacketNumber { value: 0x1234_5678, len: 4 },
            payload: vec![0x1e],
        };
        let b = datagram(std::slice::from_ref(&p)).unwrap();
        assert_eq!(b[0], 0x40 | 0x20 | 0x04 | 0x03);
        assert_eq!(Packet::parse(&b, 8).unwrap(), (p, b.len()));
    }

    #[test]
    fn version_2_types() {
        // In version 2, Initial is 0b01, 0-RTT 0b10, Handshake 0b11.
        let number = PacketNumber { value: 9, len: 1 };
        let (d, s) = (vec![1, 2], vec![3]);
        for (p, bits) in [
            (
                Packet::Initial {
                    version: VERSION_2,
                    dcid: d.clone(),
                    scid: s.clone(),
                    token: vec![5; 3],
                    number,
                    payload: vec![1],
                },
                1,
            ),
            (Packet::ZeroRtt { version: VERSION_2, dcid: d.clone(), scid: s.clone(), number, payload: vec![1] }, 2),
            (Packet::Handshake { version: VERSION_2, dcid: d.clone(), scid: s.clone(), number, payload: vec![1] }, 3),
            (Packet::ZeroRtt { version: VERSION_1, dcid: d.clone(), scid: s.clone(), number, payload: vec![1] }, 1),
            (Packet::Handshake { version: VERSION_1, dcid: d.clone(), scid: s.clone(), number, payload: vec![1] }, 2),
        ] {
            let b = datagram(std::slice::from_ref(&p)).unwrap();
            assert_eq!((b[0] >> 4) & 3, bits, "{p:?}");
            assert_eq!(Packet::parse(&b, 0).unwrap(), (p, b.len()));
        }
    }

    #[test]
    fn version_negotiation_and_other_versions() {
        let vn = Packet::VersionNegotiation {
            unused: 0x55,
            dcid: vec![9; 200],
            scid: vec![],
            versions: vec![VERSION_1, VERSION_2, 0x0a0a_0a0a],
        };
        let b = datagram(std::slice::from_ref(&vn)).unwrap();
        assert_eq!(b[..6], [0xd5, 0, 0, 0, 0, 200]);
        assert_eq!(Packet::parse(&b, 0).unwrap(), (vn, b.len()));
        let other = Packet::OtherVersion {
            bits: 0x7f,
            version: 0xff00_001d,
            dcid: vec![1; 255],
            scid: vec![2; 30],
            rest: vec![3; 10],
        };
        let b = datagram(std::slice::from_ref(&other)).unwrap();
        assert_eq!(Packet::parse(&b, 0).unwrap(), (other, b.len()));
        // A Version Negotiation packet whose versions are cut short.
        let mut b =
            Datagram::<0>(vec![Packet::VersionNegotiation { unused: 0, dcid: vec![], scid: vec![], versions: vec![1] }]).to_bytes().unwrap();
        b.pop();
        assert_eq!(Packet::parse(&b, 0), Err(Error::VersionList(3)));
    }

    #[test]
    fn coalesced_datagram() {
        let number = PacketNumber { value: 0, len: 1 };
        let initial = Packet::Initial {
            version: VERSION_1,
            dcid: vec![1; 8],
            scid: vec![2; 8],
            token: vec![],
            number,
            payload: Payload(([Frame::Crypto { offset: 0, data: vec![4; 100] }]).to_vec()).to_bytes().unwrap(),
        };
        let handshake = Packet::Handshake {
            version: VERSION_1,
            dcid: vec![1; 8],
            scid: vec![2; 8],
            number,
            payload: Payload(([Frame::Ping]).to_vec()).to_bytes().unwrap(),
        };
        let short = Packet::Short { spin: false, key_phase: false, dcid: vec![1; 8], number, payload: vec![0x1e] };
        let packets = vec![initial.clone(), handshake.clone(), short.clone()];
        let b = datagram(&packets).unwrap();
        assert_eq!(split_datagram(&b, 8), (packets, None));
        // Only the last packet may lack a Length field.
        assert_eq!(datagram(&[short.clone(), initial.clone()]), Err(Error::Unwritable));
        assert_eq!(datagram(&[]), Err(Error::Unwritable));
        assert_eq!(datagram(&vec![handshake.clone(); MAX_COALESCED + 1]), Err(Error::Unwritable));
        // A broken packet keeps the ones before it.
        let mut b = datagram(&[initial.clone(), handshake.clone()]).unwrap();
        b.push(0x00);
        assert_eq!(split_datagram(&b, 8), (vec![initial, handshake.clone()], Some(Error::FixedBit)));
        assert_eq!(split_datagram(&[], 8), (vec![], Some(Error::Empty)));
        let many = vec![datagram(std::slice::from_ref(&handshake)).unwrap(); MAX_COALESCED + 1].concat();
        let (got, err) = split_datagram(&many, 0);
        assert_eq!((got.len(), err), (MAX_COALESCED, Some(Error::TooManyPackets)));
        assert_eq!(split_datagram(&vec![0x40; MAX_DATAGRAM + 1], 0).1, Some(Error::TooLong(MAX_DATAGRAM + 1)));
    }

    fn sample_frames() -> Vec<Frame> {
        let ack = Ack::from_ranges(&[(90, 100), (50, 80), (0, 0)], 25).unwrap();
        let ecn = Ack { ecn: Some(EcnCounts { ect0: 1, ect1: 2, ce: 3 }), ..ack.clone() };
        vec![
            Frame::Ping,
            Frame::Ack(ack),
            Frame::Ack(ecn),
            Frame::ResetStream { stream: 4, error_code: 0x10c, final_size: 100_000 },
            Frame::StopSending { stream: 8, error_code: 0 },
            Frame::Crypto { offset: 1 << 20, data: vec![0xaa; 300] },
            Frame::NewToken(vec![1, 2, 3]),
            Frame::Stream(StreamFrame { id: 0, offset: 0, data: b"GET /".to_vec(), fin: false, length: true }),
            Frame::Stream(StreamFrame { id: 1 << 40, offset: 77, data: vec![], fin: true, length: true }),
            Frame::MaxData(1 << 50),
            Frame::MaxStreamData { stream: 3, max: 65_536 },
            Frame::MaxStreams { bidi: true, max: MAX_STREAM_COUNT },
            Frame::MaxStreams { bidi: false, max: 3 },
            Frame::DataBlocked(10),
            Frame::StreamDataBlocked { stream: 2, limit: 20 },
            Frame::StreamsBlocked { bidi: true, limit: 0 },
            Frame::StreamsBlocked { bidi: false, limit: 100 },
            Frame::NewConnectionId { sequence: 3, retire_prior_to: 1, id: vec![0xc1; 20], reset_token: [0x5a; 16] },
            Frame::RetireConnectionId(2),
            Frame::PathChallenge(*b"12345678"),
            Frame::PathResponse(*b"87654321"),
            Frame::ConnectionClose { error_code: 0x0a, frame_type: Some(0x08), reason: b"bad".to_vec() },
            Frame::ConnectionClose { error_code: 0x100, frame_type: None, reason: vec![] },
            Frame::HandshakeDone,
            Frame::Padding(3),
            Frame::Stream(StreamFrame { id: 5, offset: 9, data: b"tail".to_vec(), fin: true, length: false }),
        ]
    }

    #[test]
    fn every_frame_round_trips() {
        let frames = sample_frames();
        roundtrip_frames(&frames);
        for f in &frames {
            let b = f.to_bytes().unwrap();
            assert_eq!(Frame::parse(&b), Ok(f.clone()), "{f:?}");
            assert_eq!(Payload::parse(&b).map(|payload| payload.0).unwrap(), std::slice::from_ref(f));
            if !matches!(f, Frame::Stream(_)) {
                assert_eq!(read_varint(&b).unwrap().0, f.frame_type());
            }
        }
        // Each frame type's bytes, for a few.
        assert_eq!(Frame::Ping.to_bytes().unwrap(), [0x01]);
        assert_eq!(Frame::HandshakeDone.to_bytes().unwrap(), [0x1e]);
        assert_eq!(Frame::MaxData(15_293).to_bytes().unwrap(), hex("107bbd"));
        assert_eq!(
            Frame::ConnectionClose { error_code: 7, frame_type: Some(6), reason: b"x".to_vec() }.to_bytes().unwrap(),
            hex("1c07060178")
        );
        let s = StreamFrame { id: 4, offset: 0, data: b"hi".to_vec(), fin: true, length: false };
        assert_eq!(Frame::Stream(s.clone()).to_bytes().unwrap(), hex("09046869"));
        // Not last, a STREAM frame gets a length.
        assert_eq!(Payload(vec![Frame::Stream(s.clone()), Frame::Ping]).to_bytes(), Err(Error::Unwritable));
        let mut s = s;
        s.length = true;
        let b = Payload(vec![Frame::Stream(s.clone()), Frame::Ping]).to_bytes().unwrap();
        assert_eq!(b, hex("0b0402686901"));
        let with_len = StreamFrame { length: true, ..s };
        assert_eq!(Payload::parse(&b).map(|payload| payload.0).unwrap(), [Frame::Stream(with_len), Frame::Ping]);
        // An offset field holding 0 reads as no offset.
        assert_eq!(
            Payload::parse(&hex("0c040068")).map(|payload| payload.0).unwrap(),
            Payload::parse(&hex("080468")).map(|payload| payload.0).unwrap()
        );
        // Longer encodings than needed are accepted in fields.
        assert_eq!(Payload::parse(&hex("1040ff")).map(|payload| payload.0).unwrap(), [Frame::MaxData(0xff)]);
    }

    #[test]
    fn frame_rules() {
        assert!(Frame::Ping.is_ack_eliciting());
        assert!(!Frame::Padding(1).is_ack_eliciting());
        assert!(!Frame::Ack(Ack::from_ranges(&[(0, 0)], 0).unwrap()).is_ack_eliciting());
        // RFC 9000, table 3.
        let close = Frame::ConnectionClose { error_code: 0, frame_type: Some(0), reason: vec![] };
        let app_close = Frame::ConnectionClose { error_code: 0, frame_type: None, reason: vec![] };
        let crypto = Frame::Crypto { offset: 0, data: vec![] };
        let stream = Frame::Stream(StreamFrame { id: 0, offset: 0, data: vec![], fin: false, length: false });
        let ack = Frame::Ack(Ack::from_ranges(&[(0, 0)], 0).unwrap());
        for (f, want) in [
            (Frame::Padding(1), [true, true, true, true]),
            (Frame::Ping, [true, true, true, true]),
            (close, [true, true, true, true]),
            (ack, [true, false, true, true]),
            (crypto, [true, false, true, true]),
            (Frame::NewToken(vec![1]), [false, false, false, true]),
            (Frame::HandshakeDone, [false, false, false, true]),
            (Frame::PathResponse([0; 8]), [false, false, false, true]),
            (Frame::PathChallenge([0; 8]), [false, true, false, true]),
            (stream, [false, true, false, true]),
            (app_close, [false, true, false, true]),
            (Frame::MaxData(0), [false, true, false, true]),
        ] {
            let got = [Space::Initial, Space::ZeroRtt, Space::Handshake, Space::OneRtt].map(|s| f.allowed_in(s));
            assert_eq!(got, want, "{f:?}");
        }
    }

    #[test]
    fn ack_ranges() {
        let ack = Ack::from_ranges(&[(90, 100), (50, 80), (0, 0)], 25).unwrap();
        assert_eq!(ack.largest, 100);
        assert_eq!(ack.first_range, 10);
        assert_eq!(ack.ranges, [AckRange { gap: 8, len: 30 }, AckRange { gap: 48, len: 0 }]);
        assert_eq!(ack.packets().unwrap(), [(90, 100), (50, 80), (0, 0)]);
        assert!(ack.contains(95) && ack.contains(0) && ack.contains(50));
        assert!(!ack.contains(85) && !ack.contains(1) && !ack.contains(101));
        // Ranges that touch, overlap, or run the wrong way.
        assert_eq!(Ack::from_ranges(&[(10, 20), (5, 9)], 0), None);
        assert_eq!(Ack::from_ranges(&[(10, 20), (5, 15)], 0), None);
        assert_eq!(Ack::from_ranges(&[(20, 10)], 0), None);
        assert_eq!(Ack::from_ranges(&[], 0), None);
        assert!(Ack::from_ranges(&[(10, 20), (5, 8)], 0).is_some());
        let too_many: Vec<(u64, u64)> = (0..=MAX_ACK_RANGES as u64 + 1).rev().map(|i| (i * 2, i * 2)).collect();
        assert_eq!(Ack::from_ranges(&too_many, 0), None);
        assert!(Ack::from_ranges(&too_many[..MAX_ACK_RANGES + 1], 0).is_some());
    }

    #[test]
    fn packet_errors() {
        let number = PacketNumber { value: 0, len: 1 };
        let hs = |dcid: Vec<u8>| Packet::Handshake { version: VERSION_1, dcid, scid: vec![], number, payload: vec![1] };
        // Reading.
        assert_eq!(Packet::parse(&[], 0), Err(Error::Truncated));
        assert_eq!(Packet::parse(&vec![0x40; MAX_DATAGRAM + 1], 0), Err(Error::TooLong(MAX_DATAGRAM + 1)));
        assert_eq!(Packet::parse(&[0x00, 0, 1], 0), Err(Error::FixedBit));
        assert_eq!(Packet::parse(&[0x48, 0, 1], 0), Err(Error::ReservedBits));
        assert_eq!(Packet::parse(&[0x40, 0, 1], 21), Err(Error::ConnectionIdLength(21)));
        assert_eq!(Packet::parse(&[0x40, 0, 1], 3), Err(Error::Truncated));
        let mut b = datagram(&[hs(vec![])]).unwrap();
        b[0] &= !0x40;
        assert_eq!(Packet::parse(&b, 0), Err(Error::FixedBit));
        b[0] |= 0x40 | 0x04;
        assert_eq!(Packet::parse(&b, 0), Err(Error::ReservedBits));
        let mut b = datagram(&[hs(vec![])]).unwrap();
        b[7] = 0; // The Length field.
        assert_eq!(Packet::parse(&b, 0), Err(Error::Length(0)));
        b[7] = 3;
        assert_eq!(Packet::parse(&b, 0), Err(Error::Truncated));
        let mut b = vec![0xe0, 0, 0, 0, 1, 21];
        b.extend_from_slice(&[0; 22]);
        assert_eq!(Packet::parse(&b, 0), Err(Error::ConnectionIdLength(21)));
        let retry = hex("ff000000010008f067a5502a4262b504a265ba2eff4d829058fb3f0f2496ba");
        assert_eq!(Packet::parse(&retry, 0), Err(Error::EmptyToken));
        assert_eq!(Packet::parse(&retry[..retry.len() - 1], 0), Err(Error::Truncated));
        assert_eq!(Packet::parse(&retry[..20], 0), Err(Error::Truncated));
        // Writing.
        assert_eq!(datagram(&[hs(vec![0; 21])]), Err(Error::Unwritable));
        let bad = Packet::Handshake { version: 7, dcid: vec![], scid: vec![], number, payload: vec![] };
        assert_eq!(datagram(std::slice::from_ref(&bad)), Err(Error::Unwritable));
        let bad = Packet::OtherVersion { bits: 0, version: VERSION_1, dcid: vec![], scid: vec![], rest: vec![] };
        assert_eq!(datagram(std::slice::from_ref(&bad)), Err(Error::Unwritable));
        let bad = Packet::OtherVersion { bits: 0, version: 9, dcid: vec![0; 256], scid: vec![], rest: vec![] };
        assert_eq!(datagram(std::slice::from_ref(&bad)), Err(Error::Unwritable));
        for number in
            [PacketNumber { value: 256, len: 1 }, PacketNumber { value: 0, len: 0 }, PacketNumber { value: 0, len: 5 }]
        {
            let p = Packet::Short { spin: false, key_phase: false, dcid: vec![], number, payload: vec![1] };
            assert_eq!(datagram(std::slice::from_ref(&p)), Err(Error::Unwritable));
        }
        let p = Packet::Short { spin: false, key_phase: false, dcid: vec![0; 21], number, payload: vec![1] };
        assert_eq!(datagram(std::slice::from_ref(&p)), Err(Error::Unwritable));
        let p =
            Packet::Short { spin: false, key_phase: false, dcid: vec![0; 20], number, payload: vec![0; MAX_DATAGRAM] };
        assert_eq!(datagram(std::slice::from_ref(&p)), Err(Error::Unwritable));
        let p =
            Packet::Retry { version: VERSION_2, unused: 0, dcid: vec![], scid: vec![], token: vec![], tag: [0; 16] };
        assert_eq!(datagram(std::slice::from_ref(&p)), Err(Error::Unwritable));
    }

    #[test]
    fn frame_errors() {
        use frame_type as t;
        assert_eq!(Payload::parse(&[]).map(|payload| payload.0), Err(Error::Empty));
        assert_eq!(
            Payload::parse(&vec![1; MAX_PAYLOAD + 1]).map(|payload| payload.0),
            Err(Error::TooLong(MAX_PAYLOAD + 1))
        );
        assert_eq!(Payload::parse(&vec![1; MAX_FRAMES + 1]).map(|payload| payload.0), Err(Error::TooManyFrames));
        assert_eq!(Payload::parse(&vec![1; MAX_FRAMES]).map(|payload| payload.0).unwrap().len(), MAX_FRAMES);
        assert_eq!(Payload::parse(&[0x1f]).map(|payload| payload.0), Err(Error::UnknownFrame(0x1f)));
        assert_eq!(Payload::parse(&hex("4040")).map(|payload| payload.0), Err(Error::UnknownFrame(0x40)));
        assert_eq!(Payload::parse(&hex("4030")).map(|payload| payload.0), Err(Error::LongFrameType(0x30)));
        assert_eq!(Payload::parse(&hex("4001")).map(|payload| payload.0), Err(Error::LongFrameType(t::PING)));
        // ACK ranges below 0.
        assert_eq!(Payload::parse(&hex("0205000006")).map(|payload| payload.0), Err(Error::FrameEncoding(t::ACK)));
        assert_eq!(Payload::parse(&hex("02050001000400")).map(|payload| payload.0), Err(Error::FrameEncoding(t::ACK)));
        assert_eq!(Payload::parse(&hex("02050001000202")).map(|payload| payload.0), Err(Error::FrameEncoding(t::ACK)));
        assert_eq!(
            Payload::parse(&hex("02050001000100")).map(|payload| payload.0),
            Ok(vec![Frame::Ack(Ack::from_ranges(&[(5, 5), (2, 2)], 0).unwrap())])
        );
        let mut b = vec![0x02, 0, 0];
        VarInt(MAX_ACK_RANGES as u64 + 1).write(&mut b).unwrap();
        assert_eq!(Payload::parse(&b).map(|payload| payload.0), Err(Error::TooManyAckRanges(t::ACK)));
        assert_eq!(Error::TooManyAckRanges(t::ACK).frame_type(), Some(t::ACK));
        // Data ending past 2^62 - 1.
        assert_eq!(
            Payload::parse(&hex("06ffffffffffffffff0100")).map(|payload| payload.0),
            Err(Error::FrameEncoding(t::CRYPTO))
        );
        assert_eq!(
            Payload::parse(&hex("0c00ffffffffffffffff00")).map(|payload| payload.0),
            Err(Error::FrameEncoding(0x0c))
        );
        assert_eq!(Payload::parse(&hex("0700")).map(|payload| payload.0), Err(Error::FrameEncoding(t::NEW_TOKEN)));
        assert_eq!(
            Payload::parse(&hex("12d000000000000001")).map(|payload| payload.0),
            Err(Error::FrameEncoding(t::MAX_STREAMS_BIDI))
        );
        assert_eq!(
            Payload::parse(&hex("17d000000000000001")).map(|payload| payload.0),
            Err(Error::FrameEncoding(t::STREAMS_BLOCKED_UNI))
        );
        assert_eq!(
            Payload::parse(&hex("18010000")).map(|payload| payload.0),
            Err(Error::FrameEncoding(t::NEW_CONNECTION_ID))
        );
        assert_eq!(
            Payload::parse(&hex("18010015")).map(|payload| payload.0),
            Err(Error::FrameEncoding(t::NEW_CONNECTION_ID))
        );
        assert_eq!(
            Payload::parse(&hex("18010201")).map(|payload| payload.0),
            Err(Error::FrameEncoding(t::NEW_CONNECTION_ID))
        );
        // Writing.
        assert_eq!(Payload(([]).to_vec()).to_bytes(), Err(Error::Unwritable));
        assert_eq!(Payload((vec![Frame::Ping; MAX_FRAMES + 1]).to_vec()).to_bytes(), Err(Error::Unwritable));
        assert_eq!(Frame::Padding(0).to_bytes(), Err(Error::Unwritable));
        assert_eq!(Frame::Padding(MAX_PAYLOAD + 1).to_bytes(), Err(Error::Unwritable));
        assert_eq!(Payload(([Frame::Padding(MAX_PAYLOAD), Frame::Ping]).to_vec()).to_bytes(), Err(Error::Unwritable));
        assert_eq!(Frame::MaxData(MAX_VARINT + 1).to_bytes(), Err(Error::Unwritable));
        assert_eq!(Frame::NewToken(vec![]).to_bytes(), Err(Error::Unwritable));
        assert_eq!(Frame::MaxStreams { bidi: false, max: MAX_STREAM_COUNT + 1 }.to_bytes(), Err(Error::Unwritable));
        assert_eq!(
            Frame::StreamsBlocked { bidi: true, limit: MAX_STREAM_COUNT + 1 }.to_bytes(),
            Err(Error::Unwritable)
        );
        assert_eq!(Frame::Crypto { offset: MAX_VARINT, data: vec![1] }.to_bytes(), Err(Error::Unwritable));
        let s = StreamFrame { id: 0, offset: MAX_VARINT, data: vec![1], fin: false, length: false };
        assert_eq!(Frame::Stream(s).to_bytes(), Err(Error::Unwritable));
        for (id, retire) in [(vec![], 0), (vec![0; 21], 0), (vec![1], 2)] {
            let f = Frame::NewConnectionId { sequence: 1, retire_prior_to: retire, id, reset_token: [0; 16] };
            assert_eq!(f.to_bytes(), Err(Error::Unwritable));
        }
        let bad = Ack { largest: 5, delay: 0, first_range: 6, ranges: vec![], ecn: None };
        assert_eq!(Frame::Ack(bad).to_bytes(), Err(Error::Unwritable));
        let many = Ack {
            largest: 0,
            delay: 0,
            first_range: 0,
            ranges: vec![AckRange { gap: 0, len: 0 }; MAX_ACK_RANGES + 1],
            ecn: None,
        };
        assert_eq!(Frame::Ack(many).to_bytes(), Err(Error::Unwritable));
        // Codes for CONNECTION_CLOSE.
        assert_eq!(Error::UnknownFrame(0x40).transport_code(), error_code::FRAME_ENCODING_ERROR);
        assert_eq!(Error::UnknownFrame(0x40).frame_type(), Some(0x40));
        assert_eq!(Error::Empty.transport_code(), error_code::PROTOCOL_VIOLATION);
        assert_eq!(Error::Empty.frame_type(), None);
        assert_eq!(Error::Unwritable.transport_code(), error_code::INTERNAL_ERROR);
        assert_eq!(Error::Window(0).transport_code(), error_code::CRYPTO_BUFFER_EXCEEDED);
    }

    // Fixes from a review against RFC 9000.
    #[test]
    fn spec_review() {
        use frame_type as t;
        // Section 12.4: a frame type in a longer encoding than needed is a
        // PROTOCOL_VIOLATION, not a FRAME_ENCODING_ERROR.
        assert_eq!(Payload::parse(&hex("4001")).map(|payload| payload.0), Err(Error::LongFrameType(t::PING)));
        assert_eq!(Error::LongFrameType(t::PING).transport_code(), error_code::PROTOCOL_VIOLATION);
        assert_eq!(Error::LongFrameType(t::PING).frame_type(), Some(t::PING));
        // Section 20.1: a frame cut short by the payload's end is badly
        // formatted, a FRAME_ENCODING_ERROR naming its type.
        assert_eq!(Payload::parse(&hex("0600")).map(|payload| payload.0), Err(Error::FrameEncoding(t::CRYPTO)));
        assert_eq!(
            Payload::parse(&hex("1a0102")).map(|payload| payload.0),
            Err(Error::FrameEncoding(t::PATH_CHALLENGE))
        );
        assert_eq!(Payload::parse(&hex("0b0005ff")).map(|payload| payload.0), Err(Error::FrameEncoding(0x0b)));
        assert_eq!(Payload::parse(&hex("0140")).map(|payload| payload.0), Err(Error::Truncated));
        assert_eq!(Error::Truncated.transport_code(), error_code::FRAME_ENCODING_ERROR);
        // Section 12.2: packets in one datagram share a destination
        // connection ID. A sender must not mix them, and a receiver
        // ignores the packets after one that differs.
        let number = PacketNumber { value: 0, len: 1 };
        let hs = |dcid: Vec<u8>| Packet::Handshake { version: VERSION_1, dcid, scid: vec![], number, payload: vec![1] };
        let (a, b) = (hs(vec![1; 8]), hs(vec![2; 8]));
        assert_eq!(datagram(&[a.clone(), b.clone()]), Err(Error::Unwritable));
        let bytes = [datagram(std::slice::from_ref(&a)).unwrap(), datagram(std::slice::from_ref(&b)).unwrap()].concat();
        assert_eq!(split_datagram(&bytes, 8), (vec![a.clone()], Some(Error::MixedConnectionIds)));
        let short = Packet::Short { spin: false, key_phase: false, dcid: vec![1; 8], number, payload: vec![1] };
        let bytes = datagram(&[a.clone(), short.clone()]).unwrap();
        assert_eq!(split_datagram(&bytes, 8), (vec![a, short], None));
    }

    #[test]
    fn second_review() {
        use frame_type as t;
        // Frame::parse holds to MAX_PAYLOAD as Payload does, so
        // whatever it reads can be written.
        let zeros = vec![0; MAX_PAYLOAD + 1];
        assert_eq!(Frame::parse(&zeros), Err(Error::TooLong(MAX_PAYLOAD + 1)));
        assert_eq!(Frame::parse(&zeros[..MAX_PAYLOAD]), Ok(Frame::Padding(MAX_PAYLOAD)));
        let mut crypto = hex("06007fff");
        crypto.resize(MAX_PAYLOAD + 1, 0);
        assert_eq!(Frame::parse(&crypto), Err(Error::TooLong(MAX_PAYLOAD + 1)));

        // RFC 9000, section 12.5 and erratum 7365: RETIRE_CONNECTION_ID
        // is not allowed in 0-RTT.
        let retire = Frame::RetireConnectionId(0);
        let got = [Space::Initial, Space::ZeroRtt, Space::Handshake, Space::OneRtt].map(|s| retire.allowed_in(s));
        assert_eq!(got, [false, false, false, true]);

        // RFC 8999, section 6: a Version Negotiation packet with no
        // versions is ignored, so it is neither read nor written.
        assert_eq!(Packet::parse(&hex("c0 00000000 00 00"), 0), Err(Error::VersionList(0)));
        let empty = Packet::VersionNegotiation { unused: 0x40, dcid: vec![], scid: vec![], versions: vec![] };
        assert_eq!(datagram(std::slice::from_ref(&empty)), Err(Error::Unwritable));

        // RFC 9000, section 12.3: 0-RTT and 1-RTT packets share one
        // packet number space.
        assert_eq!(Space::ZeroRtt.number_space(), Space::OneRtt);
        for s in [Space::Initial, Space::Handshake, Space::OneRtt] {
            assert_eq!(s.number_space(), s);
        }

        // Writers refuse first-byte bits that do not fit their field,
        // rather than dropping them.
        let vn = Packet::VersionNegotiation { unused: 0x80, dcid: vec![], scid: vec![], versions: vec![VERSION_1] };
        assert_eq!(datagram(std::slice::from_ref(&vn)), Err(Error::Unwritable));
        let retry = Packet::Retry {
            version: VERSION_1,
            unused: 0x10,
            dcid: vec![],
            scid: vec![],
            token: vec![1],
            tag: [0; RETRY_TAG_LEN],
        };
        assert_eq!(datagram(std::slice::from_ref(&retry)), Err(Error::Unwritable));
        let other = Packet::OtherVersion { bits: 0x80, version: 5, dcid: vec![], scid: vec![], rest: vec![] };
        assert_eq!(datagram(std::slice::from_ref(&other)), Err(Error::Unwritable));

        // An ACK frame with too many ranges names its own type, 0x02 or
        // 0x03.
        for ty in [t::ACK, t::ACK_ECN] {
            let mut b = vec![ty as u8, 0, 0];
            VarInt(MAX_ACK_RANGES as u64 + 1).write(&mut b).unwrap();
            assert_eq!(Payload::parse(&b).map(|payload| payload.0), Err(Error::TooManyAckRanges(ty)));
            assert_eq!(Error::TooManyAckRanges(ty).frame_type(), Some(ty));
        }
        let ranges = vec![AckRange { gap: 0, len: 0 }; MAX_ACK_RANGES + 1];
        let ecn = Some(EcnCounts { ect0: 0, ect1: 0, ce: 0 });
        let ack = Frame::Ack(Ack { largest: MAX_VARINT, delay: 0, first_range: 0, ranges, ecn });
        assert_eq!(ack.to_bytes(), Err(Error::Unwritable));

        // The Length field covers the payload as it is on the wire,
        // AEAD tag included. A sender reserves the tag's bytes at the end
        // of the payload before it protects the packet.
        let mut payload = Payload(([Frame::Ping]).to_vec()).to_bytes().unwrap();
        payload.resize(payload.len() + 16, 0);
        let hs = Packet::Handshake {
            version: VERSION_1,
            dcid: vec![],
            scid: vec![],
            number: PacketNumber { value: 0, len: 1 },
            payload,
        };
        let b = datagram(std::slice::from_ref(&hs)).unwrap();
        assert_eq!(b[7], 1 + 1 + 16);
        assert_eq!(Packet::parse(&b, 0).unwrap(), (hs, b.len()));
    }

    #[test]
    fn errors_display() {
        let all = [
            Error::Truncated,
            Error::TooLong(1),
            Error::FixedBit,
            Error::ReservedBits,
            Error::ConnectionIdLength(21),
            Error::Length(0),
            Error::VersionList(3),
            Error::EmptyToken,
            Error::Empty,
            Error::Unwritable,
            Error::Trailing,
            Error::UnknownFrame(0x40),
            Error::FrameEncoding(0x18),
            Error::LongFrameType(0x01),
            Error::TooManyFrames,
            Error::TooManyAckRanges(2),
            Error::TooManyPackets,
            Error::MixedConnectionIds,
            Error::Window(9),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
    }

    fn sample_packets() -> Vec<(Packet, usize)> {
        let number = PacketNumber { value: 0x0102, len: 2 };
        let payload = Payload((sample_frames()).to_vec()).to_bytes().unwrap();
        let mut tag = [0; 16];
        tag[3] = 9;
        vec![
            (
                Packet::Initial {
                    version: VERSION_1,
                    dcid: vec![1; 8],
                    scid: vec![2; 5],
                    token: vec![3; 40],
                    number,
                    payload: payload.clone(),
                },
                0,
            ),
            (
                Packet::ZeroRtt {
                    version: VERSION_2,
                    dcid: vec![1; 20],
                    scid: vec![],
                    number,
                    payload: payload.clone(),
                },
                0,
            ),
            (
                Packet::Handshake { version: VERSION_1, dcid: vec![], scid: vec![4], number, payload: payload.clone() },
                0,
            ),
            (
                Packet::Retry {
                    version: VERSION_1,
                    unused: 3,
                    dcid: vec![1],
                    scid: vec![2; 8],
                    token: vec![7; 30],
                    tag,
                },
                0,
            ),
            (Packet::Short { spin: true, key_phase: false, dcid: vec![5; 8], number, payload }, 8),
            (
                Packet::VersionNegotiation { unused: 1, dcid: vec![1; 3], scid: vec![2; 4], versions: vec![VERSION_1] },
                0,
            ),
            (Packet::OtherVersion { bits: 0x40, version: 0x5, dcid: vec![1], scid: vec![], rest: vec![9; 5] }, 0),
        ]
    }

    #[test]
    fn every_packet_round_trips() {
        for (p, n) in sample_packets() {
            let b = datagram(std::slice::from_ref(&p)).unwrap();
            assert_eq!(Packet::parse(&b, n), Ok((p.clone(), b.len())));
            assert_eq!(split_datagram(&b, n), (vec![p], None));
        }
    }

    // Every strict prefix of a packet or payload is refused, or, for the
    // kinds that take the rest of a datagram, read as a different packet.
    // Nothing panics.
    #[test]
    fn every_truncated_prefix() {
        for (p, n) in sample_packets() {
            let b = datagram(std::slice::from_ref(&p)).unwrap();
            for cut in 0..b.len() {
                if let Ok((q, used)) = Packet::parse(&b[..cut], n) {
                    assert!(!p.has_length(), "{p:?} at {cut}");
                    assert_ne!(q, p);
                    assert_eq!(used, cut);
                }
            }
        }
        // Every frame but those that end at the payload's end refuses each
        // prefix.
        for f in sample_frames() {
            let b = f.to_bytes().unwrap();
            let open = matches!(f, Frame::Padding(_) | Frame::Stream(StreamFrame { length: false, .. }));
            for cut in 0..b.len() {
                let r = Payload::parse(&b[..cut]).map(|payload| payload.0);
                if open && cut > 0 {
                    assert_ne!(r.ok(), Some(vec![f.clone()]));
                } else {
                    assert!(r.is_err(), "{f:?} at {cut}: {r:?}");
                }
            }
        }
        // The whole sample payload, too.
        let b = Payload((sample_frames()).to_vec()).to_bytes().unwrap();
        for cut in 0..b.len() {
            assert_ne!(Payload::parse(&b[..cut]).map(|payload| payload.0).ok(), Some(sample_frames()));
        }
    }

    #[test]
    fn reassembler() {
        // In order.
        let mut r = Reassembler::new();
        r.insert(0, b"hello ").unwrap();
        r.insert(6, b"world").unwrap();
        assert_eq!(r.read(), b"hello world");
        assert_eq!((r.offset(), r.buffered()), (11, 0));
        assert_eq!(r.read(), b"");
        // Out of order, overlapping and repeated.
        let mut r = Reassembler::new();
        r.insert(6, b"world").unwrap();
        assert_eq!(r.read(), b"");
        assert_eq!(r.buffered(), 11);
        r.insert(3, b"lo wo").unwrap();
        r.insert(0, b"hel").unwrap();
        r.insert(0, b"HELLO").unwrap();
        assert_eq!(r.read(), b"hello world");
        r.insert(2, b"xx").unwrap();
        assert_eq!(r.read(), b"");
        // The window.
        let mut r = Reassembler::new();
        assert_eq!(r.insert(MAX_REASSEMBLY as u64, b"x"), Err(Error::Window(MAX_REASSEMBLY as u64 + 1)));
        r.insert(MAX_REASSEMBLY as u64 - 1, b"x").unwrap();
        assert_eq!(r.insert(MAX_VARINT, b"x"), Err(Error::Window(MAX_VARINT + 1)));
        assert_eq!(r.insert(u64::MAX, b"x"), Err(Error::Window(u64::MAX)));
        assert_eq!(r.buffered(), MAX_REASSEMBLY);
        r.insert(0, &vec![1; MAX_REASSEMBLY - 1]).unwrap();
        assert_eq!(r.read().len(), MAX_REASSEMBLY);
        assert_eq!(r.buffered(), 0);
        r.insert(MAX_REASSEMBLY as u64, &vec![2; MAX_REASSEMBLY]).unwrap();
        assert_eq!(r.read(), vec![2; MAX_REASSEMBLY]);
    }

    // The CRYPTO frames of a payload, inserted into a reassembler one byte at a
    // time, last byte first, give the same stream as one frame.
    #[test]
    fn reassembler_one_byte_at_a_time() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
        let mut frames = Vec::new();
        for (i, b) in data.iter().enumerate().rev() {
            frames.push(Frame::Crypto { offset: i as u64, data: vec![*b] });
        }
        let payload = Payload((frames[..1000]).to_vec()).to_bytes().unwrap();
        let mut r = Reassembler::new();
        for chunk in frames.chunks(1000) {
            let payload_frames =
                Payload::parse(&Payload((chunk).to_vec()).to_bytes().unwrap()).map(|payload| payload.0).unwrap();
            for f in payload_frames {
                let Frame::Crypto { offset, data } = f else { panic!() };
                r.insert(offset, &data).unwrap();
            }
        }
        assert_eq!(r.read(), data);
        assert!(!payload.is_empty());
    }

    // Found in the hardening review: accessors a world needs to answer a
    // packet, a frame writer that made bytes Payload refused, and a
    // reassembler that moved everything it held on each small read.
    #[test]
    fn hardening_review() {
        // Accessors.
        for (p, _) in sample_packets() {
            assert_eq!(p.scid().is_none(), matches!(p, Packet::Short { .. }));
            assert_eq!(p.version().is_none(), matches!(p, Packet::Short { .. }));
            assert_eq!(p.number().is_some(), p.payload().is_some());
        }
        let vn = Packet::VersionNegotiation { unused: 0x40, dcid: vec![1], scid: vec![2, 3], versions: vec![] };
        assert_eq!((vn.scid(), vn.version(), vn.number()), (Some(&[2, 3][..]), Some(VERSION_NEGOTIATION), None));
        let n = PacketNumber { value: 7, len: 1 };
        let short = Packet::Short { spin: false, key_phase: false, dcid: vec![], number: n, payload: vec![1] };
        assert_eq!((short.scid(), short.version(), short.number()), (None, None, Some(n)));

        // Frame::to_bytes never writes more than Payload reads.
        let big = vec![0; MAX_PAYLOAD];
        let crypto = Frame::Crypto { offset: 0, data: big.clone() };
        assert_eq!(crypto.to_bytes(), Err(Error::Unwritable));
        let stream = Frame::Stream(StreamFrame { id: 0, offset: 0, data: big.clone(), fin: false, length: false });
        assert!(matches!(stream.to_bytes(), Err(Error::Unwritable)));
        let close = Frame::ConnectionClose { error_code: 0, frame_type: None, reason: big };
        assert!(matches!(close.to_bytes(), Err(Error::Unwritable)));
        let crypto = Frame::Crypto { offset: 0, data: vec![0; MAX_PAYLOAD + 1] };
        assert_eq!(crypto.to_bytes(), Err(Error::Unwritable));
        let fits = Frame::Crypto { offset: 0, data: vec![0; MAX_PAYLOAD - 1 - 1 - 4] };
        assert_eq!(Payload::parse(&fits.to_bytes().unwrap()).map(|payload| payload.0).unwrap(), [fits]);

        // A reassembler read one byte at a time, with a byte held at the
        // far end of its window, gives the stream in order. With a queue,
        // each read costs the bytes read, not the bytes held.
        let mut r = Reassembler::new();
        let mut read = Vec::new();
        for i in 0..20_000u64 {
            r.insert(i + MAX_REASSEMBLY as u64 - 1, &[9]).unwrap();
            r.insert(i, &[i as u8]).unwrap();
            read.extend(r.read());
            assert_eq!(r.buffered(), MAX_REASSEMBLY - 1);
        }
        assert_eq!(read, (0..20_000u64).map(|i| i as u8).collect::<Vec<_>>());
        assert_eq!(r.clone(), r);
        assert_eq!(Reassembler::new(), Reassembler::default());
    }

    fn random_value(rng: &mut Lcg) -> u64 {
        match rng.index(6) {
            0 => rng.index(64) as u64,
            1 => rng.index(20_000) as u64,
            2 => rng.next(),
            3 => MAX_VARINT - rng.index(3) as u64,
            4 => MAX_VARINT + rng.index(3) as u64,
            _ => (rng.next() << 30) | rng.next(),
        }
    }

    fn random_frame(rng: &mut Lcg) -> Frame {
        let small = |rng: &mut Lcg| rng.bytes(12);
        match rng.index(22) {
            0 => Frame::Padding(rng.index(4)),
            1 => Frame::Ping,
            2 => {
                let ranges =
                    (0..rng.index(4)).map(|_| AckRange { gap: random_value(rng) % 50, len: random_value(rng) % 50 }).collect();
                let ecn = if rng.coin() { None } else { Some(EcnCounts { ect0: random_value(rng), ect1: 1, ce: 2 }) };
                Frame::Ack(Ack {
                    largest: random_value(rng),
                    delay: random_value(rng),
                    first_range: random_value(rng) % 100,
                    ranges,
                    ecn,
                })
            }
            3 => Frame::ResetStream {
                stream: random_value(rng),
                error_code: random_value(rng),
                final_size: random_value(rng),
            },
            4 => Frame::StopSending { stream: random_value(rng), error_code: random_value(rng) },
            5 => Frame::Crypto { offset: random_value(rng), data: small(rng) },
            6 => Frame::NewToken(small(rng)),
            7 => Frame::Stream(StreamFrame {
                id: random_value(rng),
                offset: random_value(rng),
                data: small(rng),
                fin: rng.coin(),
                length: rng.coin(),
            }),
            8 => Frame::MaxData(random_value(rng)),
            9 => Frame::MaxStreamData { stream: random_value(rng), max: random_value(rng) },
            10 => Frame::MaxStreams { bidi: rng.coin(), max: random_value(rng) >> rng.index(4) },
            11 => Frame::DataBlocked(random_value(rng)),
            12 => Frame::StreamDataBlocked { stream: random_value(rng), limit: random_value(rng) },
            13 => Frame::StreamsBlocked { bidi: rng.coin(), limit: random_value(rng) >> rng.index(4) },
            14 => Frame::NewConnectionId {
                sequence: random_value(rng),
                retire_prior_to: random_value(rng),
                id: rng.bytes(23),
                reset_token: [7; 16],
            },
            15 => Frame::RetireConnectionId(random_value(rng)),
            16 => Frame::PathChallenge([rng.next() as u8; 8]),
            17 => Frame::PathResponse([rng.next() as u8; 8]),
            18 => Frame::ConnectionClose {
                error_code: random_value(rng),
                frame_type: Some(random_value(rng)),
                reason: small(rng),
            },
            19 => Frame::ConnectionClose { error_code: random_value(rng), frame_type: None, reason: small(rng) },
            20 => Frame::HandshakeDone,
            _ => Frame::Ping,
        }
    }

    #[test]
    fn payload_writer_refuses_changes_and_keeps_the_destination() {
        for payload in [
            Payload(vec![Frame::Padding(1), Frame::Padding(2)]),
            Payload(vec![
                Frame::Stream(StreamFrame { id: 0, offset: 0, data: vec![1], fin: false, length: false }),
                Frame::Ping,
            ]),
        ] {
            let mut out = vec![9, 8];
            assert_eq!(payload.write(&mut out), Err(Error::Unwritable));
            assert_eq!(out, [9, 8]);
            contract::check_wire_value(&payload);
        }
        let packet = Packet::Short {
            spin: false,
            key_phase: false,
            dcid: vec![1; 8],
            number: PacketNumber { value: 0, len: 1 },
            payload: vec![1],
        };
        assert_eq!(Datagram::<0>(vec![packet.clone()]).to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&Datagram::<8>(vec![packet]));
    }

    #[test]
    fn split_datagram_keeps_packets_before_a_truncated_tail() {
        let payload = Payload(vec![Frame::Ping, Frame::Padding(3)]);
        let packet = Packet::Handshake {
            version: VERSION_1,
            dcid: vec![],
            scid: vec![],
            number: PacketNumber { value: 0, len: 1 },
            payload: payload.to_bytes().unwrap(),
        };
        let prefix = Datagram::<0>(vec![packet.clone(), packet.clone()]);
        let mut bytes = prefix.to_bytes().unwrap();
        bytes.push(0xc0);
        assert_eq!(Datagram::<0>::parse(&bytes), Err(Error::Truncated));
        let (packets, error) = split_datagram(&bytes, 0);
        assert_eq!(error, Some(Error::Truncated));
        assert_eq!(packets, prefix.0);
        contract::check_wire_value(&Datagram::<0>(packets.clone()));
        for packet in packets {
            assert_eq!(Payload::parse(packet.payload().unwrap()), Ok(payload.clone()));
            contract::check_wire_value(&Datagram::<0>(vec![packet]));
        }
    }

    #[test]
    fn generated_wire_contracts_and_reassembly() {
        let mut rng = Lcg::new(0x5155_4943);
        let seeds: Vec<_> = sample_packets()
            .iter()
            .map(|(p, _)| datagram(std::slice::from_ref(p)).unwrap())
            .chain(std::iter::once(Payload(sample_frames()).to_bytes().unwrap()))
            .collect();
        for round in 0..6000 {
            let mut bytes = if rng.coin() { rng.bytes(80) } else { seeds[rng.index(seeds.len())].clone() };
            mutate(&mut rng, &mut bytes);
            contract::check_wire::<VarInt>(&bytes);
            contract::check_wire::<Frame>(&bytes);
            check_payload(&bytes);
            contract::check_wire::<Datagram<0>>(&bytes);
            contract::check_wire::<Datagram<8>>(&bytes);
            for dcid_len in 0..=20 {
                let (packets, _) = split_datagram(&bytes, dcid_len);
                if !packets.is_empty() {
                    let wire = datagram(&packets).unwrap();
                    assert_eq!(split_datagram(&wire, dcid_len), (packets.clone(), None));
                }
                for packet in packets {
                    if let Some(payload) = packet.payload() {
                        check_payload(payload);
                    }
                    let wire = datagram(std::slice::from_ref(&packet)).unwrap();
                    assert_eq!(Packet::parse(&wire, dcid_len), Ok((packet, wire.len())));
                }
            }
            if round % 10 == 1 {
                let mut last = None;
                for cut in 0..=bytes.len() {
                    last = Some((Packet::parse(&bytes[..cut], 8), Payload::parse(&bytes[..cut])));
                }
                assert_eq!(last, Some((Packet::parse(&bytes, 8), Payload::parse(&bytes))));
            }
            if round % 50 == 0 {
                let mut reassembler = Reassembler::new();
                let mut order: Vec<_> = (0..bytes.len()).collect();
                for i in (1..order.len()).rev() {
                    order.swap(i, rng.index(i + 1));
                }
                for i in order {
                    reassembler.insert(i as u64, &bytes[i..i + 1]).unwrap();
                }
                assert_eq!(reassembler.read(), bytes);
            }
            let frames: Vec<_> = (0..1 + rng.index(5)).map(|_| random_frame(&mut rng)).collect();
            for frame in &frames {
                contract::check_wire_value(frame);
            }
            contract::check_wire_value(&Payload(frames));
            let number = PacketNumber { value: (rng.next() >> rng.index(32)) as u32, len: rng.index(6) as u8 };
            let version = [VERSION_1, VERSION_2, 0, 5][rng.index(4)];
            let dcid = rng.bytes(24);
            let scid = rng.bytes(24);
            let payload = rng.bytes(30);
            let packet = match rng.index(7) {
                0 => Packet::Initial { version, dcid, scid, token: payload.clone(), number, payload },
                1 => Packet::ZeroRtt { version, dcid, scid, number, payload },
                2 => Packet::Handshake { version, dcid, scid, number, payload },
                3 => Packet::Retry { version, unused: rng.next() as u8, dcid, scid, token: payload, tag: [1; 16] },
                4 => Packet::Short { spin: true, key_phase: rng.coin(), dcid, number, payload },
                5 => Packet::VersionNegotiation {
                    unused: rng.next() as u8,
                    dcid,
                    scid,
                    versions: vec![rng.next() as u32; payload.len()],
                },
                _ => Packet::OtherVersion { bits: rng.next() as u8, version, dcid, scid, rest: payload },
            };
            if let Ok(bytes) = datagram(std::slice::from_ref(&packet)) {
                assert_eq!(Packet::parse(&bytes, packet.dcid().len()), Ok((packet, bytes.len())));
            }
        }
    }
}
