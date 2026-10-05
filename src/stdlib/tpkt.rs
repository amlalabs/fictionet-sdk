//! TPKT: reading and writing the packets that carry ISO transport on TCP,
//! with no I/O.
//!
//! ISO transport was made for networks other than TCP. RFC 1006 carries it
//! over TCP anyway, usually on port 102, by putting each transport message
//! (a TPDU) in a TPKT: a 4-byte header that holds a version, which is
//! always 3, a reserved byte, and the length of the whole packet. Siemens
//! S7 PLCs, IEC 61850 substations and ICCP links use it, and every RDP
//! session on port 3389 starts with it. RFC 2126 keeps the same header for
//! ISO transport over TCP on IPv6 and for transport classes other than 0.
//!
//! Nothing here reads a socket. A world feeds the bytes it reads from a
//! TCP connection to a [`Decoder`], takes each [`Packet`] out, and reads
//! its payload. Most payloads are COTP TPDUs, which
//! [`Packet::tpdu`] reads with the [`cotp`] module.
//! [`Packet::try_from_tpdu`] and [`write_message`] go the other way. A world
//! may set a size limit lower than the 65535 bytes the header allows, as
//! real stacks often do.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A stream that breaks the format gives a [`TpktError`], and a
//! real server closes the connection. Writers return an [`EncodeError`]
//! rather than write a packet a reader would refuse.
//!
//! ```
//! use fictionet::stdlib::cotp::{Reassembler, Tpdu};
//! use fictionet::stdlib::tpkt::{Decoder, Packet, write_message};
//!
//! let mut decoder = Decoder::new();
//! // A COTP data TPDU marked as the last of its message, carrying "hi".
//! let bytes = [3, 0, 0, 9, 2, 0xf0, 0x80, b'h', b'i'];
//! assert_eq!(decoder.feed(&bytes), bytes.len());
//! let packet = decoder.next_packet().unwrap().unwrap();
//! assert_eq!(packet.payload, [2, 0xf0, 0x80, b'h', b'i']);
//! let Ok(Tpdu::Data(data)) = packet.tpdu() else { panic!() };
//! let mut messages = Reassembler::new();
//! assert_eq!(messages.push(&data), Ok(Some(b"hi".to_vec())));
//!
//! // The answer, "ok", in packets of up to 1024-byte TPDUs: here just one.
//! assert_eq!(write_message(b"ok", 1024).unwrap(), [3, 0, 0, 9, 2, 0xf0, 0x80, b'o', b'k']);
//!
//! // A packet holds any payload of 3 to 65531 bytes.
//! let packet = Packet::new(vec![1, 2, 3]);
//! assert_eq!(packet.to_bytes().unwrap(), [3, 0, 0, 7, 1, 2, 3]);
//! assert_eq!(Packet::parse(&[3, 0, 0, 7, 1, 2, 3]), Ok(Some((packet, 7))));
//! ```

use super::cotp;

/// The TCP port ISO transport servers listen on.
pub const PORT: u16 = 102;
/// The TCP port RDP servers listen on. RDP starts each session with TPKT.
pub const RDP_PORT: u16 = 3389;
/// The version in every TPKT header.
pub const VERSION: u8 = 3;
/// The length of the header, before the payload.
pub const HEADER_LEN: usize = 4;
/// The shortest payload: RFC 1006 sizes the packet for a TPDU, and the
/// shortest TPDU is 3 bytes.
pub const MIN_PAYLOAD: usize = 3;
/// The shortest packet: the header and the shortest payload.
pub const MIN_PACKET: usize = HEADER_LEN + MIN_PAYLOAD;
/// The longest packet the 16-bit length field can name.
pub const MAX_PACKET: usize = 65535;
/// The longest payload: the longest packet less its header.
pub const MAX_PAYLOAD: usize = MAX_PACKET - HEADER_LEN;
/// The most bytes a [`Decoder`] holds that have not been taken out: one
/// longest packet. A decoder with a lower limit holds at most that.
pub const MAX_BUFFERED: usize = MAX_PACKET;
/// The longest message [`write_message`] cuts into packets, the same as
/// the longest message a [`cotp::Reassembler`] takes.
pub const MAX_MESSAGE: usize = cotp::MAX_MESSAGE;

/// One TPKT packet: the header's reserved byte and the payload. The
/// version is always [`VERSION`] and the length is worked out from the
/// payload, so neither is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The header's second byte. RFC 1006 says senders set it to 0;
    /// readers take any value, as real stacks do.
    pub reserved: u8,
    /// What the packet carries, usually one COTP TPDU: [`MIN_PAYLOAD`] to
    /// [`MAX_PAYLOAD`] bytes for [`Packet::to_bytes`] to write it.
    pub payload: Vec<u8>,
}

/// Why a writer refused a value: no packet a reader takes can hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A payload shorter than [`MIN_PAYLOAD`], with its length.
    TooShort(usize),
    /// A payload longer than [`MAX_PAYLOAD`], or a message longer than
    /// [`MAX_MESSAGE`], with its length.
    TooLong(usize),
    /// A TPDU whose bytes would read back as a different TPDU: its data
    /// or a parameter does not fit in one packet, or a field is wider than
    /// its format, such as a credit over 15. [`Packet::try_from_tpdu`]
    /// gives it.
    Unrepresentable,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooShort(n) => write!(f, "TPKT payload of {n} bytes, below {MIN_PAYLOAD}"),
            EncodeError::TooLong(n) => write!(f, "{n} bytes, more than TPKT may carry"),
            EncodeError::Unrepresentable => {
                f.write_str("TPDU that one TPKT packet cannot carry as it is")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Why bytes are not a TPKT stream. Any of them means the connection holds
/// no more packets a reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpktError {
    /// The first byte was not 3. RDP's fast-path packets look like this.
    Version(u8),
    /// The length field was below [`MIN_PACKET`].
    Length(u16),
    /// The length field was above the reader's size limit.
    TooLong {
        /// The length field.
        length: u16,
        /// The longest packet the reader takes.
        limit: usize,
    },
}

impl std::fmt::Display for TpktError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TpktError::Version(v) => write!(f, "TPKT version {v}, not {VERSION}"),
            TpktError::Length(n) => write!(f, "TPKT length {n}, below {MIN_PACKET}"),
            TpktError::TooLong { length, limit } => {
                write!(f, "TPKT length {length}, above the limit of {limit}")
            }
        }
    }
}

impl std::error::Error for TpktError {}

/// The fields of a TPKT header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The second byte, which senders set to 0.
    pub reserved: u8,
    /// The length of the whole packet, header included.
    pub length: u16,
}

impl Header {
    /// Reads the header at the start of `b`, for a reader that takes
    /// packets of up to `limit` bytes, a limit clamped to [`MIN_PACKET`]
    /// to [`MAX_PACKET`]. It returns `Ok(None)` if `b` holds only part of
    /// one. A bad version is known from the first byte, before
    /// the rest of the header comes.
    pub fn parse(b: &[u8], limit: usize) -> Result<Option<Header>, TpktError> {
        let Some(&version) = b.first() else {
            return Ok(None);
        };
        if version != VERSION {
            return Err(TpktError::Version(version));
        }
        let [_, reserved, hi, lo, ..] = *b else {
            return Ok(None);
        };
        let length = u16::from_be_bytes([hi, lo]);
        if usize::from(length) < MIN_PACKET {
            return Err(TpktError::Length(length));
        }
        if usize::from(length) > clamp_limit(limit) {
            return Err(TpktError::TooLong {
                length,
                limit: clamp_limit(limit),
            });
        }
        Ok(Some(Header { reserved, length }))
    }

    /// The header's 4 bytes. A length below [`MIN_PACKET`] is an error,
    /// [`EncodeError::TooShort`] with [`Header::payload_len`], since a
    /// reader refuses it.
    pub fn to_bytes(&self) -> Result<[u8; HEADER_LEN], EncodeError> {
        if usize::from(self.length) < MIN_PACKET {
            return Err(EncodeError::TooShort(self.payload_len()));
        }
        let [hi, lo] = self.length.to_be_bytes();
        Ok([VERSION, self.reserved, hi, lo])
    }

    /// How many payload bytes follow the header. A length field below
    /// [`HEADER_LEN`] gives 0.
    pub fn payload_len(&self) -> usize {
        usize::from(self.length).saturating_sub(HEADER_LEN)
    }
}

/// A size limit as a reader uses it: at least [`MIN_PACKET`] and at most
/// [`MAX_PACKET`].
fn clamp_limit(limit: usize) -> usize {
    limit.clamp(MIN_PACKET, MAX_PACKET)
}

impl Packet {
    /// A packet carrying `payload`, with the reserved byte 0.
    pub fn new(payload: Vec<u8>) -> Packet {
        Packet {
            reserved: 0,
            payload,
        }
    }

    /// Reads the packet at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the packet and how many bytes
    /// of `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Packet, usize)>, TpktError> {
        Packet::parse_limited(b, MAX_PACKET)
    }

    /// Reads the packet at the start of `b`, as [`Packet::parse`] does,
    /// but refuses one longer than `limit` bytes. A limit below
    /// [`MIN_PACKET`] is taken as that, and one above [`MAX_PACKET`] as
    /// that.
    pub fn parse_limited(b: &[u8], limit: usize) -> Result<Option<(Packet, usize)>, TpktError> {
        let Some(header) = Header::parse(b, limit)? else {
            return Ok(None);
        };
        let end = usize::from(header.length);
        match b.get(HEADER_LEN..end) {
            Some(payload) => Ok(Some((
                Packet {
                    reserved: header.reserved,
                    payload: payload.to_vec(),
                },
                end,
            ))),
            None => Ok(None),
        }
    }

    /// The packet's header, or an error if the payload's length is outside
    /// [`MIN_PAYLOAD`] to [`MAX_PAYLOAD`].
    pub fn header(&self) -> Result<Header, EncodeError> {
        let n = self.payload.len();
        if n < MIN_PAYLOAD {
            return Err(EncodeError::TooShort(n));
        }
        if n > MAX_PAYLOAD {
            return Err(EncodeError::TooLong(n));
        }
        // n + HEADER_LEN is at most MAX_PACKET, so it fits in 16 bits.
        Ok(Header {
            reserved: self.reserved,
            length: (n + HEADER_LEN) as u16,
        })
    }

    /// The packet's bytes: the header, then the payload. A payload shorter
    /// than [`MIN_PAYLOAD`] or longer than [`MAX_PAYLOAD`] is an error,
    /// since no packet a reader takes can hold it.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let header = self.header()?;
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&header.to_bytes()?);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// The packet carrying `tpdu`, with the reserved byte 0. It always
    /// gives a packet, since [`cotp::Tpdu::to_bytes`] writes 3 to
    /// [`MAX_PAYLOAD`] bytes, but that writer cuts what does not fit: data
    /// past one packet, parameters past the header, and the high bits of
    /// narrow fields. [`Packet::try_from_tpdu`] refuses such a TPDU
    /// instead.
    pub fn from_tpdu(tpdu: &cotp::Tpdu) -> Packet {
        Packet::new(tpdu.to_bytes())
    }

    /// The packet carrying `tpdu`, with the reserved byte 0, if its payload
    /// reads back as the same TPDU. Otherwise it is
    /// [`EncodeError::Unrepresentable`]: data longer than one packet holds,
    /// a parameter or raw header bytes that do not fit the header, or a
    /// field wider than its format. A raw variable part counts as the same
    /// when its bytes are written whole, even if they read back as
    /// parameters. To send a long message, cut it with [`write_message`].
    pub fn try_from_tpdu(tpdu: &cotp::Tpdu) -> Result<Packet, EncodeError> {
        let packet = Packet::from_tpdu(tpdu);
        let mut back = packet.tpdu().map_err(|_| EncodeError::Unrepresentable)?;
        // Compare raw header bytes as the reader would see them, then put
        // the original back so the rest compares field by field.
        if let (Some(want), Some(got)) = (variable_of(tpdu), variable_mut(&mut back)) {
            let same = match want {
                cotp::Variable::Raw(b) => *got == cotp::Variable::parse(b),
                _ => got == want,
            };
            if !same {
                return Err(EncodeError::Unrepresentable);
            }
            // The variable parts match, so this clone is at most a header.
            *got = want.clone();
        }
        if back == *tpdu {
            Ok(packet)
        } else {
            Err(EncodeError::Unrepresentable)
        }
    }

    /// Reads the payload as one COTP TPDU.
    pub fn tpdu(&self) -> Result<cotp::Tpdu, cotp::TpduError> {
        cotp::Tpdu::parse(&self.payload)
    }
}

/// The header's variable part, for the TPDUs that have one.
fn variable_of(t: &cotp::Tpdu) -> Option<&cotp::Variable> {
    match t {
        cotp::Tpdu::ConnectionRequest(c) | cotp::Tpdu::ConnectionConfirm(c) => Some(&c.variable),
        cotp::Tpdu::DisconnectRequest(d) => Some(&d.variable),
        cotp::Tpdu::Error(e) => Some(&e.variable),
        cotp::Tpdu::Data(_) => None,
    }
}

/// [`variable_of`], to change it.
fn variable_mut(t: &mut cotp::Tpdu) -> Option<&mut cotp::Variable> {
    match t {
        cotp::Tpdu::ConnectionRequest(c) | cotp::Tpdu::ConnectionConfirm(c) => {
            Some(&mut c.variable)
        }
        cotp::Tpdu::DisconnectRequest(d) => Some(&mut d.variable),
        cotp::Tpdu::Error(e) => Some(&mut e.variable),
        cotp::Tpdu::Data(_) => None,
    }
}

/// The bytes of the packets that carry `message` as COTP data TPDUs of no
/// more than `tpdu_size` bytes each, header included, with EOT on the
/// last. [`cotp::segment`] says how `tpdu_size` is taken. A message longer
/// than [`MAX_MESSAGE`] is an error.
pub fn write_message(message: &[u8], tpdu_size: usize) -> Result<Vec<u8>, EncodeError> {
    if message.len() > MAX_MESSAGE {
        return Err(EncodeError::TooLong(message.len()));
    }
    let mut out = Vec::new();
    for data in cotp::segment(message, tpdu_size) {
        out.extend_from_slice(&Packet::try_from_tpdu(&cotp::Tpdu::Data(data))?.to_bytes()?);
    }
    Ok(out)
}

/// Splits a TPKT byte stream into packets. Feed it the bytes a connection
/// reads, in order, and take packets out until it has none.
#[derive(Clone, Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small packets costs time in proportion to their bytes.
    start: usize,
    limit: usize,
    failed: Option<TpktError>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder holding no bytes, which takes packets of up to
    /// [`MAX_PACKET`] bytes.
    pub fn new() -> Decoder {
        Decoder::with_limit(MAX_PACKET)
    }

    /// A decoder holding no bytes, which takes packets of up to `limit`
    /// bytes, header included. A limit below [`MIN_PACKET`] is taken as
    /// that, and one above [`MAX_PACKET`] as that. A longer packet breaks
    /// the stream with [`TpktError::TooLong`].
    pub fn with_limit(limit: usize) -> Decoder {
        Decoder {
            buf: Vec::new(),
            start: 0,
            limit: clamp_limit(limit),
            failed: None,
        }
    }

    /// The longest packet this decoder takes, header included.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Takes bytes read from the connection, from the start of `bytes`,
    /// and returns how many it took. It takes them all unless that would
    /// make it hold more than its limit. Then take packets out with
    /// [`Decoder::next_packet`] and feed it the rest. Once it is full,
    /// `next_packet` always gives a packet or an error, so a loop of
    /// feeding and taking out always ends. After a [`TpktError`] the
    /// stream cannot be read any further, and every byte is taken and
    /// dropped.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let n = bytes.len().min(self.limit.saturating_sub(self.buffered()));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The next whole packet, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken.
    pub fn next_packet(&mut self) -> Option<Result<Packet, TpktError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match Packet::parse_limited(&self.buf[self.start..], self.limit) {
            Ok(Some((packet, used))) => {
                self.start += used;
                if self.start == self.buf.len() {
                    self.buf.clear();
                    self.start = 0;
                }
                Some(Ok(packet))
            }
            Ok(None) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a packet.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cotp::{Data, Reassembler, Tpdu};

    /// A deterministic stream of pseudo-random numbers.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    /// Feeds `data` to a decoder with `limit`, whole or a byte at a time,
    /// taking packets out after each feed. Every packet, then the error
    /// that broke the stream, if one did.
    fn split(data: &[u8], limit: usize, bytewise: bool) -> (Vec<Packet>, Option<TpktError>) {
        let mut decoder = Decoder::with_limit(limit);
        let mut packets = Vec::new();
        let chunks: Vec<&[u8]> = if bytewise {
            data.chunks(1).collect()
        } else {
            vec![data]
        };
        for chunk in chunks {
            let mut rest = chunk;
            while !rest.is_empty() {
                let took = decoder.feed(rest);
                assert!(decoder.buffered() <= decoder.limit());
                assert!(decoder.buffered() <= MAX_BUFFERED);
                // Dropped bytes are let go before they pass the held ones.
                assert!(decoder.buf.len() < 2 * decoder.limit());
                rest = &rest[took..];
                let mut progress = took > 0;
                while let Some(r) = decoder.next_packet() {
                    match r {
                        Ok(p) => packets.push(p),
                        Err(e) => return (packets, Some(e)),
                    }
                    progress = true;
                }
                assert!(progress, "a full decoder gave nothing");
            }
        }
        (packets, None)
    }

    // RFC 1006 section 6: version 3, reserved, then the length of the
    // whole packet, header included. The smallest TPDU, a class 0 data
    // TPDU with no data, makes the smallest packet.
    #[test]
    fn rfc1006_example() {
        let bytes = [3, 0, 0, 7, 2, 0xf0, 0x80];
        let packet = Packet::new(vec![2, 0xf0, 0x80]);
        assert_eq!(Packet::parse(&bytes), Ok(Some((packet.clone(), 7))));
        assert_eq!(packet.to_bytes().unwrap(), bytes);
        assert_eq!(
            packet.header(),
            Ok(Header {
                reserved: 0,
                length: 7
            })
        );
        assert_eq!(
            packet.tpdu(),
            Ok(Tpdu::Data(Data {
                eot: true,
                number: 0,
                data: vec![]
            }))
        );
        assert_eq!(Packet::from_tpdu(&packet.tpdu().unwrap()), packet);
        assert_eq!(Packet::try_from_tpdu(&packet.tpdu().unwrap()), Ok(packet));
    }

    // An RDP connection request (MS-RDPBCGR 4.1.1) starts with a TPKT
    // header and an X.224 connection request. Its length indicator, 14,
    // covers the RDP negotiation request too, so the TPDU carries no data.
    #[test]
    fn rdp_connection_request() {
        let bytes = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        let (packet, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(used, 19);
        assert_eq!(packet.payload.len(), 15);
        let Ok(Tpdu::ConnectionRequest(cr)) = packet.tpdu() else {
            panic!()
        };
        assert_eq!(cr.class, 0);
        assert_eq!((cr.dst_ref, cr.src_ref), (0, 0));
        assert!(cr.data.is_empty());
        assert_eq!(packet.to_bytes().unwrap(), bytes);
        // RDP's negotiation request sits in the header as raw bytes, and is
        // written back whole.
        let t = Tpdu::ConnectionRequest(cr);
        assert_eq!(Packet::try_from_tpdu(&t), Ok(packet));
    }

    #[test]
    fn header_fields() {
        let h = Header {
            reserved: 9,
            length: 0x1234,
        };
        assert_eq!(h.to_bytes(), Ok([3, 9, 0x12, 0x34]));
        assert_eq!(
            Header::parse(&h.to_bytes().unwrap(), MAX_PACKET),
            Ok(Some(h))
        );
        assert_eq!(h.payload_len(), 0x1230);
        // A header writer never writes a length the reader refuses.
        for length in 0..MIN_PACKET as u16 {
            let h = Header {
                reserved: 0,
                length,
            };
            assert_eq!(h.to_bytes(), Err(EncodeError::TooShort(h.payload_len())));
        }
        let h = Header {
            reserved: 0,
            length: MIN_PACKET as u16,
        };
        assert_eq!(
            Header::parse(&h.to_bytes().unwrap(), MAX_PACKET),
            Ok(Some(h))
        );
        assert_eq!(
            Header {
                reserved: 0,
                length: 2
            }
            .payload_len(),
            0
        );
        // The reserved byte is kept, not checked.
        let (p, _) = Packet::parse(&[3, 0xff, 0, 7, 1, 2, 3]).unwrap().unwrap();
        assert_eq!(p.reserved, 0xff);
        assert_eq!(p.to_bytes().unwrap(), [3, 0xff, 0, 7, 1, 2, 3]);
    }

    #[test]
    fn every_prefix_is_incomplete() {
        let bytes = [3, 0, 0, 10, 2, 0xf0, 0x80, 1, 2, 3];
        for n in 0..bytes.len() {
            assert_eq!(Packet::parse(&bytes[..n]), Ok(None), "{n} bytes");
            if n < HEADER_LEN {
                assert_eq!(Header::parse(&bytes[..n], MAX_PACKET), Ok(None));
            }
        }
        // Bytes after the packet are left alone.
        let mut longer = bytes.to_vec();
        longer.extend_from_slice(&[3, 0]);
        assert_eq!(Packet::parse(&longer).unwrap().unwrap().1, 10);
    }

    #[test]
    fn parse_errors() {
        // A bad version is known from the first byte.
        assert_eq!(Packet::parse(&[0x30]), Err(TpktError::Version(0x30)));
        assert_eq!(
            Packet::parse(&[2, 0, 0, 7, 1, 2, 3]),
            Err(TpktError::Version(2))
        );
        for n in 0..MIN_PACKET as u16 {
            let b = [3, 0, (n >> 8) as u8, n as u8];
            assert_eq!(Packet::parse(&b), Err(TpktError::Length(n)));
        }
        // The limit, as given and as clamped.
        assert_eq!(
            Packet::parse_limited(&[3, 0, 0, 9], 8),
            Err(TpktError::TooLong {
                length: 9,
                limit: 8
            })
        );
        assert!(Packet::parse_limited(&[3, 0, 0, 8], 8).unwrap().is_none());
        assert_eq!(
            Packet::parse_limited(&[3, 0, 0, 8], 0),
            Err(TpktError::TooLong {
                length: 8,
                limit: MIN_PACKET
            })
        );
        assert!(
            Packet::parse_limited(&[3, 0, 0xff, 0xff], usize::MAX)
                .unwrap()
                .is_none()
        );
        for e in [
            TpktError::Version(2),
            TpktError::Length(2),
            TpktError::TooLong {
                length: 9,
                limit: 8,
            },
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn encode_errors() {
        for n in 0..MIN_PAYLOAD {
            assert_eq!(
                Packet::new(vec![0; n]).to_bytes(),
                Err(EncodeError::TooShort(n))
            );
        }
        let big = Packet::new(vec![0; MAX_PAYLOAD + 1]);
        assert_eq!(big.to_bytes(), Err(EncodeError::TooLong(MAX_PAYLOAD + 1)));
        let max = Packet::new(vec![7; MAX_PAYLOAD]);
        let bytes = max.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_PACKET);
        assert_eq!(&bytes[..4], &[3, 0, 0xff, 0xff]);
        assert_eq!(Packet::parse(&bytes), Ok(Some((max, MAX_PACKET))));
        assert_eq!(
            write_message(&vec![0; MAX_MESSAGE + 1], 1024),
            Err(EncodeError::TooLong(MAX_MESSAGE + 1))
        );
        for e in [
            EncodeError::TooShort(1),
            EncodeError::TooLong(1),
            EncodeError::Unrepresentable,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    // A TPDU too big for one packet, or with a field wider than its format,
    // is refused rather than cut or masked into a different TPDU.
    #[test]
    fn try_from_tpdu_refuses_lossy_tpdus() {
        let data = |n: usize, number: u8| {
            Tpdu::Data(Data {
                eot: true,
                number,
                data: vec![0x41; n],
            })
        };
        // The longest data a data TPDU in one packet carries: 3 header bytes.
        let fits = data(MAX_PAYLOAD - 3, 0);
        let p = Packet::try_from_tpdu(&fits).unwrap();
        assert_eq!(p.payload.len(), MAX_PAYLOAD);
        assert_eq!(p.tpdu(), Ok(fits));
        assert_eq!(
            Packet::try_from_tpdu(&data(MAX_PAYLOAD - 2, 0)),
            Err(EncodeError::Unrepresentable)
        );
        assert_eq!(
            Packet::try_from_tpdu(&data(65529, 0)),
            Err(EncodeError::Unrepresentable)
        );
        assert_eq!(
            Packet::try_from_tpdu(&data(0, 0x80)),
            Err(EncodeError::Unrepresentable)
        );
        let connect = |f: &dyn Fn(&mut cotp::Connect)| {
            let mut c = cotp::Connect::request(7);
            f(&mut c);
            Packet::try_from_tpdu(&Tpdu::ConnectionRequest(c))
        };
        assert!(connect(&|_| ()).is_ok());
        assert!(connect(&|c| c.credit = 15).is_ok());
        assert_eq!(
            connect(&|c| c.credit = 16),
            Err(EncodeError::Unrepresentable)
        );
        assert_eq!(
            connect(&|c| c.class = 16),
            Err(EncodeError::Unrepresentable)
        );
        assert_eq!(
            connect(&|c| c.options = 16),
            Err(EncodeError::Unrepresentable)
        );
        // A parameter longer than its length byte, or more than a header holds.
        assert_eq!(
            connect(&|c| c.variable.set(0xc1, vec![0; 256])),
            Err(EncodeError::Unrepresentable)
        );
        assert_eq!(
            connect(&|c| {
                c.variable.set(0xc1, vec![0; 200]);
                c.variable.set(0xc2, vec![0; 200]);
            }),
            Err(EncodeError::Unrepresentable)
        );
        assert_eq!(
            connect(&|c| c.variable = cotp::Variable::Raw(vec![0; 249])),
            Err(EncodeError::Unrepresentable)
        );
        // Raw bytes that happen to split into parameters, as RDP writes, are
        // the same bytes on the wire, so they are fine.
        assert!(connect(&|c| c.variable = cotp::Variable::Raw(vec![0xc1, 1, 9])).is_ok());
        assert!(connect(&|c| c.variable = cotp::Variable::Raw(vec![1; 248])).is_ok());
        assert!(connect(&|c| c.variable = cotp::Variable::Raw(vec![])).is_ok());
        // The unchecked writer still cuts, as it says.
        let cut = Packet::from_tpdu(&data(65529, 0));
        assert_eq!(cut.payload.len(), MAX_PAYLOAD);
    }

    #[test]
    fn tpdu_errors_pass_through() {
        assert_eq!(
            Packet::new(vec![2, 0x10, 0]).tpdu(),
            Err(cotp::TpduError::Unsupported(0x10))
        );
        assert!(Packet::new(vec![9, 0xf0, 0x80]).tpdu().is_err());
    }

    #[test]
    fn messages_round_trip() {
        let mut rng = Lcg(7);
        for size in [0usize, 1, 124, 125, 126, 1000, 5000, 70000] {
            let message = rng.bytes(size);
            for tpdu_size in [0usize, 128, 1024, 8192, MAX_PAYLOAD, usize::MAX] {
                let bytes = write_message(&message, tpdu_size).unwrap();
                let (packets, err) = split(&bytes, MAX_PACKET, false);
                assert_eq!(err, None);
                let mut r = Reassembler::new();
                let mut out = None;
                for (i, p) in packets.iter().enumerate() {
                    assert!(p.payload.len() <= tpdu_size.clamp(128, MAX_PAYLOAD));
                    let Ok(Tpdu::Data(d)) = p.tpdu() else {
                        panic!()
                    };
                    let got = r.push(&d).unwrap();
                    assert_eq!(got.is_some(), i + 1 == packets.len());
                    out = got.or(out);
                }
                assert_eq!(out.as_deref(), Some(&message[..]));
            }
        }
    }

    #[test]
    fn decoder_stream() {
        let mut stream = Vec::new();
        let packets: Vec<Packet> = (0..5u8)
            .map(|i| Packet {
                reserved: i,
                payload: vec![i; 3 + usize::from(i) * 50],
            })
            .collect();
        for p in &packets {
            stream.extend_from_slice(&p.to_bytes().unwrap());
        }
        for bytewise in [false, true] {
            assert_eq!(
                split(&stream, MAX_PACKET, bytewise),
                (packets.clone(), None)
            );
        }
        // An error after good packets, and the decoder stays broken.
        stream.extend_from_slice(&[4, 0, 0, 7]);
        let mut d = Decoder::new();
        assert_eq!(d.feed(&stream), stream.len());
        for p in &packets {
            assert_eq!(d.next_packet(), Some(Ok(p.clone())));
        }
        assert_eq!(d.next_packet(), Some(Err(TpktError::Version(4))));
        assert_eq!(d.next_packet(), Some(Err(TpktError::Version(4))));
        assert_eq!(d.feed(&[1, 2, 3]), 3);
        assert_eq!(d.buffered(), 0);
        assert_eq!(Decoder::default().limit(), MAX_PACKET);
    }

    #[test]
    fn decoder_limit() {
        let mut d = Decoder::with_limit(100);
        assert_eq!(d.limit(), 100);
        let ok = Packet::new(vec![1; 96]).to_bytes().unwrap();
        assert_eq!(d.feed(&ok), 100);
        assert_eq!(d.next_packet(), Some(Ok(Packet::new(vec![1; 96]))));
        // Known from the header alone, before the payload comes.
        assert_eq!(d.feed(&[3, 0, 0, 101]), 4);
        assert_eq!(
            d.next_packet(),
            Some(Err(TpktError::TooLong {
                length: 101,
                limit: 100
            }))
        );
        // A decoder only takes what its limit holds.
        let mut d = Decoder::with_limit(10);
        assert_eq!(d.feed(&[3, 0, 0, 10, 0, 0, 0, 0, 0, 0, 3, 0]), 10);
        assert!(d.next_packet().unwrap().is_ok());
        assert_eq!(Decoder::with_limit(0).limit(), MIN_PACKET);
        assert_eq!(Decoder::with_limit(usize::MAX).limit(), MAX_PACKET);
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg(0x7b47);
        for i in 0..4000 {
            // Mostly well-formed packets, with some bytes changed.
            let mut data = Vec::new();
            for _ in 0..rng.below(4) {
                let n = 3 + rng.below(if i % 50 == 0 { 3000 } else { 40 }) as usize;
                let p = Packet {
                    reserved: rng.next() as u8,
                    payload: rng.bytes(n),
                };
                data.extend_from_slice(&p.to_bytes().unwrap());
            }
            let extra = rng.below(12) as usize;
            data.extend(rng.bytes(extra));
            for _ in 0..rng.below(3) {
                if !data.is_empty() {
                    let at = rng.below(data.len() as u64) as usize;
                    data[at] = rng.next() as u8;
                }
            }
            let limit = [MAX_PACKET, 7, 20, 64, 1000][rng.below(5) as usize];
            let whole = split(&data, limit, false);
            assert_eq!(split(&data, limit, true), whole);
            for p in &whole.0 {
                assert!(p.payload.len() + HEADER_LEN <= limit);
                let bytes = p.to_bytes().unwrap();
                assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
                // A TPDU read from a packet is written back whole, and reads
                // back the same.
                if let Ok(t) = p.tpdu() {
                    let back = Packet::try_from_tpdu(&t).unwrap();
                    assert!(back.to_bytes().is_ok());
                    assert_eq!(back.tpdu(), Ok(t.clone()));
                    assert_eq!(Packet::from_tpdu(&t), back);
                }
            }
            // Any header a writer takes reads back the same.
            let h = Header {
                reserved: rng.next() as u8,
                length: rng.next() as u16,
            };
            match h.to_bytes() {
                Ok(b) => assert_eq!(Header::parse(&b, MAX_PACKET), Ok(Some(h))),
                Err(e) => {
                    assert!(usize::from(h.length) < MIN_PACKET);
                    assert_eq!(e, EncodeError::TooShort(h.payload_len()));
                }
            }
            // Payloads shaped like TPDUs: whatever reads as one is written
            // back whole.
            let n = rng.below(40) as usize;
            let mut b = rng.bytes(n + 2);
            b[0] = rng.below(n as u64 + 2) as u8;
            b[1] = [0xe0, 0xd3, 0x80, 0xf0, 0x70][rng.below(5) as usize];
            if let Ok(t) = Packet::new(b.clone()).tpdu() {
                assert_eq!(Packet::try_from_tpdu(&t), Ok(Packet::new(b)));
            }
            // Raw bytes, never panicking.
            let n = rng.below(20) as usize;
            let raw = rng.bytes(n);
            let _ = Packet::parse(&raw);
            let _ = Packet::parse_limited(&raw, rng.next() as usize);
            let _ = split(&raw, MAX_PACKET, true);
        }
    }
}
