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
//! Nothing here reads a socket. A world pushes bytes from a
//! TCP connection into a [`Stream<Packets>`](fictionet::stdlib::codec::Stream), takes each
//! [`Packet`] out, and reads its payload. Most payloads are COTP TPDUs;
//! [`fictionet::stdlib::cotp::over_tpkt`] provides conversions and a message writer.
//! A world may set a size limit lower than the 65535 bytes the header allows, as
//! real stacks often do.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A stream that breaks the format gives a [`TpktError`], and a
//! real server closes the connection. Writers return an [`EncodeError`]
//! rather than write a packet a reader would refuse.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::tpkt::{Packet, Packets};
//!
//! let mut decoder = Stream::new(Packets::new());
//! // A COTP data TPDU marked as the last of its message, carrying "hi".
//! let bytes = [3, 0, 0, 9, 2, 0xf0, 0x80, b'h', b'i'];
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! let packet = decoder.next().unwrap().unwrap();
//! assert_eq!(packet.payload, [2, 0xf0, 0x80, b'h', b'i']);
//! assert_eq!(packet.to_bytes().unwrap(), bytes);
//!
//! // A packet holds any payload of 3 to 65531 bytes.
//! let packet = Packet::new(vec![1, 2, 3]);
//! assert_eq!(packet.to_bytes().unwrap(), [3, 0, 0, 7, 1, 2, 3]);
//! assert_eq!(Packet::parse(&[3, 0, 0, 7, 1, 2, 3]), Ok(Some((packet, 7))));
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};

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
    /// A payload longer than [`MAX_PAYLOAD`], with its length.
    TooLong(usize),
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncodeError::TooShort(n) => write!(f, "TPKT payload of {n} bytes, below {MIN_PAYLOAD}"),
            EncodeError::TooLong(n) => write!(f, "{n} bytes, more than TPKT may carry"),
        }
    }
}

impl core::error::Error for EncodeError {}

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

impl core::fmt::Display for TpktError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TpktError::Version(v) => write!(f, "TPKT version {v}, not {VERSION}"),
            TpktError::Length(n) => write!(f, "TPKT length {n}, below {MIN_PACKET}"),
            TpktError::TooLong { length, limit } => {
                write!(f, "TPKT length {length}, above the limit of {limit}")
            }
        }
    }
}

impl core::error::Error for TpktError {}

/// Why an exact [`Wire`] parse could not read one complete packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The TPKT header was invalid.
    Header(TpktError),
    /// The slice ended before the packet was complete.
    Incomplete,
    /// Bytes followed the complete packet.
    Trailing {
        /// Number of bytes after the packet.
        remaining: usize,
    },
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Header(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete TPKT packet"),
            Self::Trailing { remaining } => write!(f, "{remaining} bytes after TPKT packet"),
        }
    }
}

impl core::error::Error for ParseError {}

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

    /// How many payload bytes follow the header. A length field below
    /// [`HEADER_LEN`] gives 0.
    pub fn payload_len(&self) -> usize {
        usize::from(self.length).saturating_sub(HEADER_LEN)
    }
}

impl Wire for Header {
    type ParseError = ParseError;
    type WriteError = EncodeError;

    /// Reads exactly four header bytes. Returns [`ParseError::Incomplete`]
    /// for a partial header and [`ParseError::Trailing`] for extra bytes.
    /// A version other than 3 or a length below [`MIN_PACKET`] returns
    /// [`ParseError::Header`] with [`TpktError::Version`] or [`TpktError::Length`].
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let header = Header::parse(bytes, MAX_PACKET)
            .map_err(ParseError::Header)?
            .ok_or(ParseError::Incomplete)?;
        if bytes.len() != HEADER_LEN {
            return Err(ParseError::Trailing {
                remaining: bytes.len().saturating_sub(HEADER_LEN),
            });
        }
        Ok(header)
    }

    /// Appends the header. A length below [`MIN_PACKET`] returns
    /// [`EncodeError::TooShort`] without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if usize::from(self.length) < MIN_PACKET {
            return Err(EncodeError::TooShort(self.payload_len()));
        }
        out.extend_from_slice(&[VERSION, self.reserved]);
        out.extend_from_slice(&self.length.to_be_bytes());
        Ok(())
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
    /// of `b` it took. Use [`Wire::parse`] to require exactly one packet.
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
}

impl Wire for Packet {
    type ParseError = ParseError;
    type WriteError = EncodeError;

    /// Reads exactly one packet. Returns [`ParseError::Incomplete`] for
    /// partial input and [`ParseError::Trailing`] for extra bytes. A version
    /// other than 3 or a length below [`MIN_PACKET`] returns [`ParseError::Header`]
    /// with [`TpktError::Version`] or [`TpktError::Length`].
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (packet, used) = Packet::parse(bytes)
            .map_err(ParseError::Header)?
            .ok_or(ParseError::Incomplete)?;
        if used != bytes.len() {
            return Err(ParseError::Trailing {
                remaining: bytes.len().saturating_sub(used),
            });
        }
        Ok(packet)
    }

    /// Appends one packet. Payloads below [`MIN_PAYLOAD`] return
    /// [`EncodeError::TooShort`]; those above [`MAX_PAYLOAD`] return
    /// [`EncodeError::TooLong`]. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header()?.write(out)?;
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

/// Splits a TPKT byte stream into packets.
///
/// Use with [`fictionet::stdlib::codec::Stream`] for bounded input buffering. A partial
/// packet returns [`Step::Need`], including at EOF. The stream reports
/// truncation at EOF and reports framing errors once. No input is retained.
#[derive(Clone, Copy, Debug)]
pub struct Packets {
    limit: usize,
}

impl Default for Packets {
    fn default() -> Self {
        Self::new()
    }
}

impl Packets {
    /// Reads packets up to [`MAX_PACKET`] bytes, including their headers.
    pub fn new() -> Self {
        Self::with_limit(MAX_PACKET)
    }

    /// Reads packets up to `limit` bytes, including their headers.
    /// Clamps the limit to [`MIN_PACKET`] through [`MAX_PACKET`].
    /// A larger declared packet is refused as soon as its header arrives.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: clamp_limit(limit),
        }
    }

    /// The maximum packet size, including its header.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Decode for Packets {
    type Item = Packet;
    type Error = TpktError;
    const NAME: &'static str = "TPKT";

    fn capacity(&self) -> usize {
        self.limit
    }

    /// Reads one packet. Returns [`TpktError::Version`] for a version other
    /// than 3, [`TpktError::Length`] below [`MIN_PACKET`], or
    /// [`TpktError::TooLong`] above the configured limit. Partial input
    /// returns [`Step::Need`], including at EOF.
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Packet>, TpktError> {
        Ok(match Packet::parse_limited(input, self.limit)? {
            Some((packet, used)) => Step::Item(packet, used),
            None => Step::Need,
        })
    }
}

#[cfg(test)]
mod codec_tests {
    use fictionet::stdlib::codec::{Fail, Stream, contract};
    use super::*;

    #[test]
    fn exact_wire_and_transactional_writes() {
        let packet = Packet {
            reserved: 0x91,
            payload: vec![2, 0xf0, 0x80],
        };
        let bytes = Wire::to_bytes(&packet).unwrap();
        assert_eq!(<Packet as Wire>::parse(&bytes), Ok(packet.clone()));
        contract::check_wire::<Packet>(&bytes);
        for cut in 0..bytes.len() {
            assert_eq!(
                <Packet as Wire>::parse(&bytes[..cut]),
                Err(ParseError::Incomplete)
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            <Packet as Wire>::parse(&trailing),
            Err(ParseError::Trailing { remaining: 1 })
        );
        assert_eq!(Packet::parse(&trailing), Ok(Some((packet, bytes.len()))));
        assert_eq!(
            <Packet as Wire>::parse(&[9]),
            Err(ParseError::Header(TpktError::Version(9)))
        );

        for size in [
            0,
            MIN_PAYLOAD - 1,
            MIN_PAYLOAD,
            MAX_PAYLOAD,
            MAX_PAYLOAD + 1,
        ] {
            let value = Packet::new(vec![0; size]);
            contract::check_wire_value(&value);
            let mut out = vec![0x55];
            let result = value.write(&mut out);
            assert_eq!(result.is_ok(), (MIN_PAYLOAD..=MAX_PAYLOAD).contains(&size));
            if result.is_err() {
                assert_eq!(out, [0x55]);
            }
        }
    }

    #[test]
    fn frame_limits_eof_and_error_once() {
        for limit in [0, MIN_PACKET, 128, MAX_PACKET, usize::MAX] {
            let frames = Packets::with_limit(limit);
            assert_eq!(frames.capacity(), limit.clamp(MIN_PACKET, MAX_PACKET));
            assert_eq!(frames.held(), 0);
            for input in [
                &[][..],
                &[3],
                &[3, 0, 0, 6],
                &[0],
                &[3, 4, 0, 7, 2, 0xf0, 0x80],
            ] {
                contract::check_decode_with_held_limit(|| frames, input, 0);
            }
        }
        let mut stream = Stream::new(Packets::with_limit(8));
        assert_eq!(stream.push(&[3, 0, 0, 9]), 4);
        let error = Fail::Protocol(TpktError::TooLong {
            length: 9,
            limit: 8,
        });
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
        assert_eq!(stream.push(&[1, 2]), 2);
        assert_eq!(stream.buffered(), 4);

        let mut stream = Stream::new(Packets::new());
        assert_eq!(stream.push(&[3, 0, 0, 7, 2]), 5);
        assert_eq!(stream.next(), None);
        stream.end();
        assert_eq!(stream.next(), Some(Err(Fail::Truncated { unread: 5 })));
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn maximum_packet_in_byte_chunks() {
        let packet = Packet::new(vec![0x5a; MAX_PAYLOAD]);
        let bytes = packet.to_bytes().unwrap();
        let mut stream = Stream::new(Packets::new());
        for (i, byte) in fictionet::stdlib::codec::test_support::chunks(&bytes, &[1]).enumerate() {
            assert_eq!(stream.push(byte), 1);
            assert!(stream.buffered() <= MAX_PACKET);
            let result = stream.next();
            if i + 1 == bytes.len() {
                assert_eq!(result, Some(Ok(packet.clone())));
            } else {
                assert_eq!(result, None);
            }
        }
        stream.end();
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::test_support::Lcg;
    use fictionet::stdlib::codec::{Fail, Stream, contract, test_support};

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
    }

    #[test]
    fn header_fields() {
        let h = Header {
            reserved: 9,
            length: 0x1234,
        };
        assert_eq!(h.to_bytes(), Ok(vec![3, 9, 0x12, 0x34]));
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
        for e in [EncodeError::TooShort(1), EncodeError::TooLong(1)] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn stream_packets() {
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
        contract::check_decode_with_alloc_limit(Packets::new, &stream, 2 * MAX_PACKET);
        assert_eq!(
            test_support::decode_all(Packets::new, &stream),
            (packets.clone(), None)
        );
        // An error after good packets, and the decoder stays broken.
        stream.extend_from_slice(&[4, 0, 0, 7]);
        let mut d = Stream::new(Packets::new());
        assert_eq!(d.push(&stream), stream.len());
        for p in &packets {
            assert_eq!(d.next(), Some(Ok(p.clone())));
        }
        assert_eq!(d.next(), Some(Err(Fail::Protocol(TpktError::Version(4)))));
        assert_eq!(d.next(), None);
        assert_eq!(d.push(&[1, 2, 3]), 3);
        assert_eq!(d.failed(), Some(&Fail::Protocol(TpktError::Version(4))));
        assert_eq!(Packets::default().limit(), MAX_PACKET);
    }

    #[test]
    fn stream_limit() {
        let mut d = Stream::new(Packets::with_limit(100));
        assert_eq!(d.decoder().limit(), 100);
        let ok = Packet::new(vec![1; 96]).to_bytes().unwrap();
        assert_eq!(d.push(&ok), 100);
        assert_eq!(d.next(), Some(Ok(Packet::new(vec![1; 96]))));
        // Known from the header alone, before the payload comes.
        assert_eq!(d.push(&[3, 0, 0, 101]), 4);
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(TpktError::TooLong {
                length: 101,
                limit: 100
            })))
        );
        // A decoder only takes what its limit holds.
        let mut d = Stream::new(Packets::with_limit(10));
        assert_eq!(d.push(&[3, 0, 0, 10, 0, 0, 0, 0, 0, 0, 3, 0]), 10);
        assert!(d.next().unwrap().is_ok());
        assert_eq!(Packets::with_limit(0).limit(), MIN_PACKET);
        assert_eq!(Packets::with_limit(usize::MAX).limit(), MAX_PACKET);
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x7b47);
        for i in 0..4000 {
            // Mostly well-formed packets, with some bytes changed.
            let mut data = Vec::new();
            for _ in 0..rng.below(4) {
                let mut payload = rng.bytes(if i % 50 == 0 { 3002 } else { 42 });
                payload.resize(payload.len().max(MIN_PAYLOAD), 0);
                let p = Packet {
                    reserved: rng.next() as u8,
                    payload,
                };
                data.extend_from_slice(&p.to_bytes().unwrap());
            }
            data.extend(rng.bytes(11));
            for _ in 0..rng.below(3) {
                test_support::mutate(&mut rng, &mut data);
            }
            let limit = [MAX_PACKET, 7, 20, 64, 1000][rng.index(5)];
            contract::check_decode_with_alloc_limit(
                || Packets::with_limit(limit),
                &data,
                2 * clamp_limit(limit),
            );
            let whole = test_support::decode_all(|| Packets::with_limit(limit), &data);
            for p in &whole.0 {
                assert!(p.payload.len() + HEADER_LEN <= limit);
                let bytes = p.to_bytes().unwrap();
                assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
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
            // Raw bytes, never panicking.
            let raw = rng.bytes(19);
            let _ = Packet::parse(&raw);
            let _ = Packet::parse_limited(&raw, rng.index(usize::MAX));
            contract::check_decode_with_alloc_limit(Packets::new, &raw, 2 * MAX_PACKET);
            let _ = test_support::decode_all(Packets::new, &raw);
        }
    }
}
