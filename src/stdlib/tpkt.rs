//! TPKT: reading and writing the packets that carry ISO transport on TCP,
//! with no I/O.
//!
//! `Packet` implements `Wire` and supports `codec::Frames<Packet>` stream
//! decoding. It keeps the TPDU as bytes and supplies no COTP session,
//! `Service`, or live TCP transport.
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
//! TCP connection into a [`Stream<codec::Frames<Packet>>`](fictionet::stdlib::codec::Stream), takes each
//! [`Packet`] out, and reads its payload. Most payloads are COTP TPDUs;
//! [`fictionet::stdlib::cotp::over_tpkt`] provides conversions and a message writer.
//! A world may set a size limit lower than the 65535 bytes the header allows, as
//! real stacks often do.
//!
//! A stream that breaks the format gives a [`Error`], and a
//! real server closes the connection. Writers return an [`Error`]
//! rather than write a packet a reader would refuse.
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::tpkt::Packet;
//!
//! let mut decoder = Stream::new(Frames::<Packet>::new());
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
//! assert_eq!(Packet::parse_prefix(&[3, 0, 0, 7, 1, 2, 3]), Ok(Some((packet, 7))));
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Decode;
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Wire;

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

/// Why bytes are not a TPKT stream or packet, or why a writer refused a
/// value. After an error from [`codec::Frames<Packet>`](fictionet::stdlib::codec::Frames) the connection holds no more
/// packets a reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The first byte was not 3. RDP's fast-path packets look like this.
    Version(u8),
    /// The length field was below [`MIN_PACKET`].
    Length(u16),
    /// The length field was above the reader's size limit.
    OverLimit {
        /// The length field.
        length: u16,
        /// The longest packet the reader takes.
        limit: usize,
    },
    /// The slice ended before the packet was complete.
    Incomplete,
    /// Bytes followed the complete packet.
    Trailing {
        /// Number of bytes after the packet.
        remaining: usize,
    },
    /// A payload to write is shorter than [`MIN_PAYLOAD`], with its length.
    PayloadTooShort(usize),
    /// A payload to write is longer than [`MAX_PAYLOAD`], with its length.
    PayloadTooLong(usize),
}

fictionet::error_display!(Error, f, {
    Error::Version(v) => write!(f, "TPKT version {v}, not {VERSION}"),
    Error::Length(n) => write!(f, "TPKT length {n}, below {MIN_PACKET}"),
    Error::OverLimit { length, limit } => {
        write!(f, "TPKT length {length}, above the limit of {limit}")
    }
    Error::Incomplete => f.write_str("incomplete TPKT packet"),
    Error::Trailing { remaining } => write!(f, "{remaining} bytes after TPKT packet"),
    Error::PayloadTooShort(n) => {
        write!(f, "TPKT payload of {n} bytes, below {MIN_PAYLOAD}")
    }
    Error::PayloadTooLong(n) => write!(f, "{n} bytes, more than TPKT may carry"),
});

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
    pub fn parse(b: &[u8], limit: usize) -> Result<Option<Header>, Error> {
        let Some(&version) = b.first() else {
            return Ok(None);
        };
        if version != VERSION {
            return Err(Error::Version(version));
        }
        let [_, reserved, hi, lo, ..] = *b else {
            return Ok(None);
        };
        let length = u16::from_be_bytes([hi, lo]);
        if usize::from(length) < MIN_PACKET {
            return Err(Error::Length(length));
        }
        if usize::from(length) > clamp_limit(limit) {
            return Err(Error::OverLimit {
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
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly four header bytes. Returns [`Error::Incomplete`]
    /// for a partial header and [`Error::Trailing`] for extra bytes.
    /// A version other than 3 or a length below [`MIN_PACKET`] returns
    /// [`Error::Version`] or [`Error::Length`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let header = Header::parse(bytes, MAX_PACKET)?.ok_or(Error::Incomplete)?;
        if bytes.len() != HEADER_LEN {
            return Err(Error::Trailing {
                remaining: bytes.len().saturating_sub(HEADER_LEN),
            });
        }
        Ok(header)
    }

    /// Appends the header. A length below [`MIN_PACKET`] returns
    /// [`Error::PayloadTooShort`] without changing `out`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if usize::from(self.length) < MIN_PACKET {
            return Err(Error::PayloadTooShort(self.payload_len()));
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
    pub fn parse_prefix(b: &[u8]) -> Result<Option<(Packet, usize)>, Error> {
        Packet::parse_limited(b, MAX_PACKET)
    }

    /// Reads the packet at the start of `b`, as [`Packet::parse_prefix`] does,
    /// but refuses one longer than `limit` bytes. A limit below
    /// [`MIN_PACKET`] is taken as that, and one above [`MAX_PACKET`] as
    /// that.
    pub fn parse_limited(b: &[u8], limit: usize) -> Result<Option<(Packet, usize)>, Error> {
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
    pub fn header(&self) -> Result<Header, Error> {
        let n = self.payload.len();
        if n < MIN_PAYLOAD {
            return Err(Error::PayloadTooShort(n));
        }
        if n > MAX_PAYLOAD {
            return Err(Error::PayloadTooLong(n));
        }
        // n + HEADER_LEN is at most MAX_PACKET, so it fits in 16 bits.
        Ok(Header {
            reserved: self.reserved,
            length: (n + HEADER_LEN) as u16,
        })
    }
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one packet. Returns [`Error::Incomplete`] for
    /// partial input and [`Error::Trailing`] for extra bytes. A version
    /// other than 3 or a length below [`MIN_PACKET`] returns
    /// [`Error::Version`] or [`Error::Length`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (packet, used) = Packet::parse_prefix(bytes)?.ok_or(Error::Incomplete)?;
        if used != bytes.len() {
            return Err(Error::Trailing {
                remaining: bytes.len().saturating_sub(used),
            });
        }
        Ok(packet)
    }

    /// Appends one packet. Payloads below [`MIN_PAYLOAD`] return
    /// [`Error::PayloadTooShort`]; those above [`MAX_PAYLOAD`] return
    /// [`Error::PayloadTooLong`]. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.header()?.write(out)?;
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

fictionet::prefixed! {
    /// Splits a TPKT byte stream into packets.
    ///
    /// Use with [`fictionet::stdlib::codec::Stream`] for bounded input buffering. A partial
    /// packet returns [`fictionet::stdlib::codec::Step::Need`], including at EOF. The stream reports
    /// truncation at EOF and reports framing errors once. No input is retained.
    Packet => (Packet, Error, usize);
    name = "TPKT";
    default { MAX_PACKET }
    normalize(limit) { clamp_limit(limit) }
    capacity(limit) { *limit }

    /// Reads one packet. Returns [`Error::Version`] for a version other
    /// than 3, [`Error::Length`] below [`MIN_PACKET`], or
    /// [`Error::OverLimit`] above the configured limit. Partial input
    /// returns [`fictionet::stdlib::codec::Step::Need`], including at EOF.
    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        Packet::parse_limited(input, limit)
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Stream};
    use fictionet::stdlib::test_support::contract;

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
                Err(Error::Incomplete)
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            <Packet as Wire>::parse(&trailing),
            Err(Error::Trailing { remaining: 1 })
        );
        assert_eq!(
            Packet::parse_prefix(&trailing),
            Ok(Some((packet, bytes.len())))
        );
        assert_eq!(<Packet as Wire>::parse(&[9]), Err(Error::Version(9)));

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
            let frames = Frames::<Packet>::with_limit(limit);
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
        let mut stream = Stream::new(Frames::<Packet>::with_limit(8));
        assert_eq!(stream.push(&[3, 0, 0, 9]), 4);
        let error = Fail::Protocol(Error::OverLimit {
            length: 9,
            limit: 8,
        });
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
        assert_eq!(stream.push(&[1, 2]), 2);
        assert_eq!(stream.buffered(), 4);

        let mut stream = Stream::new(Frames::<Packet>::new());
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
        let mut stream = Stream::new(Frames::<Packet>::new());
        for (i, byte) in fictionet::stdlib::test_support::chunks(&bytes, &[1]).enumerate() {
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
    fn fixture_header(reserved: u8, length: u16) -> Header {
        Header { reserved, length }
    }

    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::codec::{Fail, Stream};
    use fictionet::stdlib::test_support;
    use fictionet::stdlib::test_support::contract;

    // RFC 1006 section 6: version 3, reserved, then the length of the
    // whole packet, header included. The smallest TPDU, a class 0 data
    // TPDU with no data, makes the smallest packet.
    #[test]
    fn rfc1006_example() {
        let bytes = [3, 0, 0, 7, 2, 0xf0, 0x80];
        let packet = Packet::new(vec![2, 0xf0, 0x80]);
        assert_eq!(Packet::parse_prefix(&bytes), Ok(Some((packet.clone(), 7))));
        assert_eq!(packet.to_bytes().unwrap(), bytes);
        assert_eq!(packet.header(), Ok(fixture_header(0, 7)));
    }

    #[test]
    fn header_fields() {
        let h = fixture_header(9, 0x1234);
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
            assert_eq!(h.to_bytes(), Err(Error::PayloadTooShort(h.payload_len())));
        }
        let h = fixture_header(0, MIN_PACKET as u16);
        assert_eq!(
            Header::parse(&h.to_bytes().unwrap(), MAX_PACKET),
            Ok(Some(h))
        );
        assert_eq!(fixture_header(0, 2).payload_len(), 0);
        // The reserved byte is kept, not checked.
        let (p, _) = Packet::parse_prefix(&[3, 0xff, 0, 7, 1, 2, 3])
            .unwrap()
            .unwrap();
        assert_eq!(p.reserved, 0xff);
        assert_eq!(p.to_bytes().unwrap(), [3, 0xff, 0, 7, 1, 2, 3]);
    }

    #[test]
    fn every_prefix_is_incomplete() {
        let bytes = [3, 0, 0, 10, 2, 0xf0, 0x80, 1, 2, 3];
        for n in 0..bytes.len() {
            assert_eq!(Packet::parse_prefix(&bytes[..n]), Ok(None), "{n} bytes");
            if n < HEADER_LEN {
                assert_eq!(Header::parse(&bytes[..n], MAX_PACKET), Ok(None));
            }
        }
        // Bytes after the packet are left alone.
        let mut longer = bytes.to_vec();
        longer.extend_from_slice(&[3, 0]);
        assert_eq!(Packet::parse_prefix(&longer).unwrap().unwrap().1, 10);
    }

    #[test]
    fn parse_errors() {
        // A bad version is known from the first byte.
        assert_eq!(Packet::parse_prefix(&[0x30]), Err(Error::Version(0x30)));
        assert_eq!(
            Packet::parse_prefix(&[2, 0, 0, 7, 1, 2, 3]),
            Err(Error::Version(2))
        );
        for n in 0..MIN_PACKET as u16 {
            let b = [3, 0, (n >> 8) as u8, n as u8];
            assert_eq!(Packet::parse_prefix(&b), Err(Error::Length(n)));
        }
        // The limit, as given and as clamped.
        assert_eq!(
            Packet::parse_limited(&[3, 0, 0, 9], 8),
            Err(Error::OverLimit {
                length: 9,
                limit: 8
            })
        );
        assert!(Packet::parse_limited(&[3, 0, 0, 8], 8).unwrap().is_none());
        assert_eq!(
            Packet::parse_limited(&[3, 0, 0, 8], 0),
            Err(Error::OverLimit {
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
            Error::Version(2),
            Error::Length(2),
            Error::OverLimit {
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
                Err(Error::PayloadTooShort(n))
            );
        }
        let big = Packet::new(vec![0; MAX_PAYLOAD + 1]);
        assert_eq!(big.to_bytes(), Err(Error::PayloadTooLong(MAX_PAYLOAD + 1)));
        let max = Packet::new(vec![7; MAX_PAYLOAD]);
        let bytes = max.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_PACKET);
        assert_eq!(&bytes[..4], &[3, 0, 0xff, 0xff]);
        assert_eq!(Packet::parse_prefix(&bytes), Ok(Some((max, MAX_PACKET))));
        for e in [Error::PayloadTooShort(1), Error::PayloadTooLong(1)] {
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
        contract::check_decode_with_alloc_limit(Frames::<Packet>::new, &stream, 2 * MAX_PACKET);
        assert_eq!(
            test_support::decode_all(Frames::<Packet>::new, &stream),
            (packets.clone(), None)
        );
        // An error after good packets, and the decoder stays broken.
        stream.extend_from_slice(&[4, 0, 0, 7]);
        let mut d = Stream::new(Frames::<Packet>::new());
        assert_eq!(d.push(&stream), stream.len());
        for p in &packets {
            assert_eq!(d.next(), Some(Ok(p.clone())));
        }
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::Version(4)))));
        assert_eq!(d.next(), None);
        assert_eq!(d.push(&[1, 2, 3]), 3);
        assert_eq!(d.failed(), Some(&Fail::Protocol(Error::Version(4))));
        assert_eq!(Frames::<Packet>::default().limit(), MAX_PACKET);
    }

    #[test]
    fn stream_limit() {
        let mut d = Stream::new(Frames::<Packet>::with_limit(100));
        assert_eq!(d.decoder().limit(), 100);
        let ok = Packet::new(vec![1; 96]).to_bytes().unwrap();
        assert_eq!(d.push(&ok), 100);
        assert_eq!(d.next(), Some(Ok(Packet::new(vec![1; 96]))));
        // Known from the header alone, before the payload comes.
        assert_eq!(d.push(&[3, 0, 0, 101]), 4);
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(Error::OverLimit {
                length: 101,
                limit: 100
            })))
        );
        // A decoder only takes what its limit holds.
        let mut d = Stream::new(Frames::<Packet>::with_limit(10));
        assert_eq!(d.push(&[3, 0, 0, 10, 0, 0, 0, 0, 0, 0, 3, 0]), 10);
        assert!(d.next().unwrap().is_ok());
        assert_eq!(Frames::<Packet>::with_limit(0).limit(), MIN_PACKET);
        assert_eq!(Frames::<Packet>::with_limit(usize::MAX).limit(), MAX_PACKET);
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
                || Frames::<Packet>::with_limit(limit),
                &data,
                2 * clamp_limit(limit),
            );
            let whole = test_support::decode_all(|| Frames::<Packet>::with_limit(limit), &data);
            for p in &whole.0 {
                assert!(p.payload.len() + HEADER_LEN <= limit);
                let bytes = p.to_bytes().unwrap();
                assert_eq!(
                    Packet::parse_prefix(&bytes),
                    Ok(Some((p.clone(), bytes.len())))
                );
            }
            // Any header a writer takes reads back the same.
            let h = fixture_header(rng.next() as u8, rng.next() as u16);
            match h.to_bytes() {
                Ok(b) => assert_eq!(Header::parse(&b, MAX_PACKET), Ok(Some(h))),
                Err(e) => {
                    assert!(usize::from(h.length) < MIN_PACKET);
                    assert_eq!(e, Error::PayloadTooShort(h.payload_len()));
                }
            }
            // Raw bytes, never panicking.
            let raw = rng.bytes(19);
            let _ = Packet::parse_prefix(&raw);
            let _ = Packet::parse_limited(&raw, rng.index(usize::MAX));
            contract::check_decode_with_alloc_limit(Frames::<Packet>::new, &raw, 2 * MAX_PACKET);
            let _ = test_support::decode_all(Frames::<Packet>::new, &raw);
        }
    }
}
