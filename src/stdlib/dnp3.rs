//! DNP3: reading and writing link frames, transport segments and application
//! headers, with no I/O.
//!
//! DNP3 connects industrial controllers and outstations, usually over TCP
//! port 20000. A link frame starts with `05 64` and carries a CRC after its
//! header and after every block of up to 16 data bytes. [`Frame`] checks
//! every CRC and removes them from its data; its writer puts them back.
//! The framing follows IEEE 1815 (DNP3).
//!
//! Push connection bytes to a [`Stream<codec::Frames<Frame>>`](fictionet::stdlib::codec::Stream),
//! then read each data frame's [`Segment`]. A [`Reassembler`] joins transport
//! segments into application fragments. Use one reassembler per source,
//! destination and direction. Link acknowledgments, duplicate suppression
//! and session state belong to world code. [`Fragment`] reads the
//! application header and leaves object groups and variations as bytes.
//! Secure authentication is not performed.
//! Unknown link and application function codes are preserved.
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::dnp3::{Frame, Fragment, Segment};
//!
//! // Read class 0 data: group 60, variation 1, all objects.
//! let request = Fragment { control: 0xc0, function: 1, indications: None,
//!                          objects: vec![60, 1, 6] };
//! let segment = Segment { first: true, final_segment: true, sequence: 0,
//!                         data: request.to_bytes().unwrap() };
//! let frame = Frame { control: 0xc4, destination: 1, source: 1024,
//!                     data: segment.to_bytes().unwrap() };
//! let bytes = frame.to_bytes().unwrap();
//! let mut decoder = Stream::new(Frames::<Frame>::new());
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! assert_eq!(decoder.next().unwrap().unwrap(), frame);
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Prefixed;
use fictionet::stdlib::codec::{Wire, le16};

/// The usual TCP and UDP port.
pub const PORT: u16 = 20000;
/// Link header size, including its CRC.
pub const HEADER_LEN: usize = 10;
/// The most user data a link frame holds, before block CRCs.
pub const MAX_DATA: usize = 250;
/// The longest link frame, including all CRCs.
pub const MAX_FRAME: usize = 292;
/// The local limit on a reassembled application fragment.
pub const MAX_FRAGMENT: usize = 64 << 10;

/// Why a link frame, a transport segment or an application fragment
/// cannot be read or written, or why a segment sequence cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The start bytes were not `05 64`.
    Start,
    /// The length field was below five, or user data exceeded 250 bytes.
    FrameLength,
    /// A CRC failed, at this byte offset in the wire frame.
    Crc(usize),
    /// The input ended before a complete frame, including empty input.
    Truncated,
    /// Bytes follow the first complete frame.
    Trailing,
    /// The link frame does not carry transport data.
    NotData,
    /// A segment needs a header and 1 to 249 data bytes.
    SegmentLength,
    /// A sequence number is above 63, or does not follow the previous one.
    Sequence,
    /// A continuation arrived without a first segment.
    MissingFirst,
    /// The application fragment would exceed [`MAX_FRAGMENT`].
    FragmentTooLong,
    /// Missing application header bytes, or more than [`MAX_FRAGMENT`].
    FragmentLength,
    /// Response functions (bit 7 set) require IIN; requests must omit it.
    Indications,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start => f.write_str("DNP3 frame does not start with 05 64"),
            Self::FrameLength => f.write_str("DNP3 frame length is outside its range"),
            Self::Crc(at) => write!(f, "DNP3 CRC failed at byte {at}"),
            Self::Truncated => f.write_str("incomplete DNP3 frame"),
            Self::Trailing => f.write_str("bytes follow the DNP3 frame"),
            Self::NotData => f.write_str("DNP3 link frame does not carry user data"),
            Self::SegmentLength => f.write_str("DNP3 transport segment length is outside 2..=250"),
            Self::Sequence => f.write_str("DNP3 transport sequence is invalid"),
            Self::MissingFirst => f.write_str("DNP3 transport continuation has no first segment"),
            Self::FragmentTooLong => {
                f.write_str("DNP3 application fragment exceeds the local limit")
            }
            Self::FragmentLength => {
                f.write_str("DNP3 application fragment length is outside its range")
            }
            Self::Indications => f.write_str("DNP3 internal indications do not match the function"),
        }
    }
}

impl std::error::Error for Error {}

/// CRC-16/DNP: reflected polynomial `0xa6bc`, initial value zero, complemented
/// result. A frame sends the result least significant byte first.
pub fn crc(data: &[u8]) -> u16 {
    let mut value = 0u16;
    for &byte in data {
        value ^= u16::from(byte);
        for _ in 0..8 {
            value = (value >> 1) ^ if value & 1 != 0 { 0xa6bc } else { 0 };
        }
    }
    !value
}

/// A link frame with its CRCs removed. Control bits and unknown functions
/// are preserved; link state and function-specific rules are not checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Direction, primary/secondary, FCB/DFC, FCV and function bits.
    pub control: u8,
    /// Destination link address.
    pub destination: u16,
    /// Source link address.
    pub source: u16,
    /// User data, normally a transport segment; empty for link-only frames.
    pub data: Vec<u8>,
}

impl Frame {
    /// Reads one frame at the start of `b`, returning its consumed length.
    /// `Ok(None)` means more bytes are needed. Invalid headers and complete
    /// bad CRC blocks are reported as soon as they are available.
    pub fn parse_prefix(b: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let n = b.len().min(2);
        if b[..n] != [5, 0x64][..n] {
            return Err(Error::Start);
        }
        let Some(&length) = b.get(2) else {
            return Ok(None);
        };
        if length < 5 {
            return Err(Error::FrameLength);
        }
        if b.len() < HEADER_LEN {
            return Ok(None);
        }
        check_crc(b, 0, 8)?;
        let length = usize::from(length) - 5;
        let mut at = HEADER_LEN;
        let mut left = length;
        while left != 0 {
            let size = left.min(16);
            if b.len() < at + size + 2 {
                return Ok(None);
            }
            check_crc(b, at, size)?;
            at += size + 2;
            left -= size;
        }
        let mut data = Vec::with_capacity(length);
        let mut pos = HEADER_LEN;
        while data.len() < length {
            let size = (length - data.len()).min(16);
            data.extend_from_slice(&b[pos..pos + size]);
            pos += size + 2;
        }
        Ok(Some((
            Self {
                control: b[3],
                destination: le16(b, 4).ok_or(Error::Truncated)?,
                source: le16(b, 6).ok_or(Error::Truncated)?,
                data,
            },
            at,
        )))
    }

    /// The low four bits of the link control byte.
    pub fn function(&self) -> u8 {
        self.control & 0x0f
    }

    /// Whether this is a primary link message.
    pub fn is_primary(&self) -> bool {
        self.control & 0x40 != 0
    }

    /// Reads the transport segment of a confirmed or unconfirmed user-data
    /// frame. Link-only and unknown functions give [`Error::NotData`].
    pub fn segment(&self) -> Result<Segment, Error> {
        if !self.is_primary() || !matches!(self.function(), 3 | 4) {
            return Err(Error::NotData);
        }
        Segment::parse(&self.data)
    }
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one frame. Incomplete input and trailing bytes are errors.
    /// Returns [`Error::Truncated`] for an incomplete frame and
    /// [`Error::Trailing`] for extra bytes. Bad start bytes, lengths
    /// and CRCs return [`Error::Start`],
    /// [`Error::FrameLength`] or [`Error::Crc`].
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match Self::parse_prefix(b)? {
            Some((frame, used)) if used == b.len() => Ok(frame),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Truncated),
        }
    }

    /// Writes the header and each data block with freshly calculated CRCs.
    /// Returns [`Error::FrameLength`] if data exceeds [`MAX_DATA`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.data.len() > MAX_DATA {
            return Err(Error::FrameLength);
        }
        let mut out = Vec::with_capacity(MAX_FRAME);
        out.extend_from_slice(&[5, 0x64, (self.data.len() + 5) as u8, self.control]);
        out.extend_from_slice(&self.destination.to_le_bytes());
        out.extend_from_slice(&self.source.to_le_bytes());
        out.extend_from_slice(&crc(&out).to_le_bytes());
        for block in self.data.chunks(16) {
            out.extend_from_slice(block);
            out.extend_from_slice(&crc(block).to_le_bytes());
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

/// Reads DNP3 frames without holding input bytes.
///
/// Use with [`Stream<codec::Frames<Frame>>`](fictionet::stdlib::codec::Stream) for a buffer limited to
/// [`MAX_FRAME`]. Partial frames return [`fictionet::stdlib::codec::Step::Need`], including at EOF.
/// The stream reports truncation at EOF and framing errors once.
impl Prefixed for Frame {
    type Item = Frame;
    type Error = Error;
    type Limit = ();
    const NAME: &'static str = "DNP3";

    #[inline]
    fn default_limit() -> Self::Limit {}

    #[inline]
    fn capacity(_limit: &Self::Limit) -> usize {
        MAX_FRAME
    }

    /// Reads a frame prefix, returning [`fictionet::stdlib::codec::Step::Need`] while incomplete.
    /// Returns [`Error::Start`], [`Error::FrameLength`] or
    /// [`Error::Crc`] for invalid start bytes, lengths or CRCs.
    #[inline]
    fn parse_prefix(
        input: &[u8],
        _limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        Frame::parse_prefix(input)
    }
}

fn check_crc(b: &[u8], at: usize, size: usize) -> Result<(), Error> {
    if crc(&b[at..at + size]) == le16(b, at + size).ok_or(Error::Truncated)? {
        Ok(())
    } else {
        Err(Error::Crc(at + size))
    }
}

/// One transport header and its portion of an application fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// FIR: starts a fragment.
    pub first: bool,
    /// FIN: ends a fragment.
    pub final_segment: bool,
    /// Six-bit sequence number, wrapping from 63 to 0.
    pub sequence: u8,
    /// Between 1 and 249 application bytes.
    pub data: Vec<u8>,
}
impl Segment {
    fn validate(&self) -> Result<(), Error> {
        if self.sequence > 63 {
            return Err(Error::Sequence);
        }
        if self.data.is_empty() || self.data.len() >= MAX_DATA {
            return Err(Error::SegmentLength);
        }
        Ok(())
    }
}

/// Joins transport segments for one link-address pair and direction. A
/// new FIR discards any unfinished fragment. Any error resets the state.
#[derive(Debug, Default)]
pub struct Reassembler {
    data: Vec<u8>,
    next: Option<u8>,
}
impl Reassembler {
    /// An empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a segment, returning an application fragment at FIN.
    pub fn push(&mut self, segment: &Segment) -> Result<Option<Vec<u8>>, Error> {
        let result = self.push_inner(segment);
        if result.is_err() {
            *self = Self::new();
        }
        result
    }

    fn push_inner(&mut self, s: &Segment) -> Result<Option<Vec<u8>>, Error> {
        s.validate()?;
        if s.first {
            self.data.clear();
        } else {
            let expected = self.next.ok_or(Error::MissingFirst)?;
            if s.sequence != expected {
                return Err(Error::Sequence);
            }
        }
        if self
            .data
            .len()
            .checked_add(s.data.len())
            .is_none_or(|n| n > MAX_FRAGMENT)
        {
            return Err(Error::FragmentTooLong);
        }
        self.data.extend_from_slice(&s.data);
        self.next = Some((s.sequence + 1) & 63);
        if s.final_segment {
            self.next = None;
            Ok(Some(std::mem::take(&mut self.data)))
        } else {
            Ok(None)
        }
    }

    /// Application bytes pending in the current fragment.
    pub fn pending(&self) -> usize {
        self.data.len()
    }
}

/// An application fragment, after transport reassembly. Object headers and
/// values remain opaque; no application-fragment reassembly is performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// FIR, FIN, CON, UNS and the four-bit application sequence.
    pub control: u8,
    /// Application function, such as 1 (READ) or 0x81 (RESPONSE).
    pub function: u8,
    /// Internal indications in responses, with IIN1 in the low byte.
    pub indications: Option<u16>,
    /// Encoded object headers and values.
    pub objects: Vec<u8>,
}
impl Wire for Segment {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole transport segment, without link framing.
    /// Returns [`Error::SegmentLength`] unless the input has 2 through
    /// [`MAX_DATA`] bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if !(2..=MAX_DATA).contains(&b.len()) {
            return Err(Error::SegmentLength);
        }
        Ok(Self {
            first: b[0] & 0x40 != 0,
            final_segment: b[0] & 0x80 != 0,
            sequence: b[0] & 0x3f,
            data: b[1..].to_vec(),
        })
    }

    /// Writes a transport header followed by its data.
    /// Returns [`Error::Sequence`] above sequence 63 and
    /// [`Error::SegmentLength`] unless data has 1 through 249 bytes.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        let mut out = vec![
            self.sequence
                | if self.first { 0x40 } else { 0 }
                | if self.final_segment { 0x80 } else { 0 },
        ];
        out.extend_from_slice(&self.data);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Fragment {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete application fragment.
    /// Returns [`Error::FragmentLength`] for a short header, a response
    /// without its two IIN bytes, or input above [`MAX_FRAGMENT`].
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 2 || b.len() > MAX_FRAGMENT {
            return Err(Error::FragmentLength);
        }
        let response = b[1] & 0x80 != 0;
        let header = if response { 4 } else { 2 };
        if b.len() < header {
            return Err(Error::FragmentLength);
        }
        Ok(Self {
            control: b[0],
            function: b[1],
            indications: if response {
                Some(le16(b, 2).ok_or(Error::FragmentLength)?)
            } else {
                None
            },
            objects: b[header..].to_vec(),
        })
    }

    /// Writes an application fragment, requiring IIN exactly for responses.
    /// Returns [`Error::Indications`] if IIN presence disagrees
    /// with the response bit. Returns [`Error::FragmentLength`] when the
    /// header and objects exceed [`MAX_FRAGMENT`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if (self.function & 0x80 != 0) != self.indications.is_some() {
            return Err(Error::Indications);
        }
        let header = if self.indications.is_some() { 4 } else { 2 };
        if self.objects.len() > MAX_FRAGMENT - header {
            return Err(Error::FragmentLength);
        }
        let mut out = vec![self.control, self.function];
        if let Some(iin) = self.indications {
            out.extend_from_slice(&iin.to_le_bytes());
        }
        out.extend_from_slice(&self.objects);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Stream};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::decode_all;

    // Reset link states: master 1024 to outstation 1, no user data.
    const RESET: &[u8] = &[5, 0x64, 5, 0xc0, 1, 0, 0, 4, 0xe9, 0x21];

    #[test]
    fn known_crc_and_link_frame() {
        assert_eq!(crc(b"123456789"), 0xea82);
        let (frame, used) = Frame::parse_prefix(RESET).unwrap().unwrap();
        assert_eq!(used, 10);
        assert_eq!(
            frame,
            Frame {
                control: 0xc0,
                destination: 1,
                source: 1024,
                data: vec![]
            }
        );
        assert_eq!(frame.to_bytes().unwrap(), RESET);
        assert_eq!(frame.segment(), Err(Error::NotData));
        for n in 0..RESET.len() {
            assert_eq!(Frame::parse_prefix(&RESET[..n]), Ok(None));
        }
    }

    #[test]
    fn every_block_boundary_and_truncated_prefix() {
        for n in 0..=MAX_DATA {
            let frame = Frame {
                control: 0xc4,
                destination: 0xffff,
                source: 0x1234,
                data: (0..n as u8).collect(),
            };
            let bytes = frame.to_bytes().unwrap();
            assert_eq!(bytes.len(), HEADER_LEN + n + 2 * n.div_ceil(16));
            for cut in 0..bytes.len() {
                assert_eq!(Frame::parse_prefix(&bytes[..cut]), Ok(None));
            }
            let mut joined = bytes.clone();
            joined.extend_from_slice(RESET);
            assert_eq!(Frame::parse_prefix(&joined), Ok(Some((frame, bytes.len()))));
        }
        let frame = Frame {
            control: 0xc4,
            destination: 1,
            source: 0,
            data: vec![0; MAX_DATA + 1],
        };
        assert_eq!(frame.to_bytes(), Err(Error::FrameLength));
    }

    #[test]
    fn corruption_in_each_crc_block_is_rejected() {
        let frame = Frame {
            control: 0xc4,
            destination: 1,
            source: 0,
            data: vec![42; MAX_DATA],
        };
        let bytes = frame.to_bytes().unwrap();
        for at in 3..bytes.len() {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(
                matches!(Frame::parse_prefix(&bad), Err(Error::Crc(_))),
                "offset {at}"
            );
        }
        assert_eq!(Frame::parse_prefix(&[4]), Err(Error::Start));
        assert_eq!(Frame::parse_prefix(&[5, 0x65]), Err(Error::Start));
        assert_eq!(Frame::parse_prefix(&[5, 0x64, 4]), Err(Error::FrameLength));
    }

    #[test]
    fn stream_limits_and_terminal_failure() {
        let frame = Frame {
            control: 0xc4,
            destination: 1,
            source: 2,
            data: vec![0; MAX_DATA],
        };
        let encoded = frame.to_bytes().unwrap();
        assert_eq!(encoded.len(), MAX_FRAME);
        let bytes = encoded.repeat(10);
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &bytes, 2 * MAX_FRAME);
        let (frames, failure) = decode_all(Frames::<Frame>::new, &bytes);
        assert!(failure.is_none());
        assert_eq!(frames, vec![frame; 10]);
        let mut stream = Stream::new(Frames::<Frame>::new());
        assert_eq!(stream.push(&vec![0; MAX_FRAME + 1]), MAX_FRAME);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::Start))));
        assert_eq!(stream.failed(), Some(&Fail::Protocol(Error::Start)));
        assert!(stream.next().is_none());
        assert_eq!(stream.push(&[0]), 1);
    }

    #[test]
    fn transport_sequence_wrap_restarts_and_errors() {
        let mut r = Reassembler::new();
        let mut s = Segment {
            first: true,
            final_segment: false,
            sequence: 63,
            data: vec![1, 2],
        };
        assert_eq!(Segment::parse(&s.to_bytes().unwrap()), Ok(s.clone()));
        assert_eq!(r.push(&s), Ok(None));
        s.first = false;
        s.sequence = 0;
        s.final_segment = true;
        assert_eq!(r.push(&s), Ok(Some(vec![1, 2, 1, 2])));
        assert_eq!(r.push(&s), Err(Error::MissingFirst));
        s.first = true;
        s.final_segment = false;
        assert_eq!(r.push(&s), Ok(None));
        assert_eq!(r.push(&s), Ok(None)); // FIR replaces unfinished data.
        assert_eq!(r.pending(), 2);
        s.first = false;
        s.sequence = 2;
        assert_eq!(r.push(&s), Err(Error::Sequence));
        assert_eq!(r.pending(), 0);
        s.sequence = 64;
        assert_eq!(s.to_bytes(), Err(Error::Sequence));
        assert_eq!(Segment::parse(&[]), Err(Error::SegmentLength));
        assert_eq!(Segment::parse(&[0xc0]), Err(Error::SegmentLength));
    }

    #[test]
    fn transport_size_limit_resets_state() {
        let mut r = Reassembler::new();
        let mut s = Segment {
            first: true,
            final_segment: false,
            sequence: 0,
            data: vec![0; 249],
        };
        assert_eq!(r.push(&s), Ok(None));
        s.first = false;
        loop {
            s.sequence = (s.sequence + 1) & 63;
            match r.push(&s) {
                Ok(None) => assert!(r.pending() <= MAX_FRAGMENT),
                Err(Error::FragmentTooLong) => break,
                other => panic!("unexpected result {other:?}"),
            }
        }
        assert_eq!(r.pending(), 0);
        s.first = true;
        s.final_segment = true;
        assert_eq!(r.push(&s), Ok(Some(s.data.clone())));
    }

    #[test]
    fn application_requests_responses_and_opaque_objects() {
        for bytes in [
            &[0xc0, 1, 60, 1, 6][..],
            &[0xf3, 0x81, 0x80, 2, 1, 2, 3][..],
            &[0xc1, 0x82, 0, 0][..],
        ] {
            let fragment = Fragment::parse(bytes).unwrap();
            assert_eq!(fragment.to_bytes().unwrap(), bytes);
        }
        assert_eq!(Fragment::parse(&[0xc0]), Err(Error::FragmentLength));
        assert_eq!(
            Fragment::parse(&[0xc0, 0x81, 0]),
            Err(Error::FragmentLength)
        );
        let mut fragment = Fragment {
            control: 0xc0,
            function: 1,
            indications: Some(0),
            objects: vec![],
        };
        assert_eq!(fragment.to_bytes(), Err(Error::Indications));
        fragment.indications = None;
        fragment.objects = vec![0; MAX_FRAGMENT - 2];
        assert!(fragment.to_bytes().is_ok());
        fragment.objects.push(0);
        assert_eq!(fragment.to_bytes(), Err(Error::FragmentLength));
    }
}
