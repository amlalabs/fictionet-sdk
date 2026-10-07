//! DNP3: reading and writing link frames, transport segments and application
//! headers, with no I/O.
//!
//! DNP3 connects industrial controllers and outstations, usually over TCP
//! port 20000. A link frame starts with `05 64` and carries a CRC after its
//! header and after every block of up to 16 data bytes. [`Frame`] checks
//! every CRC and removes them from its data; its writer puts them back.
//! The framing follows IEEE 1815 (DNP3).
//!
//! Push connection bytes to a [`Stream<Frames>`](fictionet::stdlib::codec::Stream),
//! then read each data frame's [`Segment`]. A [`Reassembler`] joins transport
//! segments into application fragments. Use one reassembler per source,
//! destination and direction. Link acknowledgments, duplicate suppression
//! and session state belong to world code. [`Fragment`] reads the
//! application header and leaves object groups and variations as bytes.
//! Secure authentication is not performed.
//! Unknown link and application function codes are preserved.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::dnp3::{Frames, Frame, Fragment, Segment};
//!
//! // Read class 0 data: group 60, variation 1, all objects.
//! let request = Fragment { control: 0xc0, function: 1, indications: None,
//!                          objects: vec![60, 1, 6] };
//! let segment = Segment { first: true, final_segment: true, sequence: 0,
//!                         data: request.to_bytes().unwrap() };
//! let frame = Frame { control: 0xc4, destination: 1, source: 1024,
//!                     data: segment.to_bytes().unwrap() };
//! let bytes = frame.to_bytes().unwrap();
//! let mut decoder = Stream::new(Frames::new());
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! assert_eq!(decoder.next().unwrap().unwrap(), frame);
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};

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

/// Why a link frame cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The start bytes were not `05 64`.
    Start,
    /// The length field was below five, or user data exceeded 250 bytes.
    Length,
    /// A CRC failed, at this byte offset in the wire frame.
    Crc(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start => f.write_str("DNP3 frame does not start with 05 64"),
            Self::Length => f.write_str("DNP3 frame length is outside its range"),
            Self::Crc(at) => write!(f, "DNP3 CRC failed at byte {at}"),
        }
    }
}
impl std::error::Error for FrameError {}

/// Why an exact [`Wire`] parse did not read one complete frame.
/// [`Frame::parse_prefix`] reads a prefix and returns the bytes used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameParseError {
    /// The frame is invalid.
    Frame(FrameError),
    /// The input ended before a complete frame, including empty input.
    Truncated,
    /// Bytes follow the first complete frame.
    Trailing,
}

impl core::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Truncated => f.write_str("incomplete DNP3 frame"),
            Self::Trailing => f.write_str("bytes follow the DNP3 frame"),
        }
    }
}

impl core::error::Error for FrameParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(e) => Some(e),
            Self::Truncated | Self::Trailing => None,
        }
    }
}

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
    pub fn parse_prefix(b: &[u8]) -> Result<Option<(Self, usize)>, FrameError> {
        let n = b.len().min(2);
        if b[..n] != [5, 0x64][..n] {
            return Err(FrameError::Start);
        }
        let Some(&length) = b.get(2) else {
            return Ok(None);
        };
        if length < 5 {
            return Err(FrameError::Length);
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
                destination: le16(b, 4),
                source: le16(b, 6),
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
    /// frame. Link-only and unknown functions give [`TransportError::NotData`].
    pub fn segment(&self) -> Result<Segment, TransportError> {
        if !self.is_primary() || !matches!(self.function(), 3 | 4) {
            return Err(TransportError::NotData);
        }
        Segment::parse(&self.data)
    }
}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = FrameError;

    /// Reads exactly one frame. Incomplete input and trailing bytes are errors.
    /// Returns [`FrameParseError::Truncated`] for an incomplete frame and
    /// [`FrameParseError::Trailing`] for extra bytes. Bad start bytes, lengths
    /// and CRCs return [`FrameParseError::Frame`] with [`FrameError::Start`],
    /// [`FrameError::Length`] or [`FrameError::Crc`].
    fn parse(b: &[u8]) -> Result<Self, FrameParseError> {
        match Self::parse_prefix(b).map_err(FrameParseError::Frame)? {
            Some((frame, used)) if used == b.len() => Ok(frame),
            Some(_) => Err(FrameParseError::Trailing),
            None => Err(FrameParseError::Truncated),
        }
    }

    /// Writes the header and each data block with freshly calculated CRCs.
    /// Returns [`FrameError::Length`] if data exceeds [`MAX_DATA`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), FrameError> {
        if self.data.len() > MAX_DATA {
            return Err(FrameError::Length);
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
/// Use with [`Stream<Frames>`](fictionet::stdlib::codec::Stream) for a buffer limited to
/// [`MAX_FRAME`]. Partial frames return [`Step::Need`], including at EOF.
/// The stream reports truncation at EOF and framing errors once.
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames;

impl Frames {
    /// Creates a frame decoder with a capacity of [`MAX_FRAME`] bytes.
    pub fn new() -> Self {
        Self
    }
}

impl Decode for Frames {
    type Item = Frame;
    type Error = FrameError;
    const NAME: &'static str = "DNP3";

    fn capacity(&self) -> usize {
        MAX_FRAME
    }

    /// Reads a frame prefix, returning [`Step::Need`] while incomplete.
    /// Returns [`FrameError::Start`], [`FrameError::Length`] or
    /// [`FrameError::Crc`] for invalid start bytes, lengths or CRCs.
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, FrameError> {
        Ok(match Frame::parse_prefix(input)? {
            Some((frame, used)) => Step::Item(frame, used),
            None => Step::Need,
        })
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn check_crc(b: &[u8], at: usize, size: usize) -> Result<(), FrameError> {
    if crc(&b[at..at + size]) == le16(b, at + size) {
        Ok(())
    } else {
        Err(FrameError::Crc(at + size))
    }
}

/// Why a transport segment or sequence cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The link frame does not carry transport data.
    NotData,
    /// A segment needs a header and 1 to 249 data bytes.
    Length,
    /// A sequence number is above 63, or does not follow the previous one.
    Sequence,
    /// A continuation arrived without a first segment.
    MissingFirst,
    /// The application fragment would exceed [`MAX_FRAGMENT`].
    TooLong,
}
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotData => "DNP3 link frame does not carry user data",
            Self::Length => "DNP3 transport segment length is outside 2..=250",
            Self::Sequence => "DNP3 transport sequence is invalid",
            Self::MissingFirst => "DNP3 transport continuation has no first segment",
            Self::TooLong => "DNP3 application fragment exceeds the local limit",
        })
    }
}
impl std::error::Error for TransportError {}

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
    fn validate(&self) -> Result<(), TransportError> {
        if self.sequence > 63 {
            return Err(TransportError::Sequence);
        }
        if self.data.is_empty() || self.data.len() >= MAX_DATA {
            return Err(TransportError::Length);
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
    pub fn push(&mut self, segment: &Segment) -> Result<Option<Vec<u8>>, TransportError> {
        let result = self.push_inner(segment);
        if result.is_err() {
            *self = Self::new();
        }
        result
    }

    fn push_inner(&mut self, s: &Segment) -> Result<Option<Vec<u8>>, TransportError> {
        s.validate()?;
        if s.first {
            self.data.clear();
        } else {
            let expected = self.next.ok_or(TransportError::MissingFirst)?;
            if s.sequence != expected {
                return Err(TransportError::Sequence);
            }
        }
        if self
            .data
            .len()
            .checked_add(s.data.len())
            .is_none_or(|n| n > MAX_FRAGMENT)
        {
            return Err(TransportError::TooLong);
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

/// Why an application fragment cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragmentError {
    /// Missing application header bytes, or more than [`MAX_FRAGMENT`].
    Length,
    /// Response functions (bit 7 set) require IIN; requests must omit it.
    Indications,
}
impl std::fmt::Display for FragmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Length => "DNP3 application fragment length is outside its range",
            Self::Indications => "DNP3 internal indications do not match the function",
        })
    }
}
impl std::error::Error for FragmentError {}

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
    type ParseError = TransportError;
    type WriteError = TransportError;

    /// Reads a whole transport segment, without link framing.
    /// Returns [`TransportError::Length`] unless the input has 2 through
    /// [`MAX_DATA`] bytes.
    fn parse(b: &[u8]) -> Result<Self, TransportError> {
        if !(2..=MAX_DATA).contains(&b.len()) {
            return Err(TransportError::Length);
        }
        Ok(Self {
            first: b[0] & 0x40 != 0,
            final_segment: b[0] & 0x80 != 0,
            sequence: b[0] & 0x3f,
            data: b[1..].to_vec(),
        })
    }

    /// Writes a transport header followed by its data.
    /// Returns [`TransportError::Sequence`] above sequence 63 and
    /// [`TransportError::Length`] unless data has 1 through 249 bytes.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), TransportError> {
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
    type ParseError = FragmentError;
    type WriteError = FragmentError;

    /// Reads one complete application fragment.
    /// Returns [`FragmentError::Length`] for a short header, a response
    /// without its two IIN bytes, or input above [`MAX_FRAGMENT`].
    fn parse(b: &[u8]) -> Result<Self, FragmentError> {
        if b.len() < 2 || b.len() > MAX_FRAGMENT {
            return Err(FragmentError::Length);
        }
        let response = b[1] & 0x80 != 0;
        let header = if response { 4 } else { 2 };
        if b.len() < header {
            return Err(FragmentError::Length);
        }
        Ok(Self {
            control: b[0],
            function: b[1],
            indications: response.then(|| le16(b, 2)),
            objects: b[header..].to_vec(),
        })
    }

    /// Writes an application fragment, requiring IIN exactly for responses.
    /// Returns [`FragmentError::Indications`] if IIN presence disagrees
    /// with the response bit. Returns [`FragmentError::Length`] when the
    /// header and objects exceed [`MAX_FRAGMENT`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), FragmentError> {
        if (self.function & 0x80 != 0) != self.indications.is_some() {
            return Err(FragmentError::Indications);
        }
        let header = if self.indications.is_some() { 4 } else { 2 };
        if self.objects.len() > MAX_FRAGMENT - header {
            return Err(FragmentError::Length);
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
    use fictionet::stdlib::codec::{Fail, Stream, contract, test_support::decode_all};

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
        assert_eq!(frame.segment(), Err(TransportError::NotData));
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
        assert_eq!(frame.to_bytes(), Err(FrameError::Length));
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
                matches!(Frame::parse_prefix(&bad), Err(FrameError::Crc(_))),
                "offset {at}"
            );
        }
        assert_eq!(Frame::parse_prefix(&[4]), Err(FrameError::Start));
        assert_eq!(Frame::parse_prefix(&[5, 0x65]), Err(FrameError::Start));
        assert_eq!(Frame::parse_prefix(&[5, 0x64, 4]), Err(FrameError::Length));
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
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_FRAME);
        let (frames, failure) = decode_all(Frames::new, &bytes);
        assert!(failure.is_none());
        assert_eq!(frames, vec![frame; 10]);
        let mut stream = Stream::new(Frames);
        assert_eq!(stream.push(&vec![0; MAX_FRAME + 1]), MAX_FRAME);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(FrameError::Start))));
        assert_eq!(stream.failed(), Some(&Fail::Protocol(FrameError::Start)));
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
        assert_eq!(r.push(&s), Err(TransportError::MissingFirst));
        s.first = true;
        s.final_segment = false;
        assert_eq!(r.push(&s), Ok(None));
        assert_eq!(r.push(&s), Ok(None)); // FIR replaces unfinished data.
        assert_eq!(r.pending(), 2);
        s.first = false;
        s.sequence = 2;
        assert_eq!(r.push(&s), Err(TransportError::Sequence));
        assert_eq!(r.pending(), 0);
        s.sequence = 64;
        assert_eq!(s.to_bytes(), Err(TransportError::Sequence));
        assert_eq!(Segment::parse(&[]), Err(TransportError::Length));
        assert_eq!(Segment::parse(&[0xc0]), Err(TransportError::Length));
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
                Err(TransportError::TooLong) => break,
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
        assert_eq!(Fragment::parse(&[0xc0]), Err(FragmentError::Length));
        assert_eq!(
            Fragment::parse(&[0xc0, 0x81, 0]),
            Err(FragmentError::Length)
        );
        let mut fragment = Fragment {
            control: 0xc0,
            function: 1,
            indications: Some(0),
            objects: vec![],
        };
        assert_eq!(fragment.to_bytes(), Err(FragmentError::Indications));
        fragment.indications = None;
        fragment.objects = vec![0; MAX_FRAGMENT - 2];
        assert!(fragment.to_bytes().is_ok());
        fragment.objects.push(0);
        assert_eq!(fragment.to_bytes(), Err(FragmentError::Length));
    }
}
