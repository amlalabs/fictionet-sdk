//! IEC 60870-5-104: reading and writing APDUs and ASDU headers, with no I/O.
//!
//! IEC 104 carries telecontrol messages over TCP, usually on port 2404.
//! [`Frame`] reads the I (information), S (acknowledgment) and U (link
//! control) formats. [`Stream<Frames>`](fictionet::stdlib::codec::Stream) splits a byte
//! stream into those frames.
//! Sequence numbers are checked for their 15-bit range; tracking which
//! numbers have been sent or acknowledged belongs to world code.
//!
//! [`Asdu`] uses IEC 104's fixed field sizes: two bytes for the cause of
//! transmission (including the originator), two for the common address,
//! and three for information object addresses. Object values remain
//! opaque. [`Asdu::objects`] splits fixed-width values, including the SQ
//! form that sends only the first address. Type-specific value validation,
//! timers, connection state and secure authentication belong to the caller.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::iec104::{Asdu, Frame, Object, UFunction};
//!
//! assert_eq!(Frame::Unnumbered(UFunction::StartDtAct).to_bytes().unwrap(),
//!            [0x68, 4, 7, 0, 0, 0]);
//! // General interrogation, activation cause, station 1, QOI 20.
//! let asdu = Asdu { type_id: 100, sequence: false, count: 1, cause: 6,
//!     negative: false, test: false, originator: 0, common_address: 1,
//!     data: vec![0, 0, 0, 20] };
//! assert_eq!(asdu.objects(1).unwrap(), [Object { address: 0, value: vec![20] }]);
//! let frame = Frame::Information { send: 0, receive: 0, asdu: asdu.to_bytes().unwrap() };
//! let bytes = frame.to_bytes().unwrap();
//! assert_eq!(Frame::parse(&bytes).unwrap(), Some((frame, bytes.len())));
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The TCP port IEC 104 servers normally listen on.
pub const PORT: u16 = 2404;
/// Start byte, length byte and four control bytes.
pub const HEADER_LEN: usize = 6;
/// Maximum APDU length, including the start and length bytes.
pub const MAX_FRAME: usize = 255;
/// Maximum ASDU size inside an I-format frame.
pub const MAX_ASDU: usize = MAX_FRAME - HEADER_LEN;
/// Fixed ASDU header length.
pub const ASDU_HEADER_LEN: usize = 6;
/// Largest information object address.
pub const MAX_ADDRESS: u32 = 0x00ff_ffff;

/// Why an APDU cannot be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The frame did not start with 0x68.
    Start,
    /// Invalid APDU length, or an S/U frame carrying extra bytes.
    Length,
    /// Reserved control bits, or an unknown or combined U function.
    Control,
    /// A send or receive sequence number exceeded 32767.
    Sequence,
    /// An I frame's ASDU is shorter than its header or exceeds its limit.
    AsduLength,
}
impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Start => "IEC 104 frame does not start with 0x68",
            Self::Length => "IEC 104 APDU length is invalid",
            Self::Control => "IEC 104 control field is invalid",
            Self::Sequence => "IEC 104 sequence number exceeds 32767",
            Self::AsduLength => "IEC 104 ASDU length is outside 6..=249",
        })
    }
}
impl std::error::Error for FrameError {}

/// Why an exact [`Wire`] parse did not read one complete frame.
/// [`Frame::parse`] reads a prefix and returns the bytes used.
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
            Self::Truncated => f.write_str("incomplete IEC 104 frame"),
            Self::Trailing => f.write_str("bytes follow the IEC 104 frame"),
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

/// The six U-format control functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UFunction {
    /// Start data transfer, activation.
    StartDtAct,
    /// Start data transfer, confirmation.
    StartDtCon,
    /// Stop data transfer, activation.
    StopDtAct,
    /// Stop data transfer, confirmation.
    StopDtCon,
    /// Test frame, activation.
    TestFrAct,
    /// Test frame, confirmation.
    TestFrCon,
}
impl UFunction {
    /// The first control byte, including its low two format bits.
    pub fn code(self) -> u8 {
        match self {
            Self::StartDtAct => 0x07,
            Self::StartDtCon => 0x0b,
            Self::StopDtAct => 0x13,
            Self::StopDtCon => 0x23,
            Self::TestFrAct => 0x43,
            Self::TestFrCon => 0x83,
        }
    }

    /// Reads a complete first control byte.
    pub fn from_code(code: u8) -> Result<Self, FrameError> {
        match code {
            0x07 => Ok(Self::StartDtAct),
            0x0b => Ok(Self::StartDtCon),
            0x13 => Ok(Self::StopDtAct),
            0x23 => Ok(Self::StopDtCon),
            0x43 => Ok(Self::TestFrAct),
            0x83 => Ok(Self::TestFrCon),
            _ => Err(FrameError::Control),
        }
    }
}

/// An IEC 104 APDU. An information frame preserves its whole ASDU; use
/// [`Asdu::parse`] to read its fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// I format: an ASDU and both sequence numbers.
    Information {
        /// Send sequence number N(S), 0..=32767.
        send: u16,
        /// Receive sequence number N(R), 0..=32767.
        receive: u16,
        /// Complete ASDU, including its six-byte header.
        asdu: Vec<u8>,
    },
    /// S format: acknowledges information frames.
    Supervisory {
        /// Receive sequence number N(R), 0..=32767.
        receive: u16,
    },
    /// U format: starts, stops or tests the connection.
    Unnumbered(UFunction),
}
impl Frame {
    /// Reads one APDU at the start of `b` and returns its consumed length.
    /// `Ok(None)` means it needs more bytes. S and U frames must have
    /// exactly four control bytes and no ASDU.
    pub fn parse(b: &[u8]) -> Result<Option<(Self, usize)>, FrameError> {
        if b.first().is_some_and(|&x| x != 0x68) {
            return Err(FrameError::Start);
        }
        let Some(&length) = b.get(1) else {
            return Ok(None);
        };
        if !(4..=253).contains(&length) {
            return Err(FrameError::Length);
        }
        if b.len() < HEADER_LEN {
            return Ok(None);
        }
        let end = usize::from(length) + 2;
        let frame = if b[2] & 1 == 0 {
            if b[4] & 1 != 0 {
                return Err(FrameError::Control);
            }
            if end < HEADER_LEN + ASDU_HEADER_LEN {
                return Err(FrameError::AsduLength);
            }
            if b.len() < end {
                return Ok(None);
            }
            Self::Information {
                send: le16(b, 2) >> 1,
                receive: le16(b, 4) >> 1,
                asdu: b[HEADER_LEN..end].to_vec(),
            }
        } else {
            if length != 4 {
                return Err(FrameError::Length);
            }
            if b[2] == 1 {
                if b[3] != 0 || b[4] & 1 != 0 {
                    return Err(FrameError::Control);
                }
                Self::Supervisory {
                    receive: le16(b, 4) >> 1,
                }
            } else {
                if b[3..6] != [0, 0, 0] {
                    return Err(FrameError::Control);
                }
                Self::Unnumbered(UFunction::from_code(b[2])?)
            }
        };
        Ok(Some((frame, end)))
    }
}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = FrameError;

    /// Reads exactly one frame. Incomplete input and trailing bytes are errors.
    /// Returns [`FrameParseError::Truncated`] for an incomplete APDU and
    /// [`FrameParseError::Trailing`] for extra bytes. Invalid start bytes,
    /// lengths, control fields or ASDU lengths return [`FrameParseError::Frame`]
    /// with [`FrameError::Start`], [`FrameError::Length`],
    /// [`FrameError::Control`] or [`FrameError::AsduLength`].
    fn parse(b: &[u8]) -> Result<Self, FrameParseError> {
        match Self::parse(b).map_err(FrameParseError::Frame)? {
            Some((frame, used)) if used == b.len() => Ok(frame),
            Some(_) => Err(FrameParseError::Trailing),
            None => Err(FrameParseError::Truncated),
        }
    }

    /// Writes an APDU, refusing out-of-range sequence numbers or ASDUs.
    /// Returns [`FrameError::Sequence`] above sequence 32767 and
    /// [`FrameError::AsduLength`] unless an I-frame ASDU has 6 through 249 bytes.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), FrameError> {
        let mut out = vec![0x68, 4];
        match self {
            Self::Information {
                send,
                receive,
                asdu,
            } => {
                if *send > 0x7fff || *receive > 0x7fff {
                    return Err(FrameError::Sequence);
                }
                if !(ASDU_HEADER_LEN..=MAX_ASDU).contains(&asdu.len()) {
                    return Err(FrameError::AsduLength);
                }
                out[1] = (4 + asdu.len()) as u8;
                out.extend_from_slice(&(send << 1).to_le_bytes());
                out.extend_from_slice(&(receive << 1).to_le_bytes());
                out.extend_from_slice(asdu);
            }
            Self::Supervisory { receive } => {
                if *receive > 0x7fff {
                    return Err(FrameError::Sequence);
                }
                out.extend_from_slice(&[1, 0]);
                out.extend_from_slice(&(receive << 1).to_le_bytes());
            }
            Self::Unnumbered(function) => out.extend_from_slice(&[function.code(), 0, 0, 0]),
        }
        dst.extend_from_slice(&out);
        Ok(())
    }
}

/// Reads IEC 104 frames without holding input bytes.
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
    const NAME: &'static str = "IEC 104";

    fn capacity(&self) -> usize {
        MAX_FRAME
    }

    /// Reads an APDU prefix, returning [`Step::Need`] while incomplete.
    /// Invalid start bytes, lengths, control fields or ASDU lengths return
    /// [`FrameError::Start`], [`FrameError::Length`], [`FrameError::Control`]
    /// or [`FrameError::AsduLength`].
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Frame>, FrameError> {
        Ok(match Frame::parse(input)? {
            Some((frame, used)) => Step::Item(frame, used),
            None => Step::Need,
        })
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le24(b: &[u8]) -> u32 {
    u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16
}

/// Why an ASDU or its information objects are malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsduError {
    /// A header is truncated, or the ASDU exceeds 249 bytes.
    Length,
    /// A count exceeds 127 or a cause exceeds 63.
    Field,
    /// Object count, width and encoded data length disagree, or width is zero.
    Objects,
    /// An explicit or implied information object address exceeds 24 bits.
    Address,
}
impl std::fmt::Display for AsduError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Length => "IEC 104 ASDU length is outside 6..=249",
            Self::Field => "IEC 104 ASDU count or cause is out of range",
            Self::Objects => "IEC 104 information objects do not match their count and width",
            Self::Address => "IEC 104 information object address exceeds 24 bits",
        })
    }
}
impl std::error::Error for AsduError {}

/// An ASDU header followed by opaque information object bytes. Unknown
/// type IDs and causes are preserved. Object layout is checked separately
/// by [`Asdu::objects`], because it depends on the type ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asdu {
    /// Type identification, such as 1 (single point) or 100 (interrogation).
    pub type_id: u8,
    /// SQ: only the first object's address is explicit; the rest increase by one.
    pub sequence: bool,
    /// Seven-bit number of information objects.
    pub count: u8,
    /// Six-bit cause of transmission.
    pub cause: u8,
    /// P/N: negative confirmation.
    pub negative: bool,
    /// T: test message.
    pub test: bool,
    /// Originator address, the second cause-of-transmission byte.
    pub originator: u8,
    /// Common address of the ASDU, usually the station address.
    pub common_address: u16,
    /// Encoded information object addresses and values.
    pub data: Vec<u8>,
}

/// One information object with its address made explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// A 24-bit information object address.
    pub address: u32,
    /// Type-specific bytes, including quality and timestamps when present.
    pub value: Vec<u8>,
}

impl Asdu {
    fn validate(&self) -> Result<(), AsduError> {
        if self.count > 127 || self.cause > 63 {
            return Err(AsduError::Field);
        }
        if self.data.len() > MAX_ASDU - ASDU_HEADER_LEN {
            return Err(AsduError::Length);
        }
        Ok(())
    }

    /// Reads fixed-width information objects. `width` is the number of
    /// bytes per value, excluding its address, and must be positive. Both
    /// SQ layouts require exactly the declared number of objects and no
    /// trailing data. Sequential addresses must not overflow 24 bits.
    pub fn objects(&self, width: usize) -> Result<Vec<Object>, AsduError> {
        self.validate()?;
        if width == 0 || width > MAX_ASDU {
            return Err(AsduError::Objects);
        }
        let count = usize::from(self.count);
        let expected = if self.sequence {
            count * width + if count == 0 { 0 } else { 3 }
        } else {
            count * (width + 3)
        };
        if self.data.len() != expected {
            return Err(AsduError::Objects);
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        let first = le24(&self.data);
        if self.sequence && first + count as u32 - 1 > MAX_ADDRESS {
            return Err(AsduError::Address);
        }
        let mut out = Vec::with_capacity(count);
        let mut at = if self.sequence { 3 } else { 0 };
        for i in 0..count {
            let address = if self.sequence {
                first + i as u32
            } else {
                let address = le24(&self.data[at..]);
                at += 3;
                address
            };
            out.push(Object {
                address,
                value: self.data[at..at + width].to_vec(),
            });
            at += width;
        }
        Ok(out)
    }

    /// Replaces the data and count with equal-width objects in the chosen
    /// SQ layout. Sequential addresses must be consecutive. On error, the
    /// ASDU is unchanged. Value bytes are not interpreted.
    pub fn set_objects(&mut self, objects: &[Object], sequence: bool) -> Result<(), AsduError> {
        if objects.len() > 127 {
            return Err(AsduError::Field);
        }
        let mut data = Vec::new();
        let width = objects.first().map_or(0, |o| o.value.len());
        for (i, object) in objects.iter().enumerate() {
            if object.address > MAX_ADDRESS {
                return Err(AsduError::Address);
            }
            if width == 0 || object.value.len() != width {
                return Err(AsduError::Objects);
            }
            if sequence && object.address != objects[0].address + i as u32 {
                return Err(AsduError::Address);
            }
            let address_len = if !sequence || i == 0 { 3 } else { 0 };
            if width
                .checked_add(address_len + data.len())
                .is_none_or(|n| n > MAX_ASDU - ASDU_HEADER_LEN)
            {
                return Err(AsduError::Length);
            }
            if address_len != 0 {
                data.extend_from_slice(&object.address.to_le_bytes()[..3]);
            }
            data.extend_from_slice(&object.value);
        }
        self.sequence = sequence;
        self.count = objects.len() as u8;
        self.data = data;
        Ok(())
    }
}

impl Wire for Asdu {
    type ParseError = AsduError;
    type WriteError = AsduError;

    /// Reads one complete ASDU with IEC 104's fixed field sizes.
    /// Returns [`AsduError::Length`] unless input has 6 through 249 bytes.
    /// Object layout is checked separately by [`Asdu::objects`].
    fn parse(b: &[u8]) -> Result<Self, AsduError> {
        if !(ASDU_HEADER_LEN..=MAX_ASDU).contains(&b.len()) {
            return Err(AsduError::Length);
        }
        Ok(Self {
            type_id: b[0],
            sequence: b[1] & 0x80 != 0,
            count: b[1] & 0x7f,
            cause: b[2] & 0x3f,
            negative: b[2] & 0x40 != 0,
            test: b[2] & 0x80 != 0,
            originator: b[3],
            common_address: le16(b, 4),
            data: b[6..].to_vec(),
        })
    }

    /// Writes the ASDU header and opaque data. Use [`Asdu::set_objects`]
    /// to construct data whose object count and addresses are consistent.
    /// Returns [`AsduError::Field`] above count 127 or cause 63, and
    /// [`AsduError::Length`] if the header and data exceed [`MAX_ASDU`].
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), AsduError> {
        self.validate()?;
        let mut out = vec![
            self.type_id,
            self.count | if self.sequence { 0x80 } else { 0 },
            self.cause | if self.negative { 0x40 } else { 0 } | if self.test { 0x80 } else { 0 },
            self.originator,
        ];
        out.extend_from_slice(&self.common_address.to_le_bytes());
        out.extend_from_slice(&self.data);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Stream, contract, test_support::decode_all};

    const INTERROGATION: &[u8] = &[0x68, 14, 0, 0, 0, 0, 100, 1, 6, 0, 1, 0, 0, 0, 0, 20];

    fn interrogation() -> Asdu {
        Asdu::parse(&INTERROGATION[6..]).unwrap()
    }

    #[test]
    fn known_wire_messages_and_all_prefixes() {
        for bytes in [
            INTERROGATION,
            &[0x68, 4, 1, 0, 0xfe, 0xff],
            &[0x68, 4, 7, 0, 0, 0],
        ] {
            for cut in 0..bytes.len() {
                assert_eq!(Frame::parse(&bytes[..cut]), Ok(None));
            }
            let (frame, used) = Frame::parse(bytes).unwrap().unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(frame.to_bytes().unwrap(), bytes);
        }
        let asdu = interrogation();
        assert_eq!(asdu.type_id, 100);
        assert_eq!(asdu.cause, 6);
        assert_eq!(asdu.common_address, 1);
        assert_eq!(
            asdu.objects(1),
            Ok(vec![Object {
                address: 0,
                value: vec![20]
            }])
        );
        for code in [7, 11, 19, 35, 67, 131] {
            let function = UFunction::from_code(code).unwrap();
            assert_eq!(function.code(), code);
            let bytes = [0x68, 4, code, 0, 0, 0];
            assert_eq!(
                Frame::parse(&bytes),
                Ok(Some((Frame::Unnumbered(function), 6)))
            );
        }
    }

    #[test]
    fn rejects_invalid_lengths_and_reserved_control_bits() {
        for bytes in [
            &[0][..],
            &[0x68, 0],
            &[0x68, 3],
            &[0x68, 254],
            &[0x68, 255],
            &[0x68, 4, 0, 0, 0, 0],
            &[0x68, 4, 1, 1, 0, 0],
            &[0x68, 4, 1, 0, 1, 0],
            &[0x68, 4, 3, 0, 0, 0],
            &[0x68, 4, 15, 0, 0, 0],
            &[0x68, 4, 7, 0, 1, 0],
            &[0x68, 5, 1, 0, 0, 0, 0],
            &[0x68, 5, 7, 0, 0, 0, 0],
        ] {
            assert!(Frame::parse(bytes).is_err(), "{bytes:?}");
        }
        let mut bytes = INTERROGATION.to_vec();
        bytes[4] = 1;
        assert_eq!(Frame::parse(&bytes), Err(FrameError::Control));
        assert_eq!(
            Frame::Supervisory { receive: 32768 }.to_bytes(),
            Err(FrameError::Sequence)
        );
        assert_eq!(
            Frame::Information {
                send: 32768,
                receive: 0,
                asdu: vec![0; 6]
            }
            .to_bytes(),
            Err(FrameError::Sequence)
        );
        for n in [0, 5, MAX_ASDU + 1] {
            assert_eq!(
                Frame::Information {
                    send: 0,
                    receive: 0,
                    asdu: vec![0; n]
                }
                .to_bytes(),
                Err(FrameError::AsduLength)
            );
        }
    }

    #[test]
    fn stream_limits_and_terminal_failure() {
        let frame = Frame::Information {
            send: 32767,
            receive: 32767,
            asdu: vec![0xff; MAX_ASDU],
        };
        let encoded = frame.to_bytes().unwrap();
        assert_eq!(encoded.len(), MAX_FRAME);
        let bytes = encoded.repeat(7);
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_FRAME);
        let (frames, failure) = decode_all(Frames::new, &bytes);
        assert!(failure.is_none());
        assert_eq!(frames, vec![frame; 7]);
        let mut stream = Stream::new(Frames);
        assert_eq!(stream.push(&vec![0; MAX_FRAME + 1]), MAX_FRAME);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(FrameError::Start))));
        assert_eq!(stream.failed(), Some(&Fail::Protocol(FrameError::Start)));
        assert!(stream.next().is_none());
        assert_eq!(stream.push(&[0]), 1);
    }

    #[test]
    fn asdu_headers_preserve_unknown_types_flags_and_empty_payloads() {
        let bytes = [255, 0x80, 0xff, 0xaa, 0xfe, 0xca];
        let asdu = Asdu::parse(&bytes).unwrap();
        assert_eq!(asdu.to_bytes().unwrap(), bytes);
        assert!(asdu.sequence && asdu.negative && asdu.test);
        assert_eq!(asdu.cause, 63);
        assert_eq!(asdu.common_address, 0xcafe);
        assert_eq!(asdu.objects(1), Ok(vec![]));
        for n in [0, 5, MAX_ASDU + 1] {
            assert_eq!(Asdu::parse(&vec![0; n]), Err(AsduError::Length));
        }
        let mut asdu = asdu;
        asdu.cause = 64;
        assert_eq!(asdu.to_bytes(), Err(AsduError::Field));
        asdu.cause = 1;
        asdu.count = 128;
        assert_eq!(asdu.to_bytes(), Err(AsduError::Field));
    }

    #[test]
    fn objects_in_both_address_layouts() {
        let objects = vec![
            Object {
                address: 0x123456,
                value: vec![1, 2],
            },
            Object {
                address: 0x123457,
                value: vec![3, 4],
            },
        ];
        let mut asdu = interrogation();
        for sequence in [false, true] {
            asdu.set_objects(&objects, sequence).unwrap();
            assert_eq!(asdu.count, 2);
            assert_eq!(asdu.data.len(), if sequence { 7 } else { 10 });
            assert_eq!(&asdu.data[..3], &[0x56, 0x34, 0x12]);
            let back = Asdu::parse(&asdu.to_bytes().unwrap()).unwrap();
            assert_eq!(back.objects(2), Ok(objects.clone()));
            for width in [0, 1, 3, usize::MAX] {
                assert_eq!(back.objects(width), Err(AsduError::Objects));
            }
        }
        asdu.set_objects(&[], true).unwrap();
        assert_eq!(asdu.objects(1), Ok(vec![]));
    }

    #[test]
    fn object_overflow_lengths_and_failed_writes_are_atomic() {
        let mut asdu = interrogation();
        let original = asdu.clone();
        let bad_lists = [
            vec![Object {
                address: MAX_ADDRESS + 1,
                value: vec![1],
            }],
            vec![Object {
                address: 0,
                value: vec![],
            }],
            vec![
                Object {
                    address: 0,
                    value: vec![0; 240],
                },
                Object {
                    address: 1,
                    value: vec![0; 240],
                },
            ],
            vec![
                Object {
                    address: 1,
                    value: vec![0],
                },
                Object {
                    address: 3,
                    value: vec![0],
                },
            ],
            vec![
                Object {
                    address: 0,
                    value: vec![0]
                };
                128
            ],
        ];
        for objects in bad_lists {
            assert!(asdu.set_objects(&objects, true).is_err());
            assert_eq!(asdu, original);
        }
        // Regression: a full first object's data must not underflow remaining space.
        let objects = [
            Object {
                address: 0,
                value: vec![0; 240],
            },
            Object {
                address: 1,
                value: vec![0; 240],
            },
        ];
        assert_eq!(asdu.set_objects(&objects, false), Err(AsduError::Length));
        asdu.sequence = true;
        asdu.count = 2;
        asdu.data = vec![255, 255, 255, 0, 0];
        assert_eq!(asdu.objects(1), Err(AsduError::Address));
        asdu.data = vec![0, 0, 0, 0];
        assert_eq!(asdu.objects(1), Err(AsduError::Objects));
    }
}
