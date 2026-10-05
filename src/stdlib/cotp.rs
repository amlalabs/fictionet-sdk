//! TPKT and COTP: reading and writing ISO transport packets on TCP, with no
//! I/O.
//!
//! ISO transport (COTP, the connection-oriented transport protocol) runs
//! under Siemens S7 PLCs, IEC 61850 substations, ICCP links between control
//! centers, and the start of every RDP session. On TCP, usually port 102
//! (3389 for RDP), each transport message (a TPDU) travels in a TPKT: a
//! 4-byte header with a version and a length. This module follows RFC 1006
//! for TPKT and ITU-T X.224 (ISO 8073) for the TPDUs of class 0, the class
//! RFC 1006 uses: connection request and confirm, data, disconnect request,
//! and error.
//!
//! Nothing here reads a socket. A world that plays a server feeds bytes
//! from a TCP connection to [`tpdus`] through [`super::codec::Stream`] and
//! gets each packet's TPDU back. Data TPDUs carry a message in segments;
//! [`messages`] puts them back together, and [`segment`] cuts a message
//! into them. Which TSAPs exist, what TPDU size to accept, and what the
//! data means are up to world code.
//!
//! New stream readers use [`tpdus`] for individual TPDUs or [`messages`]
//! for EOT reassembly. Both compose the shared [`tpkt::Packets`] decoder.
//! [`Tpdu`] implements [`Wire`] with a [`MAX_TPDU`] input limit and a
//! strict, transactional writer. [`Tpdu::to_bytes_clipped`] names the lossy
//! writer explicitly. The inherent `parse` and `to_bytes` retain their
//! original behavior. [`over_tpkt`] provides TPKT conversions and a message
//! writer that writes strictly through [`Wire`] at both layers. The strict
//! TPDU writer stages and reparses one bounded TPDU before appending it.
//!
//! ```
//! use fictionet::stdlib::{codec::{Assembled, Stream, finish, pump}, cotp, tpkt};
//!
//! let bytes = cotp::over_tpkt::write_message(b"hello", 128).unwrap();
//! let mut stream = Stream::new(cotp::messages(tpkt::MAX_PACKET, cotp::MAX_MESSAGE));
//! let mut items = Vec::new();
//! for byte in bytes.chunks(1) {
//!     pump(&mut stream, byte, |item| items.push(item)).unwrap();
//! }
//! finish(&mut stream, |item| items.push(item)).unwrap();
//! assert_eq!(items, vec![Assembled::Message(b"hello".to_vec())]);
//! ```
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A TPDU this module cannot read gives a [`TpduError`] that
//! [`ErrorTpdu::rejecting`] turns into the error TPDU a real stack sends.
//!
//! ```
//! use fictionet::stdlib::codec::Stream;
//! use fictionet::stdlib::cotp::{Reassembler, Tpdu, tpdus};
//! use fictionet::stdlib::tpkt::MAX_PACKET;
//!
//! let mut decoder = Stream::new(tpdus(MAX_PACKET));
//! // A connection request: source reference 1, class 0, TPDU size 1024
//! // (code 10), calling TSAP 01 00 and called TSAP 01 02.
//! let bytes = [3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc0, 1, 10, 0xc1, 2, 1, 0, 0xc2, 2, 1, 2];
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! let tpdu = decoder.next().unwrap().unwrap();
//! let Ok(Tpdu::ConnectionRequest(request)) = tpdu else { panic!() };
//! assert_eq!(request.called_tsap(), Some(&[1, 2][..]));
//! assert_eq!(request.tpdu_size(), Some(1024));
//!
//! // Accept it with source reference 0x4242, echoing its parameters.
//! let confirm = Tpdu::ConnectionConfirm(request.confirm(0x4242).unwrap());
//! assert_eq!(
//!     confirm.to_packet(),
//!     [3, 0, 0, 22, 17, 0xd0, 0, 1, 0x42, 0x42, 0, 0xc0, 1, 10, 0xc1, 2, 1, 0, 0xc2, 2, 1, 2]
//! );
//!
//! // Then a message, "hi", in one data TPDU marked as the last.
//! let bytes = [3, 0, 0, 9, 2, 0xf0, 0x80, b'h', b'i'];
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! let tpdu = decoder.next().unwrap().unwrap();
//! let Ok(Tpdu::Data(data)) = tpdu else { panic!() };
//! let mut messages = Reassembler::new();
//! assert_eq!(messages.push(&data), Ok(Some(b"hi".to_vec())));
//! ```

use super::{
    codec::{Assemble, Decode, Fragment, Map, Step, Wire},
    tpkt,
};

/// The TCP port ISO transport servers listen on.
pub const PORT: u16 = tpkt::PORT;
/// The only TPKT version, the first byte of every packet.
#[deprecated(note = "use tpkt::VERSION")]
pub const TPKT_VERSION: u8 = tpkt::VERSION;
/// The length of the TPKT header, before the TPDU.
#[deprecated(note = "use tpkt::HEADER_LEN")]
pub const TPKT_HEADER_LEN: usize = tpkt::HEADER_LEN;
/// The shortest TPDU: a data TPDU's 3-byte header with no data.
pub const MIN_TPDU: usize = tpkt::MIN_PAYLOAD;
/// The shortest packet: the header and the shortest TPDU.
#[deprecated(note = "use tpkt::MIN_PACKET")]
pub const MIN_PACKET: usize = tpkt::MIN_PACKET;
/// The longest packet the 16-bit length field allows.
#[deprecated(note = "use tpkt::MAX_PACKET")]
pub const MAX_PACKET: usize = tpkt::MAX_PACKET;
/// The longest TPDU one packet can carry.
pub const MAX_TPDU: usize = tpkt::MAX_PAYLOAD;
/// The largest length indicator: the most header bytes after the first.
/// The value 255 is reserved.
pub const MAX_HEADER: usize = 254;
/// The longest parameter value: its length is one byte.
pub const MAX_PARAMETER: usize = 255;
/// The TPDU size on TCP when a connection request names none. RFC 1006
/// raises it to the largest TPDU a packet carries.
pub const DEFAULT_TPDU_SIZE: usize = MAX_TPDU;
/// The TPDU size ISO 8073 class 0 uses on other networks when a connection
/// request names none.
pub const ISO_DEFAULT_TPDU_SIZE: usize = 128;
/// The largest TPDU size parameter class 0 allows. X.224 does not allow
/// 4096 or 8192 in class 0.
pub const MAX_CLASS0_TPDU_SIZE: usize = 2048;
/// The longest message a [`Reassembler`] will put back together.
pub const MAX_MESSAGE: usize = 1 << 20;

/// TPDU codes: the high four bits of a TPDU's second byte.
pub mod code {
    /// Connection request (CR). The low four bits are the credit.
    pub const CONNECTION_REQUEST: u8 = 0xe0;
    /// Connection confirm (CC). The low four bits are the credit.
    pub const CONNECTION_CONFIRM: u8 = 0xd0;
    /// Disconnect request (DR).
    pub const DISCONNECT_REQUEST: u8 = 0x80;
    /// Data (DT).
    pub const DATA: u8 = 0xf0;
    /// Error (ER), also called TPDU error.
    pub const ERROR: u8 = 0x70;
    /// Set in a data TPDU's third byte on the last segment of a message.
    pub const EOT: u8 = 0x80;
}

/// Parameter codes in the variable part of a TPDU's header.
pub mod parameter {
    /// In CR and CC: the TPDU size, as a power of two from 7 to 13.
    pub const TPDU_SIZE: u8 = 0xc0;
    /// In CR and CC: the calling transport selector (TSAP).
    pub const CALLING_TSAP: u8 = 0xc1;
    /// In CR and CC: the called transport selector (TSAP).
    pub const CALLED_TSAP: u8 = 0xc2;
    /// In CR: the classes the caller accepts besides its preferred one,
    /// one byte each, with the class in the high four bits. A class 0
    /// request does not carry it.
    pub const ALTERNATIVE_CLASSES: u8 = 0xc7;
    /// In ER: the header of the TPDU that was rejected.
    pub const INVALID_TPDU: u8 = 0xc1;
    /// In DR: free text on why the connection is closing.
    pub const ADDITIONAL_INFORMATION: u8 = 0xe0;
}

/// Reasons a disconnect request gives. X.224 13.5.3 allows only the
/// first four, 0 to 3, in class 0; the others, from 128 up, belong to
/// classes 1 to 4. A world that plays a strict class 0 stack refuses
/// with one of the first four.
pub mod reason {
    /// No reason given.
    pub const NOT_SPECIFIED: u8 = 0;
    /// The TSAP is congested.
    pub const CONGESTION_AT_TSAP: u8 = 1;
    /// No session entity is attached to the TSAP.
    pub const SESSION_ENTITY_NOT_ATTACHED: u8 = 2;
    /// The address is unknown.
    pub const ADDRESS_UNKNOWN: u8 = 3;
    /// A normal disconnect, asked for by the session entity.
    pub const NORMAL: u8 = 128;
    /// The remote transport entity was congested at connect time.
    pub const REMOTE_CONGESTION: u8 = 129;
    /// The connection's options could not be agreed.
    pub const NEGOTIATION_FAILED: u8 = 130;
    /// The source reference is already in use.
    pub const DUPLICATE_SOURCE_REFERENCE: u8 = 131;
    /// The references do not match a connection.
    pub const MISMATCHED_REFERENCES: u8 = 132;
    /// The peer broke the protocol.
    pub const PROTOCOL_ERROR: u8 = 133;
    /// No references are left.
    pub const REFERENCE_OVERFLOW: u8 = 135;
    /// The connection request was refused.
    pub const REFUSED: u8 = 136;
    /// A header or parameter length is invalid.
    pub const HEADER_LENGTH_INVALID: u8 = 138;
}

/// Reject causes an error TPDU gives.
pub mod cause {
    /// No cause given.
    pub const NOT_SPECIFIED: u8 = 0;
    /// A parameter code is not allowed.
    pub const INVALID_PARAMETER_CODE: u8 = 1;
    /// The TPDU's code is not one the receiver reads.
    pub const INVALID_TPDU_TYPE: u8 = 2;
    /// A parameter's value is not allowed.
    pub const INVALID_PARAMETER_VALUE: u8 = 3;
}

/// Why bytes are not a TPKT stream. Either way, the connection holds no
/// more packets a reader can find, and a real server closes it.
/// This legacy error is used by [`Decoder`] and [`parse_packet`];
/// [`tpdus`] and [`messages`] use [`tpkt::TpktError`] for framing errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[deprecated(note = "use tpkt::TpktError with tpkt::Packets")]
pub enum TpktError {
    /// The first byte was not 3. RDP's fast-path packets look like this.
    Version(u8),
    /// The length field was below [`MIN_PACKET`].
    Length(u16),
}

#[allow(deprecated)]
impl core::fmt::Display for TpktError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TpktError::Version(v) => write!(f, "TPKT version {v}, not 3"),
            TpktError::Length(n) => write!(f, "TPKT length {n}, below {MIN_PACKET}"),
        }
    }
}

#[allow(deprecated)]
impl core::error::Error for TpktError {}

/// Converts errors from the shared framer for the unlimited legacy reader.
#[allow(deprecated)]
fn legacy_error(error: tpkt::TpktError) -> TpktError {
    match error {
        tpkt::TpktError::Version(v) => TpktError::Version(v),
        tpkt::TpktError::Length(n) => TpktError::Length(n),
        // A 16-bit length cannot exceed MAX_PACKET. Legacy readers always
        // use that limit, so this arm cannot be reached by input bytes;
        // Length's "below MIN_PACKET" diagnostic would not apply here.
        tpkt::TpktError::TooLong { length, .. } => TpktError::Length(length),
    }
}

/// Reads the packet at the start of `b`. It returns `Ok(None)` if `b`
/// holds only part of one, and otherwise the TPDU it carries and how many
/// bytes of `b` the packet took. The reserved second byte is not checked.
#[deprecated(note = "use tpkt::Packet::parse and its payload")]
#[allow(deprecated)]
pub fn parse_packet(b: &[u8]) -> Result<Option<(&[u8], usize)>, TpktError> {
    let Some(header) = tpkt::Header::parse(b, tpkt::MAX_PACKET).map_err(legacy_error)? else {
        return Ok(None);
    };
    let end = usize::from(header.length);
    Ok(b.get(tpkt::HEADER_LEN..end).map(|payload| (payload, end)))
}

/// The packet that carries `tpdu`. A TPDU longer than [`MAX_TPDU`] is cut
/// to that length, and one shorter than [`MIN_TPDU`] is padded with zeros,
/// so the packet always reads back.
#[deprecated(note = "use tpkt::Packet::new(payload).to_bytes() for strict writing")]
pub fn write_packet(tpdu: &[u8]) -> Vec<u8> {
    let mut payload = tpdu
        .get(..tpdu.len().min(MAX_TPDU))
        .unwrap_or_default()
        .to_vec();
    payload.resize(payload.len().max(MIN_TPDU), 0);
    // Padding and clipping above put the payload within the writer's limits.
    let bytes = tpkt::Packet::new(payload).to_bytes();
    debug_assert!(bytes.is_ok(), "padded and clipped payload fits a TPKT packet");
    bytes.unwrap_or_default()
}

/// The most spare room a [`Decoder`] keeps once its bytes are taken out.
const DECODER_RETAINED: usize = 2 * tpkt::MAX_PACKET;

/// Splits a TPKT byte stream into TPDUs. Feed it the bytes a connection
/// reads, in order, and take TPDUs out until it has none.
///
/// This compatibility wrapper uses [`tpkt::Packets`]. Its void `feed` keeps
/// the legacy behavior of holding every byte until packets are taken out.
/// Use [`tpdus`] or [`messages`] with [`super::codec::Stream`] for bounded
/// input and explicit EOF handling.
#[derive(Clone, Debug, Default)]
#[deprecated(note = "use codec::Stream with cotp::tpdus or cotp::messages for bounded input")]
#[allow(deprecated)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small packets costs time in proportion to their bytes.
    start: usize,
    frames: tpkt::Packets,
    failed: Option<TpktError>,
}

#[allow(deprecated)]
impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the connection. After a [`TpktError`] the
    /// stream cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
                self.buf.shrink_to(DECODER_RETAINED.max(self.buf.len()));
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The TPDU in the next whole packet, if one has come. It returns
    /// `None` when it needs more bytes, and keeps returning the same error
    /// once the stream has broken. A world that takes packets out after
    /// each `feed` never holds more than one packet's bytes
    /// ([`MAX_PACKET`]) beyond what has been taken out, plus what that
    /// `feed` added. Once every packet fed has been taken out, the decoder
    /// keeps at most two packets' worth of spare room, however much one
    /// `feed` added. The decoder buffers what it is fed and nothing more,
    /// so a world that feeds without taking packets out holds all of it.
    pub fn next_packet(&mut self) -> Option<Result<Vec<u8>, TpktError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match self
            .frames
            .decode(self.buf.get(self.start..).unwrap_or_default(), false)
        {
            Ok(Step::Item(packet, used)) => {
                self.start = self.start.saturating_add(used);
                if self.start == self.buf.len() {
                    // Everything fed has been taken out. Keep room for a
                    // couple of packets, not for the largest burst fed.
                    self.buf.clear();
                    self.buf.shrink_to(DECODER_RETAINED);
                    self.start = 0;
                }
                Some(Ok(packet.payload))
            }
            Ok(_) => None,
            Err(e) => {
                let e = legacy_error(e);
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Some(Err(e))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a packet.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }
}

/// One parameter in a TPDU header's variable part: a code and a value of
/// up to [`MAX_PARAMETER`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    /// What the parameter is, such as [`parameter::CALLED_TSAP`].
    pub code: u8,
    /// Its value.
    pub value: Vec<u8>,
}

/// The variable part of a TPDU's header: the bytes after the fixed part,
/// up to the end the length indicator gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Variable {
    /// The bytes split cleanly into parameters, kept in order.
    Parameters(Vec<Parameter>),
    /// The bytes do not split into parameters, and are kept as they came.
    /// RDP's connection request does this: its cookie and negotiation
    /// request sit in the header, where the parameters would be.
    Raw(Vec<u8>),
}

impl Default for Variable {
    fn default() -> Variable {
        Variable::Parameters(Vec::new())
    }
}

impl Variable {
    /// Reads a variable part. It is [`Variable::Parameters`] when every
    /// parameter's length stays inside `b`, and [`Variable::Raw`]
    /// otherwise. Bytes longer than [`MAX_HEADER`] cannot be a header's
    /// variable part, and are always [`Variable::Raw`], so the list of
    /// parameters stays small whatever the input.
    pub fn parse(b: &[u8]) -> Variable {
        if b.len() > MAX_HEADER {
            return Variable::Raw(b.to_vec());
        }
        let mut params = Vec::new();
        let mut rest = b;
        while let [code, len, tail @ ..] = rest {
            let Some(value) = tail.get(..usize::from(*len)) else { return Variable::Raw(b.to_vec()) };
            params.push(Parameter { code: *code, value: value.to_vec() });
            rest = tail.get(usize::from(*len)..).unwrap_or_default();
        }
        if rest.is_empty() { Variable::Parameters(params) } else { Variable::Raw(b.to_vec()) }
    }

    /// The value of the last parameter with `code`, if this is a list of
    /// parameters that has one. X.224 13.2.3 says that when a parameter
    /// comes more than once, the later value is used.
    pub fn get(&self, code: u8) -> Option<&[u8]> {
        match self {
            Variable::Parameters(params) => params.iter().rev().find(|p| p.code == code).map(|p| p.value.as_slice()),
            Variable::Raw(_) => None,
        }
    }

    /// Appends the variable part's bytes to `out`, writing at most `room`
    /// of them. A parameter that does not fit is left out, and raw bytes
    /// are cut.
    fn write(&self, out: &mut Vec<u8>, room: usize) {
        match self {
            Variable::Parameters(params) => {
                let mut left = room;
                for p in params {
                    let need = 2 + p.value.len();
                    if p.value.len() > MAX_PARAMETER || need > left {
                        continue;
                    }
                    out.push(p.code);
                    out.push(p.value.len() as u8);
                    out.extend_from_slice(&p.value);
                    left -= need;
                }
            }
            Variable::Raw(bytes) => {
                out.extend_from_slice(bytes.get(..bytes.len().min(room)).unwrap_or_default());
            }
        }
    }

    /// Sets the parameter with `code` to `value`. The first parameter with
    /// that code keeps its place and takes the new value, and any later
    /// ones are removed, so [`Variable::get`] returns `value`. With none, it is added at the end. Raw bytes are
    /// replaced by a list holding just this parameter. A value longer than
    /// [`MAX_PARAMETER`] is left out when the TPDU is written.
    pub fn set(&mut self, code: u8, value: Vec<u8>) {
        if let Variable::Raw(_) = self {
            *self = Variable::Parameters(Vec::new());
        }
        if let Variable::Parameters(params) = self {
            match params.iter().position(|p| p.code == code) {
                Some(i) => {
                    params[i].value = value;
                    let mut seen = 0;
                    params.retain(|p| {
                        if p.code != code {
                            return true;
                        }
                        seen += 1;
                        seen == 1
                    });
                }
                None => params.push(Parameter { code, value }),
            }
        }
    }
}

/// A connection request (CR) or connection confirm (CC).
///
/// X.224 13.3 limits a CR to 128 bytes. Neither the reader nor the writers
/// hold to that, since RDP clients send longer requests (a cookie or
/// routing token in the header); a world that plays a strict stack checks
/// the length itself.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Connect {
    /// The initial credit, four bits. Class 0 always uses 0.
    pub credit: u8,
    /// The destination reference: 0 in a request, and the request's
    /// source reference in a confirm.
    pub dst_ref: u16,
    /// The sender's reference for this connection.
    pub src_ref: u16,
    /// The protocol class, four bits: 0 to 4.
    pub class: u8,
    /// The option bits, four bits: 2 for extended formats and 1 for
    /// explicit flow control. Class 0 uses neither.
    pub options: u8,
    /// The parameters, such as the TSAPs and the TPDU size.
    pub variable: Variable,
    /// User data after the header. ISO 8073 class 0 does not allow it,
    /// but RFC 1006 lets a connection request and confirm carry it.
    pub data: Vec<u8>,
}

/// The fixed part of a CR or CC after the length indicator: the code,
/// two references and the class byte.
const CONNECT_FIXED: usize = 6;
/// The fixed part of a DR after the length indicator.
const DISCONNECT_FIXED: usize = 6;
/// The fixed part of an ER after the length indicator.
const ERROR_FIXED: usize = 4;
/// The fixed part of a class 0 DT after the length indicator.
const DATA_FIXED: usize = 2;

impl Connect {
    /// A class 0 connection request from `src_ref` with no parameters.
    pub fn request(src_ref: u16) -> Connect {
        Connect { src_ref, ..Connect::default() }
    }

    /// The TPDU size, in bytes, if the TPDU size parameter is there and
    /// holds a code from 7 (128 bytes) to 13 (8192 bytes).
    pub fn tpdu_size(&self) -> Option<usize> {
        match self.variable.get(parameter::TPDU_SIZE)? {
            [n @ 7..=13] => Some(1usize << n),
            _ => None,
        }
    }

    /// The calling TSAP, if the parameter is there.
    pub fn calling_tsap(&self) -> Option<&[u8]> {
        self.variable.get(parameter::CALLING_TSAP)
    }

    /// The called TSAP, if the parameter is there.
    pub fn called_tsap(&self) -> Option<&[u8]> {
        self.variable.get(parameter::CALLED_TSAP)
    }

    /// Sets the TPDU size parameter to the largest power of two from 128 to
    /// 8192 that is no more than `bytes`, or 128 if `bytes` is smaller.
    /// In class 0 the most is [`MAX_CLASS0_TPDU_SIZE`], 2048, since X.224
    /// does not allow 4096 or 8192 there; set [`Connect::class`] first to
    /// ask for more in another class. A size already there is replaced.
    pub fn with_tpdu_size(mut self, bytes: usize) -> Connect {
        let max = if self.class == 0 { MAX_CLASS0_TPDU_SIZE.trailing_zeros() as u8 } else { 13 };
        let n = (7..=max).rev().find(|n| 1usize << n <= bytes).unwrap_or(7);
        self.variable.set(parameter::TPDU_SIZE, vec![n]);
        self
    }

    /// Sets the calling TSAP parameter, replacing one already there. A
    /// value longer than [`MAX_PARAMETER`] is cut to that length.
    pub fn with_calling_tsap(mut self, tsap: &[u8]) -> Connect {
        self.variable.set(parameter::CALLING_TSAP, tsap[..tsap.len().min(MAX_PARAMETER)].to_vec());
        self
    }

    /// Sets the called TSAP parameter, replacing one already there. A value
    /// longer than [`MAX_PARAMETER`] is cut to that length.
    pub fn with_called_tsap(mut self, tsap: &[u8]) -> Connect {
        self.variable.set(parameter::CALLED_TSAP, tsap[..tsap.len().min(MAX_PARAMETER)].to_vec());
        self
    }

    /// Whether a responder may answer this request in class 0, by X.224
    /// table 3: the request offers class 0 or 1, as its preferred class or
    /// as an alternative, and pairs its classes as the table allows. A
    /// request whose preferred class is 2, with no alternative class 0,
    /// may not be answered in class 0.
    pub fn allows_class0(&self) -> bool {
        let alternatives: Vec<u8> =
            self.variable.get(parameter::ALTERNATIVE_CLASSES).unwrap_or(&[]).iter().map(|a| a >> 4).collect();
        let pairs = |a: &u8| match self.class {
            1 => *a <= 1,
            2 => *a == 0 || *a == 2,
            3 => *a <= 3,
            4 => *a <= 4,
            _ => false,
        };
        self.class <= 4
            && alternatives.iter().all(pairs)
            && (self.class <= 1 || alternatives.iter().any(|a| *a <= 1))
    }

    /// A class 0 confirm that accepts this request, from `src_ref`, or
    /// `None` when the request does not allow class 0 (see
    /// [`Connect::allows_class0`]); a world refuses such a request. The
    /// confirm echoes the request's TSAP parameters and TPDU size, in
    /// their order, each once with the value that counts: the last one,
    /// when a parameter comes more than once. A TPDU size above
    /// [`MAX_CLASS0_TPDU_SIZE`] is lowered to it, and a size value that is
    /// not a code from 7 to 13 is left out. A world that wants a smaller
    /// TPDU size or other TSAPs changes them.
    pub fn confirm(&self, src_ref: u16) -> Option<Connect> {
        if !self.allows_class0() {
            return None;
        }
        // 2048 is 2 to the 11th, so this is 11.
        let max_code = MAX_CLASS0_TPDU_SIZE.trailing_zeros() as u8;
        let echo = |p: &Parameter| match (p.code, p.value.as_slice()) {
            (parameter::TPDU_SIZE, [n @ 7..=13]) => Some(Parameter { code: p.code, value: vec![(*n).min(max_code)] }),
            (parameter::CALLING_TSAP | parameter::CALLED_TSAP, _) => Some(p.clone()),
            _ => None,
        };
        let params = match &self.variable {
            Variable::Parameters(params) => params
                .iter()
                .enumerate()
                .filter(|(i, p)| !params[i + 1..].iter().any(|q| q.code == p.code))
                .filter_map(|(_, p)| echo(p))
                .collect(),
            Variable::Raw(_) => Vec::new(),
        };
        Some(Connect { dst_ref: self.src_ref, src_ref, variable: Variable::Parameters(params), ..Connect::default() })
    }

    /// The disconnect request that refuses this request, giving `reason`
    /// from [`reason`]; class 0 allows only 0 to 3. Its source reference
    /// is 0, since no connection was made.
    pub fn refuse(&self, reason: u8) -> Disconnect {
        Disconnect { dst_ref: self.src_ref, src_ref: 0, reason, ..Disconnect::default() }
    }
}

/// A disconnect request (DR).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Disconnect {
    /// The peer's reference for the connection.
    pub dst_ref: u16,
    /// The sender's reference for the connection, or 0 when refusing a
    /// request.
    pub src_ref: u16,
    /// Why, from [`reason`].
    pub reason: u8,
    /// The parameters, such as additional information.
    pub variable: Variable,
    /// User data after the header. Class 0 does not use it, but it is
    /// kept if it comes.
    pub data: Vec<u8>,
}

impl Disconnect {
    /// The additional information parameter, if it is there.
    pub fn additional_information(&self) -> Option<&[u8]> {
        self.variable.get(parameter::ADDITIONAL_INFORMATION)
    }

    /// Sets the additional information parameter, replacing one already
    /// there. A value longer than [`MAX_PARAMETER`] is cut to that length.
    pub fn with_additional_information(mut self, text: &[u8]) -> Disconnect {
        self.variable.set(parameter::ADDITIONAL_INFORMATION, text[..text.len().min(MAX_PARAMETER)].to_vec());
        self
    }
}

/// A data TPDU (DT): one segment of a message.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Data {
    /// Whether this is the last segment of its message (EOT).
    pub eot: bool,
    /// The TPDU number, seven bits. Class 0 does not use it, and senders
    /// set it to 0.
    pub number: u8,
    /// The segment's bytes.
    pub data: Vec<u8>,
}

/// An error TPDU (ER): the answer to a TPDU the receiver could not read.
/// Class 0 requires the invalid TPDU parameter, which
/// [`ErrorTpdu::rejecting`] always sets; the reader takes an ER without it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ErrorTpdu {
    /// The peer's reference for the connection, or 0 if there is none.
    pub dst_ref: u16,
    /// Why, from [`cause`].
    pub cause: u8,
    /// The parameters, such as the rejected TPDU's header.
    pub variable: Variable,
}

impl ErrorTpdu {
    /// The header of the rejected TPDU, if the parameter is there.
    pub fn invalid_tpdu(&self) -> Option<&[u8]> {
        self.variable.get(parameter::INVALID_TPDU)
    }

    /// The error TPDU that answers the bytes `bad`, which failed to read
    /// with `error`, on the connection the peer calls `dst_ref`. It
    /// carries `bad`'s header, as far as it goes, cut to fit.
    pub fn rejecting(dst_ref: u16, bad: &[u8], error: &TpduError) -> ErrorTpdu {
        let header = match bad.first() {
            Some(&li) => &bad[..bad.len().min(usize::from(li) + 1)],
            None => &[][..],
        };
        let room = MAX_HEADER - ERROR_FIXED - 2;
        let value = header[..header.len().min(room)].to_vec();
        let variable = Variable::Parameters(vec![Parameter { code: parameter::INVALID_TPDU, value }]);
        ErrorTpdu { dst_ref, cause: error.reject_cause(), variable }
    }
}

/// One class 0 TPDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tpdu {
    /// A connection request (CR).
    ConnectionRequest(Connect),
    /// A connection confirm (CC).
    ConnectionConfirm(Connect),
    /// A disconnect request (DR).
    DisconnectRequest(Disconnect),
    /// A data TPDU (DT).
    Data(Data),
    /// An error TPDU (ER).
    Error(ErrorTpdu),
}

/// Why bytes are not a class 0 TPDU this module reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpduError {
    /// There were no bytes.
    Empty,
    /// The length indicator is 255, which is reserved, or does not fit the
    /// TPDU's fixed part.
    LengthIndicator(u8),
    /// The length indicator says the header runs past the bytes there are.
    Truncated {
        /// How many bytes the header needs, the length indicator included.
        needed: usize,
        /// How many bytes there are.
        have: usize,
    },
    /// The TPDU code is not one class 0 uses, or the header is too short
    /// to hold one.
    Unsupported(u8),
    /// An error TPDU has bytes after its header, which it may not.
    UnexpectedData,
}

impl TpduError {
    /// The reject cause an error TPDU gives for this error.
    pub fn reject_cause(&self) -> u8 {
        match self {
            TpduError::Unsupported(_) => cause::INVALID_TPDU_TYPE,
            _ => cause::NOT_SPECIFIED,
        }
    }
}

impl core::fmt::Display for TpduError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TpduError::Empty => f.write_str("empty TPDU"),
            TpduError::LengthIndicator(li) => write!(f, "length indicator {li} does not fit the TPDU"),
            TpduError::Truncated { needed, have } => write!(f, "TPDU header needs {needed} bytes, has {have}"),
            TpduError::Unsupported(c) => write!(f, "TPDU code {c:#04x} is not class 0"),
            TpduError::UnexpectedData => f.write_str("error TPDU with data after its header"),
        }
    }
}

impl core::error::Error for TpduError {}

/// Why an exact, bounded [`Wire`] parse refused a TPDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The TPDU cannot fit in a TPKT payload.
    TooLong {
        /// Number of input bytes, greater than [`MAX_TPDU`].
        length: usize,
    },
    /// The TPDU header or body was invalid.
    Tpdu(TpduError),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong { length } => write!(f, "TPDU of {length} bytes, above {MAX_TPDU}"),
            Self::Tpdu(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for ParseError {}

/// A TPDU cannot be written without changing its value.
///
/// A field, parameter, header, or payload exceeds its wire limit, or a
/// [`Variable::Raw`] value would parse as [`Variable::Parameters`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeError;

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TPDU cannot be represented without changing its value")
    }
}

impl core::error::Error for EncodeError {}

impl Wire for Tpdu {
    type ParseError = ParseError;
    type WriteError = EncodeError;

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() > MAX_TPDU {
            return Err(ParseError::TooLong {
                length: bytes.len(),
            });
        }
        Tpdu::parse(bytes).map_err(ParseError::Tpdu)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // The legacy writer stages at most MAX_TPDU bytes. Compare before
        // appending so clipping, masked fields, and raw normalization fail
        // without changing the destination.
        let bytes = self.to_bytes_clipped();
        if Tpdu::parse(&bytes).as_ref() != Ok(self) {
            return Err(EncodeError);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// COTP TPDUs and messages carried by the shared TPKT codec.
///
/// `from_tpdu` and `try_from_tpdu` preserve the legacy conversion rules.
/// Use [`Wire::write`] on a [`Tpdu`] for strict, value-preserving encoding;
/// [`over_tpkt::write_message`] uses that writer and the TPKT writer.
pub mod over_tpkt {
    use super::{MAX_MESSAGE, Tpdu, TpduError, Variable, Wire, segment, tpkt};
    use tpkt::{EncodeError, Packet};

    /// The packet carrying `tpdu`, with the reserved byte 0. It always
    /// gives a packet, since [`Tpdu::to_bytes_clipped`] writes 3 to
    /// [`tpkt::MAX_PAYLOAD`] bytes, but cuts data past one packet,
    /// parameters past the header, and the high bits of narrow fields.
    /// [`try_from_tpdu`] refuses such a TPDU instead.
    pub fn from_tpdu(tpdu: &Tpdu) -> Packet {
        Packet::new(tpdu.to_bytes_clipped())
    }

    /// The packet carrying `tpdu`, with the reserved byte 0, if its payload
    /// reads back as the same TPDU. Otherwise it is
    /// [`EncodeError::Unrepresentable`]: data longer than one packet holds,
    /// a parameter or raw header bytes that do not fit the header, or a
    /// field wider than its format. A raw variable part counts as the same
    /// when its bytes are written whole, even if they read back as
    /// parameters. To send a long message, cut it with [`write_message`].
    pub fn try_from_tpdu(tpdu: &Tpdu) -> Result<Packet, EncodeError> {
        let packet = from_tpdu(tpdu);
        let mut back = Tpdu::parse(&packet.payload).map_err(|_| EncodeError::Unrepresentable)?;
        // Compare raw header bytes as the reader would see them, then put
        // the original back so the rest compares field by field.
        if let (Some(want), Some(got)) = (variable_of(tpdu), variable_mut(&mut back)) {
            let same = match want {
                Variable::Raw(b) => *got == Variable::parse(b),
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
    pub fn tpdu(packet: &Packet) -> Result<Tpdu, TpduError> {
        Tpdu::parse(&packet.payload)
    }

    /// The header's variable part, for the TPDUs that have one.
    fn variable_of(t: &Tpdu) -> Option<&Variable> {
        match t {
            Tpdu::ConnectionRequest(c) | Tpdu::ConnectionConfirm(c) => Some(&c.variable),
            Tpdu::DisconnectRequest(d) => Some(&d.variable),
            Tpdu::Error(e) => Some(&e.variable),
            Tpdu::Data(_) => None,
        }
    }

    /// [`variable_of`], to change it.
    fn variable_mut(t: &mut Tpdu) -> Option<&mut Variable> {
        match t {
            Tpdu::ConnectionRequest(c) | Tpdu::ConnectionConfirm(c) => Some(&mut c.variable),
            Tpdu::DisconnectRequest(d) => Some(&mut d.variable),
            Tpdu::Error(e) => Some(&mut e.variable),
            Tpdu::Data(_) => None,
        }
    }

    /// The packets carrying `message` as data TPDUs, with EOT on the last.
    /// [`segment`] clamps `tpdu_size`, including the TPDU header. A message
    /// longer than [`MAX_MESSAGE`] is refused. Both layers use [`Wire::write`].
    pub fn write_message(message: &[u8], tpdu_size: usize) -> Result<Vec<u8>, EncodeError> {
        if message.len() > MAX_MESSAGE {
            return Err(EncodeError::TooLong(message.len()));
        }
        let mut out = Vec::new();
        for data in segment(message, tpdu_size) {
            let mut payload = Vec::new();
            Wire::write(&Tpdu::Data(data), &mut payload)
                .map_err(|_| EncodeError::Unrepresentable)?;
            Wire::write(&Packet::new(payload), &mut out)?;
        }
        Ok(out)
    }
}

/// One bounded TPDU parse per TPKT packet, composed with [`Map`].
///
/// Items are `Result<Tpdu, TpduError>`. A malformed TPDU is an item error;
/// it does not end framing and can be answered with [`ErrorTpdu::rejecting`].
/// TPKT already bounds each payload to [`MAX_TPDU`], so only the standalone
/// [`Wire`] parser needs [`ParseError::TooLong`]. Framing errors are
/// [`tpkt::TpktError`].
pub type Tpdus = Map<tpkt::Packets, fn(tpkt::Packet) -> Result<Tpdu, TpduError>>;

/// Creates a TPDU decoder with a TPKT packet limit, including its header.
/// Clamps `packet_limit` to [`tpkt::MIN_PACKET`] through [`tpkt::MAX_PACKET`].
/// TPDU errors do not retain the refused bytes. To build an error reply
/// with [`ErrorTpdu::rejecting`], use [`super::codec::Stream::with_next`]:
/// its raw bytes are the TPKT packet, whose TPDU starts at [`tpkt::HEADER_LEN`].
pub fn tpdus(packet_limit: usize) -> Tpdus {
    tpkt::Packets::with_limit(packet_limit).map(|packet| Tpdu::parse(&packet.payload))
}

/// Data TPDUs joined into messages by [`Assemble`].
///
/// Items are [`super::codec::Assembled`]. Control TPDUs and TPDU parse
/// errors pass through as `Whole(Result<Tpdu, TpduError>)` items without
/// clearing a pending message.
/// DT payloads join in order until EOT. TPDU numbers are not checked.
/// EOF before EOT reports [`super::codec::AssembleError::Incomplete`], even
/// for an empty fragment. A torn TPKT reports [`super::codec::Fail::Truncated`].
/// Framing errors and message overflow end the stream.
pub type Messages =
    Assemble<Tpdus, fn(Result<Tpdu, TpduError>) -> Fragment<Result<Tpdu, TpduError>>>;

/// Creates a TPKT, TPDU, and message decoder with separate size limits.
///
/// `packet_limit` includes the TPKT header and is clamped by [`tpdus`].
/// `message_limit` counts DT payload bytes and is capped at [`MAX_MESSAGE`].
/// Zero permits empty messages. The decoder holds at most `message_limit`
/// bytes outside its driver's input buffer.
/// For `Whole(Err(_))`, obtain refused TPDU bytes through
/// [`super::codec::Stream::with_next`] as described on [`tpdus`].
pub fn messages(packet_limit: usize, message_limit: usize) -> Messages {
    Assemble::new(
        tpdus(packet_limit),
        message_limit.min(MAX_MESSAGE),
        |tpdu| match tpdu {
            Ok(Tpdu::Data(data)) => Fragment::Part {
                data: data.data,
                last: data.eot,
            },
            other => Fragment::Whole(other),
        },
    )
}

impl Tpdu {
    /// Reads the TPDU in `b`: all of it, as one packet carries.
    pub fn parse(b: &[u8]) -> Result<Tpdu, TpduError> {
        let (&li, rest) = b.split_first().ok_or(TpduError::Empty)?;
        if usize::from(li) > MAX_HEADER {
            return Err(TpduError::LengthIndicator(li));
        }
        let Some(header) = rest.get(..usize::from(li)) else {
            return Err(TpduError::Truncated { needed: usize::from(li) + 1, have: b.len() });
        };
        let data = rest.get(usize::from(li)..).unwrap_or_default();
        let Some(&code_byte) = header.first() else { return Err(TpduError::Unsupported(0)) };
        match code_byte & 0xf0 {
            code::CONNECTION_REQUEST | code::CONNECTION_CONFIRM => {
                let [_, dst_hi, dst_lo, src_hi, src_lo, class, variable @ ..] = header else {
                    return Err(TpduError::LengthIndicator(li));
                };
                let connect = Connect {
                    credit: code_byte & 0x0f,
                    dst_ref: u16::from_be_bytes([*dst_hi, *dst_lo]),
                    src_ref: u16::from_be_bytes([*src_hi, *src_lo]),
                    class: class >> 4,
                    options: class & 0x0f,
                    variable: Variable::parse(variable),
                    data: data.to_vec(),
                };
                Ok(if code_byte & 0xf0 == code::CONNECTION_REQUEST {
                    Tpdu::ConnectionRequest(connect)
                } else {
                    Tpdu::ConnectionConfirm(connect)
                })
            }
            _ if code_byte == code::DISCONNECT_REQUEST => {
                let [_, dst_hi, dst_lo, src_hi, src_lo, reason, variable @ ..] = header else {
                    return Err(TpduError::LengthIndicator(li));
                };
                Ok(Tpdu::DisconnectRequest(Disconnect {
                    dst_ref: u16::from_be_bytes([*dst_hi, *dst_lo]),
                    src_ref: u16::from_be_bytes([*src_hi, *src_lo]),
                    reason: *reason,
                    variable: Variable::parse(variable),
                    data: data.to_vec(),
                }))
            }
            _ if code_byte == code::DATA => {
                // Class 0 data has no variable part; a longer header is
                // another class's format.
                let [_, flags] = header else {
                    return Err(TpduError::LengthIndicator(li));
                };
                let eot = flags & code::EOT != 0;
                Ok(Tpdu::Data(Data {
                    eot,
                    number: flags & 0x7f,
                    data: data.to_vec(),
                }))
            }
            _ if code_byte == code::ERROR => {
                let [_, dst_hi, dst_lo, cause, variable @ ..] = header else {
                    return Err(TpduError::LengthIndicator(li));
                };
                if !data.is_empty() {
                    return Err(TpduError::UnexpectedData);
                }
                Ok(Tpdu::Error(ErrorTpdu {
                    dst_ref: u16::from_be_bytes([*dst_hi, *dst_lo]),
                    cause: *cause,
                    variable: Variable::parse(variable),
                }))
            }
            _ => Err(TpduError::Unsupported(code_byte)),
        }
    }

    /// The TPDU's bytes, with the legacy clipping behavior of
    /// [`Tpdu::to_bytes_clipped`]. Use [`Wire::write`] or `Wire::to_bytes`
    /// for strict writing without clipping or normalization.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_clipped()
    }

    /// The TPDU's bytes. Parameters that do not fit in the header are left
    /// out, and data past what one packet can carry is cut, so the bytes
    /// always read back and always fit in a packet. Fields wider than the
    /// format allows, such as a credit over 15, keep only their low bits.
    /// Use [`Wire::write`] or `Wire::to_bytes` for strict writing without
    /// clipping or normalization.
    pub fn to_bytes_clipped(&self) -> Vec<u8> {
        let mut out = vec![0u8];
        let data: &[u8] = match self {
            Tpdu::ConnectionRequest(c) | Tpdu::ConnectionConfirm(c) => {
                let kind = match self {
                    Tpdu::ConnectionRequest(_) => code::CONNECTION_REQUEST,
                    _ => code::CONNECTION_CONFIRM,
                };
                out.push(kind | (c.credit & 0x0f));
                out.extend_from_slice(&c.dst_ref.to_be_bytes());
                out.extend_from_slice(&c.src_ref.to_be_bytes());
                out.push((c.class & 0x0f) << 4 | (c.options & 0x0f));
                c.variable.write(&mut out, MAX_HEADER - CONNECT_FIXED);
                &c.data
            }
            Tpdu::DisconnectRequest(d) => {
                out.push(code::DISCONNECT_REQUEST);
                out.extend_from_slice(&d.dst_ref.to_be_bytes());
                out.extend_from_slice(&d.src_ref.to_be_bytes());
                out.push(d.reason);
                d.variable.write(&mut out, MAX_HEADER - DISCONNECT_FIXED);
                &d.data
            }
            Tpdu::Data(d) => {
                out.push(code::DATA);
                out.push(if d.eot { code::EOT } else { 0 } | (d.number & 0x7f));
                &d.data
            }
            Tpdu::Error(e) => {
                out.push(code::ERROR);
                out.extend_from_slice(&e.dst_ref.to_be_bytes());
                out.push(e.cause);
                e.variable.write(&mut out, MAX_HEADER - ERROR_FIXED);
                &[]
            }
        };
        // The header is at most MAX_HEADER + 1 bytes, so this fits a byte.
        let li = (out.len() - 1) as u8;
        if let Some(first) = out.first_mut() {
            *first = li;
        }
        let room = MAX_TPDU - out.len();
        out.extend_from_slice(data.get(..data.len().min(room)).unwrap_or_default());
        out
    }

    /// The TPDU in a TPKT packet, ready to write to the connection.
    #[allow(deprecated)] // Preserve the legacy clipping and padding writer.
    pub fn to_packet(&self) -> Vec<u8> {
        write_packet(&self.to_bytes())
    }
}

/// Why a [`Reassembler`] gave up on a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageTooLong {
    /// The longest message the reassembler takes.
    pub limit: usize,
}

impl core::fmt::Display for MessageTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "message longer than {} bytes", self.limit)
    }
}

impl core::error::Error for MessageTooLong {}

/// Puts a message back together from the data TPDUs that carry it.
#[derive(Clone, Debug)]
pub struct Reassembler {
    buf: Vec<u8>,
    limit: usize,
    /// Set after a message ran past the limit, until its last segment.
    skipping: bool,
}

impl Default for Reassembler {
    fn default() -> Reassembler {
        Reassembler::new()
    }
}

impl Reassembler {
    /// A reassembler that takes messages of up to [`MAX_MESSAGE`] bytes.
    pub fn new() -> Reassembler {
        Reassembler::with_limit(MAX_MESSAGE)
    }

    /// A reassembler that takes messages of up to `limit` bytes, or
    /// [`MAX_MESSAGE`] if `limit` is larger.
    pub fn with_limit(limit: usize) -> Reassembler {
        Reassembler { buf: Vec::new(), limit: limit.min(MAX_MESSAGE), skipping: false }
    }

    /// Adds the next segment. It returns the whole message once its last
    /// segment comes, and `Ok(None)` before then. A message that runs past
    /// the limit gives [`MessageTooLong`] once; the rest of its segments,
    /// up to its last, are dropped. A real stack disconnects instead, and
    /// a world can too.
    pub fn push(&mut self, segment: &Data) -> Result<Option<Vec<u8>>, MessageTooLong> {
        if self.skipping {
            if segment.eot {
                self.skipping = false;
            }
            return Ok(None);
        }
        let total = self.buf.len().checked_add(segment.data.len());
        if total.is_none_or(|n| n > self.limit) {
            self.buf = Vec::new();
            self.skipping = !segment.eot;
            return Err(MessageTooLong { limit: self.limit });
        }
        self.buf.extend_from_slice(&segment.data);
        if segment.eot {
            Ok(Some(core::mem::take(&mut self.buf)))
        } else {
            Ok(None)
        }
    }

    /// How many bytes of an unfinished message are held.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// Cuts `message` into data TPDUs no longer than `tpdu_size` bytes each,
/// header included, with EOT on the last. A size below 128, the smallest
/// TPDU size X.224 allows, is taken as 128, and one above [`MAX_TPDU`] as
/// that, so the segments never hold much more memory than the message.
/// An empty message is one empty TPDU.
pub fn segment(message: &[u8], tpdu_size: usize) -> Vec<Data> {
    let room = tpdu_size.clamp(ISO_DEFAULT_TPDU_SIZE, MAX_TPDU) - (DATA_FIXED + 1);
    let mut out: Vec<Data> = message.chunks(room).map(|c| Data { eot: false, number: 0, data: c.to_vec() }).collect();
    match out.last_mut() {
        Some(last) => last.eot = true,
        None => out.push(Data { eot: true, number: 0, data: Vec::new() }),
    }
    out
}

#[cfg(test)]
mod codec_tests {
    use super::super::codec::{
        AssembleError, Assembled, Fail, Stream, contract, finish, pump, test_support,
    };
    use super::*;

    fn strict_packet(tpdu: &Tpdu) -> tpkt::Packet {
        tpkt::Packet {
            reserved: 0x31,
            payload: Wire::to_bytes(tpdu).unwrap(),
        }
    }

    #[test]
    #[allow(deprecated)] // The moved helpers must preserve the old conversions.
    fn over_tpkt_conversions_preserve_legacy_behavior() {
        for value in [
            Tpdu::ConnectionRequest(Connect::request(1).with_called_tsap(b"tsap")),
            Tpdu::ConnectionConfirm(Connect {
                variable: Variable::Raw(vec![0xc0, 1, 10]),
                ..Connect::default()
            }),
            Tpdu::DisconnectRequest(Disconnect::default()),
            Tpdu::Error(ErrorTpdu::default()),
            Tpdu::Data(Data {
                number: 128,
                data: vec![1; MAX_TPDU],
                ..Data::default()
            }),
        ] {
            let packet = over_tpkt::from_tpdu(&value);
            assert_eq!(packet, tpkt::Packet::from_tpdu(&value));
            assert_eq!(packet.payload, value.to_bytes_clipped());
            assert_eq!(over_tpkt::tpdu(&packet), packet.tpdu());
            assert_eq!(
                over_tpkt::try_from_tpdu(&value),
                tpkt::Packet::try_from_tpdu(&value)
            );
        }
        let bad = tpkt::Packet::new(vec![2, 0x10, 0]);
        assert_eq!(over_tpkt::tpdu(&bad), Err(TpduError::Unsupported(0x10)));
    }

    #[test]
    #[allow(deprecated)] // The old message writer forwards without changing bytes.
    fn over_tpkt_message_writer_matches_both_wire_layers() {
        for size in [0, 125, 126, MAX_TPDU, MAX_MESSAGE] {
            let message = vec![0x5a; size];
            for tpdu_size in [0, 128, 1024, MAX_TPDU, usize::MAX] {
                let mut expected = Vec::new();
                for data in segment(&message, tpdu_size) {
                    let mut payload = Vec::new();
                    Wire::write(&Tpdu::Data(data), &mut payload).unwrap();
                    Wire::write(&tpkt::Packet::new(payload), &mut expected).unwrap();
                }
                let bytes = over_tpkt::write_message(&message, tpdu_size).unwrap();
                assert_eq!(bytes, expected);
                assert_eq!(tpkt::write_message(&message, tpdu_size), Ok(bytes.clone()));
                let items = drive(messages(tpkt::MAX_PACKET, MAX_MESSAGE), &[&bytes]);
                assert_eq!(items, vec![Assembled::Message(message.clone())]);
            }
        }
        assert_eq!(
            over_tpkt::write_message(&vec![0; MAX_MESSAGE + 1], 128),
            Err(tpkt::EncodeError::TooLong(MAX_MESSAGE + 1))
        );
    }

    fn drive<D: Decode>(decoder: D, chunks: &[&[u8]]) -> Vec<D::Item>
    where
        D::Error: Clone + core::fmt::Debug,
    {
        let capacity = decoder.capacity();
        let mut stream = Stream::new(decoder);
        let mut items = Vec::new();
        for chunk in chunks {
            assert_eq!(
                pump(&mut stream, chunk, |item| items.push(item)).unwrap(),
                chunk.len()
            );
            assert!(stream.buffered() <= capacity);
            assert!(stream.held() <= MAX_MESSAGE);
        }
        finish(&mut stream, |item| items.push(item)).unwrap();
        assert!(stream.is_done());
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.held(), 0);
        items
    }

    #[test]
    fn stack_round_trip_under_arbitrary_chunking() {
        let message: Vec<u8> = (0..513).map(|i| i as u8).collect();
        let request = Tpdu::ConnectionRequest(Connect::request(17).with_tpdu_size(128));
        let confirm = Tpdu::ConnectionConfirm(Connect {
            dst_ref: 17,
            src_ref: 29,
            ..Connect::default()
        });
        let mut units = vec![request.clone()];
        for (i, part) in segment(&message, 128).into_iter().enumerate() {
            units.push(Tpdu::Data(part));
            if i == 0 {
                units.push(confirm.clone());
            }
        }
        units.push(Tpdu::Data(Data {
            eot: true,
            number: 0,
            data: Vec::new(),
        }));
        units.push(Tpdu::Data(Data {
            eot: true,
            number: 0,
            data: b"next".to_vec(),
        }));
        let packets: Vec<_> = units.iter().map(strict_packet).collect();
        let mut wire = Vec::new();
        for packet in &packets {
            packet.write(&mut wire).unwrap();
        }
        let expected = vec![
            Assembled::Whole(Ok(request)),
            Assembled::Whole(Ok(confirm)),
            Assembled::Message(message.clone()),
            Assembled::Message(Vec::new()),
            Assembled::Message(b"next".to_vec()),
        ];
        let check = |chunks: Vec<&[u8]>| {
            let read_packets = drive(tpkt::Packets::with_limit(132), &chunks);
            assert_eq!(read_packets, packets);
            let read_tpdus = drive(tpdus(132), &chunks);
            assert_eq!(
                read_tpdus,
                units.iter().cloned().map(Ok).collect::<Vec<_>>()
            );
            let assembled = drive(messages(132, 1024), &chunks);
            assert_eq!(assembled, expected);

            // Run the layers separately as an oracle for the composed stack.
            let mut reassembler = Reassembler::with_limit(1024);
            let mut separate = Vec::new();
            let mut rewritten = Vec::new();
            for packet in read_packets {
                let tpdu = <Tpdu as Wire>::parse(&packet.payload).unwrap();
                assert_eq!(strict_packet(&tpdu), packet);
                strict_packet(&tpdu).write(&mut rewritten).unwrap();
                match tpdu {
                    Tpdu::Data(data) => {
                        if let Some(message) = reassembler.push(&data).unwrap() {
                            separate.push(Assembled::Message(message));
                        }
                    }
                    other => separate.push(Assembled::Whole(Ok(other))),
                }
            }
            assert_eq!(rewritten, wire);
            assert_eq!(separate, assembled);
        };
        for pattern in [&[][..], &[1], &[2], &[3, 1, 128, 4, 7], &[131, 2, 133]] {
            check(test_support::chunks(&wire, pattern).collect());
        }
        for seed in 0..32 {
            let mut rng = test_support::Lcg::new(seed);
            check(test_support::random_chunks(&wire, &mut rng, 199).collect());
        }
        contract::check_decode_with_held_limit(|| messages(132, 1024), &wire, 1024);

        // The existing message writer uses the same packet and TPDU layers.
        let written = over_tpkt::write_message(&message, 128).unwrap();
        let chunks: Vec<_> = written.chunks(1).collect();
        assert_eq!(
            drive(messages(132, 1024), &chunks),
            vec![Assembled::Message(message)]
        );
    }

    #[test]
    fn stream_parse_errors_can_build_replies() {
        let bad = tpkt::Packet::new(vec![2, 0x10, 0]);
        let good = Tpdu::Data(Data {
            eot: true,
            data: b"next".to_vec(),
            ..Data::default()
        });
        let mut wire = bad.to_bytes().unwrap();
        strict_packet(&good).write(&mut wire).unwrap();
        let chunks: Vec<_> = wire.chunks(1).collect();

        let mut items = drive(tpdus(tpkt::MAX_PACKET), &chunks).into_iter();
        let error = items.next().unwrap().unwrap_err();
        let reply = Tpdu::Error(ErrorTpdu::rejecting(17, &bad.payload, &error));
        assert_eq!(items.next(), Some(Ok(good)));
        assert_eq!(items.next(), None);

        let mut items = drive(messages(tpkt::MAX_PACKET, 4), &chunks).into_iter();
        let Some(Assembled::Whole(Err(error))) = items.next() else {
            panic!("malformed TPDU must be a per-item error");
        };
        // The world can answer the error directly, as in design section 5.1.
        assert_eq!(
            Tpdu::Error(ErrorTpdu::rejecting(17, &bad.payload, &error)),
            reply
        );
        assert_eq!(items.next(), Some(Assembled::Message(b"next".to_vec())));
        assert_eq!(items.next(), None);

        let Tpdu::Error(rejection) = &reply else {
            unreachable!()
        };
        assert_eq!(rejection.cause, cause::INVALID_TPDU_TYPE);
        assert_eq!(rejection.invalid_tpdu(), Some(bad.payload.as_slice()));
        let bytes = Wire::to_bytes(&reply).unwrap();
        assert_eq!(<Tpdu as Wire>::parse(&bytes), Ok(reply));
    }

    #[test]
    fn malformed_tpdu_is_an_item_and_preserves_assembly() {
        let first = strict_packet(&Tpdu::Data(Data {
            eot: false,
            number: 127,
            data: b"a".to_vec(),
        }));
        let bad = tpkt::Packet::new(vec![2, 0x10, 0]);
        let last = strict_packet(&Tpdu::Data(Data {
            eot: true,
            number: 23,
            data: b"b".to_vec(),
        }));
        let mut wire = Vec::new();
        for packet in [first, bad, last] {
            packet.write(&mut wire).unwrap();
        }
        assert_eq!(
            drive(messages(tpkt::MAX_PACKET, 2), &[&wire]),
            vec![
                Assembled::Whole(Err(TpduError::Unsupported(0x10))),
                Assembled::Message(b"ab".to_vec()),
            ]
        );
        contract::check_decode(|| tpdus(tpkt::MAX_PACKET), &wire);
        contract::check_decode_with_held_limit(|| messages(tpkt::MAX_PACKET, 2), &wire, 2);
    }

    #[test]
    fn assembly_limits_and_incomplete_eof_are_terminal() {
        for payload in [Vec::new(), b"abc".to_vec()] {
            let packet = strict_packet(&Tpdu::Data(Data {
                eot: false,
                number: 0,
                data: payload.clone(),
            }));
            let wire = packet.to_bytes().unwrap();
            let mut stream = Stream::new(messages(tpkt::MAX_PACKET, 3));
            assert_eq!(stream.push(&wire), wire.len());
            assert_eq!(stream.next(), None);
            assert_eq!(stream.held(), payload.len());
            stream.end();
            let error = Fail::Protocol(AssembleError::Incomplete {
                held: payload.len(),
            });
            assert_eq!(stream.next(), Some(Err(error.clone())));
            assert_eq!(stream.next(), None);
            assert_eq!(stream.failed(), Some(&error));
            contract::check_decode_with_held_limit(|| messages(tpkt::MAX_PACKET, 3), &wire, 3);
        }
        let mut wire = Vec::new();
        for eot in [false, true] {
            strict_packet(&Tpdu::Data(Data {
                eot,
                number: 0,
                data: b"ab".to_vec(),
            }))
            .write(&mut wire)
            .unwrap();
        }
        let mut stream = Stream::new(messages(tpkt::MAX_PACKET, 3));
        assert_eq!(stream.push(&wire), wire.len());
        let error = Fail::Protocol(AssembleError::TooLong { limit: 3 });
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.held(), 2);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&error));
        contract::check_decode_with_held_limit(|| messages(tpkt::MAX_PACKET, 3), &wire, 3);

        let empty = Tpdu::Data(Data {
            eot: true,
            ..Data::default()
        })
        .to_packet();
        assert_eq!(
            drive(messages(tpkt::MAX_PACKET, 0), &[&empty]),
            vec![Assembled::Message(Vec::new())]
        );
        let mut stream = Stream::new(messages(tpkt::MAX_PACKET, 0));
        assert_eq!(stream.push(&empty[..5]), 5);
        stream.end();
        assert_eq!(stream.next(), Some(Err(Fail::Truncated { unread: 5 })));
        let mut stream = Stream::new(messages(tpkt::MAX_PACKET, 0));
        assert_eq!(stream.push(&[9]), 1);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(AssembleError::Inner(
                tpkt::TpktError::Version(9)
            ))))
        );
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn wire_is_strict_bounded_and_transactional() {
        let raw = Tpdu::ConnectionRequest(Connect {
            variable: Variable::Raw(vec![0xc1, 0]),
            ..Connect::default()
        });
        let oversized = Tpdu::Data(Data {
            eot: true,
            number: 0,
            data: vec![1; MAX_TPDU - 2],
        });
        let invalid = [
            raw.clone(),
            oversized.clone(),
            Tpdu::Data(Data {
                number: 128,
                ..Data::default()
            }),
            Tpdu::ConnectionRequest(Connect {
                credit: 16,
                ..Connect::default()
            }),
            Tpdu::ConnectionConfirm(Connect {
                class: 16,
                ..Connect::default()
            }),
            Tpdu::ConnectionRequest(Connect {
                options: 16,
                ..Connect::default()
            }),
            Tpdu::DisconnectRequest(Disconnect {
                variable: Variable::Parameters(vec![Parameter {
                    code: 0xe0,
                    value: vec![1; MAX_PARAMETER + 1],
                }]),
                ..Disconnect::default()
            }),
            Tpdu::Error(ErrorTpdu {
                variable: Variable::Raw(vec![1; MAX_HEADER]),
                ..ErrorTpdu::default()
            }),
        ];
        for value in invalid {
            contract::check_wire_value(&value);
            let mut out = vec![0x55, 0xaa];
            assert_eq!(value.write(&mut out), Err(EncodeError));
            assert_eq!(out, [0x55, 0xaa]);
            assert!(Tpdu::parse(&value.to_bytes()).is_ok());
        }
        // Legacy conversion still accepts raw normalization and clipping.
        assert!(over_tpkt::try_from_tpdu(&raw).is_ok());
        assert_ne!(Tpdu::parse(&oversized.to_bytes()).unwrap(), oversized);
        let oversized_wire = [vec![2, 0xf0, 0x80], vec![0; MAX_TPDU - 2]].concat();
        assert!(Tpdu::parse(&oversized_wire).is_ok());
        assert_eq!(
            <Tpdu as Wire>::parse(&oversized_wire),
            Err(ParseError::TooLong {
                length: MAX_TPDU + 1
            })
        );

        for value in [
            Tpdu::ConnectionRequest(Connect::request(1).with_called_tsap(b"tsap")),
            Tpdu::ConnectionConfirm(Connect {
                variable: Variable::Raw(b"Cookie: test\r\n".to_vec()),
                ..Connect::default()
            }),
            Tpdu::DisconnectRequest(Disconnect::default()),
            Tpdu::Error(ErrorTpdu::default()),
            Tpdu::Data(Data {
                eot: true,
                number: 127,
                data: vec![1; MAX_TPDU - 3],
            }),
        ] {
            let bytes = Wire::to_bytes(&value).unwrap();
            contract::check_wire::<Tpdu>(&bytes);
            assert_eq!(<Tpdu as Wire>::parse(&bytes), Ok(value));
        }
    }

    #[test]
    #[allow(deprecated)] // Check the unchanged legacy buffering contract.
    fn compatibility_wrapper_buffers_whole_batches_and_repeats_errors() {
        let packet = Tpdu::Data(Data::default()).to_packet();
        let batch = packet.repeat(tpkt::MAX_PACKET / packet.len() + 1);
        let mut decoder = Decoder::new();
        decoder.feed(&batch);
        assert_eq!(decoder.buffered(), batch.len());
        assert!(decoder.buffered() > tpkt::MAX_PACKET);
        assert_eq!(decoder.clone().next_packet(), decoder.next_packet());
        while decoder.next_packet().is_some() {}
        decoder.feed(&[8]);
        for _ in 0..2 {
            assert_eq!(decoder.next_packet(), Some(Err(TpktError::Version(8))));
        }
        decoder.feed(&packet);
        assert_eq!(decoder.buffered(), 0);
        assert_eq!(decoder.next_packet(), Some(Err(TpktError::Version(8))));
    }
}

#[cfg(test)]
#[allow(deprecated)] // These tests cover the legacy API.
mod tests {
    use super::*;

    /// A deterministic stream of pseudo-random numbers.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    fn tpdu_from_packet(packet: &[u8]) -> Tpdu {
        let (tpdu, used) = parse_packet(packet).unwrap().unwrap();
        assert_eq!(used, packet.len());
        Tpdu::parse(tpdu).unwrap()
    }

    // RFC 1006 section 6: a TPKT is version 3, reserved, then the length
    // of the whole packet.
    #[test]
    fn tpkt_example() {
        let packet = [3, 0, 0, 7, 2, 0xf0, 0x80];
        assert_eq!(parse_packet(&packet), Ok(Some((&packet[4..], 7))));
        assert_eq!(write_packet(&packet[4..]), packet);
        // Every prefix is incomplete, not an error.
        for n in 0..packet.len() {
            assert_eq!(parse_packet(&packet[..n]), Ok(None), "{n} bytes");
        }
        // Extra bytes after the packet are left alone.
        let mut longer = packet.to_vec();
        longer.extend_from_slice(&[3, 0]);
        assert_eq!(parse_packet(&longer).unwrap().unwrap().1, 7);
    }

    #[test]
    fn tpkt_errors() {
        // Known from the first byte.
        assert_eq!(parse_packet(&[0x30]), Err(TpktError::Version(0x30)));
        assert_eq!(parse_packet(&[2, 0, 0, 7, 2, 0xf0, 0x80]), Err(TpktError::Version(2)));
        for n in 0..MIN_PACKET as u16 {
            let b = [3, 0, (n >> 8) as u8, n as u8];
            assert_eq!(parse_packet(&b), Err(TpktError::Length(n)));
        }
        // The reserved byte is not checked.
        assert!(parse_packet(&[3, 9, 0, 7, 2, 0xf0, 0x80]).unwrap().is_some());
        assert!(!TpktError::Version(2).to_string().is_empty());
        assert!(!TpktError::Length(2).to_string().is_empty());
    }

    #[test]
    fn write_packet_bounds() {
        let big = vec![7u8; MAX_PACKET + 10];
        let p = write_packet(&big);
        assert_eq!(p.len(), MAX_PACKET);
        assert_eq!(&p[2..4], &[0xff, 0xff]);
        assert!(parse_packet(&p).unwrap().is_some());
        // Too short a TPDU is padded, so the packet reads back.
        let p = write_packet(&[]);
        assert_eq!(p, [3, 0, 0, 7, 0, 0, 0]);
        assert!(parse_packet(&p).unwrap().is_some());
    }

    // An S7comm connection request as Siemens tools send it: TPDU size
    // 1024, calling TSAP 01 00, called TSAP 01 02 (rack 0, slot 2).
    const S7_CR: [u8; 22] =
        [0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02];

    #[test]
    fn connection_request_and_confirm() {
        let Tpdu::ConnectionRequest(cr) = tpdu_from_packet(&S7_CR) else { panic!() };
        assert_eq!((cr.credit, cr.dst_ref, cr.src_ref, cr.class, cr.options), (0, 0, 1, 0, 0));
        assert_eq!(cr.tpdu_size(), Some(1024));
        assert_eq!(cr.calling_tsap(), Some(&[1, 0][..]));
        assert_eq!(cr.called_tsap(), Some(&[1, 2][..]));
        assert!(cr.data.is_empty());
        // Built from parts, it is the same.
        let built = Connect::request(1).with_tpdu_size(1024).with_calling_tsap(&[1, 0]).with_called_tsap(&[1, 2]);
        assert_eq!(built, cr);
        assert_eq!(Tpdu::ConnectionRequest(built).to_packet(), S7_CR);
        let cc = cr.confirm(0x0044).unwrap();
        assert_eq!((cc.dst_ref, cc.src_ref), (1, 0x44));
        let packet = Tpdu::ConnectionConfirm(cc.clone()).to_packet();
        assert_eq!(&packet[4..10], &[0x11, 0xd0, 0x00, 0x01, 0x00, 0x44]);
        assert_eq!(tpdu_from_packet(&packet), Tpdu::ConnectionConfirm(cc));
    }

    // RFC 1006 section 5: on TCP the default TPDU size is 65531, not
    // ISO 8073's 128.
    #[test]
    fn rfc1006_default_tpdu_size() {
        assert_eq!(DEFAULT_TPDU_SIZE, 65531);
        assert_eq!(DEFAULT_TPDU_SIZE, MAX_TPDU);
        assert_eq!(ISO_DEFAULT_TPDU_SIZE, 128);
    }

    // X.224 13.3.4 b: sizes of 4096 and 8192 are not allowed in class 0,
    // and a confirm may not offer a size the request did not allow.
    #[test]
    fn confirm_keeps_class0_tpdu_size() {
        // A class 0 request built here never asks for more than 2048, so
        // a peer's request for 8192 is set by hand.
        assert_eq!(Connect::request(1).with_tpdu_size(8192).tpdu_size(), Some(MAX_CLASS0_TPDU_SIZE));
        let mut cr = Connect::request(1).with_called_tsap(&[1, 2]);
        cr.variable.set(parameter::TPDU_SIZE, vec![13]);
        let cc = cr.confirm(2).unwrap();
        assert_eq!(cc.tpdu_size(), Some(MAX_CLASS0_TPDU_SIZE));
        assert_eq!(cc.called_tsap(), Some(&[1, 2][..]));
        let mut cr = Connect::request(1);
        cr.variable.set(parameter::TPDU_SIZE, vec![12]);
        assert_eq!(cr.confirm(2).unwrap().tpdu_size(), Some(2048));
        let cr = Connect::request(1).with_tpdu_size(512);
        assert_eq!(cr.confirm(2).unwrap().tpdu_size(), Some(512));
        // A size value outside the code points is not echoed back.
        for bad in [vec![3u8], vec![14], vec![], vec![7, 0]] {
            let cr = Connect { variable: Variable::Parameters(vec![Parameter { code: parameter::TPDU_SIZE, value: bad }]), ..Connect::default() };
            assert_eq!(cr.confirm(2).unwrap().variable, Variable::Parameters(vec![]));
        }
    }

    // A world that changes a confirm's size or TSAP gets the new value, not
    // a second parameter hidden behind the first.
    #[test]
    fn builders_replace_parameters() {
        let cr = Connect::request(1).with_tpdu_size(1024).with_called_tsap(&[1, 2]).with_calling_tsap(&[1, 0]);
        let cc = cr.confirm(2).unwrap().with_tpdu_size(512).with_called_tsap(&[9]);
        assert_eq!(cc.tpdu_size(), Some(512));
        assert_eq!(cc.called_tsap(), Some(&[9][..]));
        // Each code once, in the order they first came.
        let Variable::Parameters(params) = &cc.variable else { panic!() };
        let codes: Vec<u8> = params.iter().map(|p| p.code).collect();
        assert_eq!(codes, [parameter::TPDU_SIZE, parameter::CALLED_TSAP, parameter::CALLING_TSAP]);
        let Ok(Tpdu::ConnectionConfirm(back)) = Tpdu::parse(&Tpdu::ConnectionConfirm(cc.clone()).to_bytes()) else { panic!() };
        assert_eq!(back, cc);
        // Set on a list that already holds the code twice keeps one.
        let mut v = Variable::Parameters(vec![Parameter { code: 1, value: vec![1] }, Parameter { code: 1, value: vec![2] }]);
        v.set(1, vec![3]);
        assert_eq!(v, Variable::Parameters(vec![Parameter { code: 1, value: vec![3] }]));
        // Set on raw bytes makes a list.
        let mut v = Variable::Raw(vec![1, 2, 3]);
        v.set(5, vec![]);
        assert_eq!(v.get(5), Some(&[][..]));
    }

    #[test]
    fn refusing_a_request() {
        let Tpdu::ConnectionRequest(cr) = tpdu_from_packet(&S7_CR) else { panic!() };
        let dr = cr.refuse(reason::ADDRESS_UNKNOWN).with_additional_information(b"no such slot");
        assert_eq!((dr.dst_ref, dr.src_ref, dr.reason), (1, 0, reason::ADDRESS_UNKNOWN));
        assert_eq!(dr.additional_information(), Some(&b"no such slot"[..]));
        let t = Tpdu::DisconnectRequest(dr);
        assert_eq!(tpdu_from_packet(&t.to_packet()), t);
        // Too long a text is cut to fit its length byte.
        let dr = Disconnect::default().with_additional_information(&[b'x'; 400]);
        assert_eq!(dr.additional_information().map(<[u8]>::len), Some(MAX_PARAMETER));
        assert!(matches!(Tpdu::parse(&Tpdu::DisconnectRequest(dr).to_bytes()), Ok(Tpdu::DisconnectRequest(_))));
    }

    #[test]
    fn tpdu_size_codes() {
        let size = |v: &[u8]| {
            let c = Connect { variable: Variable::Parameters(vec![Parameter { code: 0xc0, value: v.to_vec() }]), ..Connect::default() };
            c.tpdu_size()
        };
        assert_eq!(size(&[7]), Some(128));
        assert_eq!(size(&[11]), Some(2048));
        assert_eq!(size(&[13]), Some(8192));
        assert_eq!(size(&[6]), None);
        assert_eq!(size(&[14]), None);
        assert_eq!(size(&[]), None);
        assert_eq!(size(&[7, 0]), None);
        assert_eq!(Connect::default().with_tpdu_size(2047).tpdu_size(), Some(1024));
        assert_eq!(Connect::default().with_tpdu_size(1).tpdu_size(), Some(128));
        assert_eq!(Connect::default().with_tpdu_size(usize::MAX).tpdu_size(), Some(2048));
        let class4 = Connect { class: 4, ..Connect::default() };
        assert_eq!(class4.clone().with_tpdu_size(usize::MAX).tpdu_size(), Some(8192));
        assert_eq!(class4.with_tpdu_size(5000).tpdu_size(), Some(4096));
    }

    // MS-RDPBCGR 4.1.1: the client's X.224 connection request, with a
    // cookie and an RDP negotiation request inside the header.
    #[test]
    fn rdp_connection_request() {
        let mut tpdu = vec![0, 0xe0, 0, 0, 0, 0, 0];
        tpdu.extend_from_slice(b"Cookie: mstshash=eltons\r\n");
        tpdu.extend_from_slice(&[0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
        tpdu[0] = (tpdu.len() - 1) as u8;
        let packet = write_packet(&tpdu);
        assert_eq!(&packet[..4], &[3, 0, 0, 0x2c]);
        let Tpdu::ConnectionRequest(cr) = tpdu_from_packet(&packet) else { panic!() };
        let Variable::Raw(raw) = &cr.variable else { panic!() };
        assert!(raw.starts_with(b"Cookie: "));
        assert_eq!(cr.called_tsap(), None);
        assert_eq!(cr.confirm(9).unwrap().variable, Variable::Parameters(vec![]));
        assert_eq!(Tpdu::ConnectionRequest(cr).to_bytes(), tpdu);
    }

    #[test]
    fn data_tpdus() {
        // X.224 13.7: LI 2, code F0, EOT and TPDU-NR.
        let t = Tpdu::parse(&[2, 0xf0, 0x80, 1, 2, 3]).unwrap();
        assert_eq!(t, Tpdu::Data(Data { eot: true, number: 0, data: vec![1, 2, 3] }));
        assert_eq!(t.to_bytes(), [2, 0xf0, 0x80, 1, 2, 3]);
        let t = Tpdu::parse(&[2, 0xf0, 0x05]).unwrap();
        assert_eq!(t, Tpdu::Data(Data { eot: false, number: 5, data: vec![] }));
        // Another class's data header.
        assert_eq!(Tpdu::parse(&[4, 0xf0, 0, 1, 0x80]), Err(TpduError::LengthIndicator(4)));
        assert_eq!(Tpdu::parse(&[1, 0xf0]), Err(TpduError::LengthIndicator(1)));
        // Too much data is cut to fit a packet.
        let big = Tpdu::Data(Data { eot: true, number: 0, data: vec![1; MAX_PACKET] });
        assert_eq!(big.to_bytes().len(), MAX_TPDU);
        assert_eq!(big.to_packet().len(), MAX_PACKET);
    }

    #[test]
    fn disconnect_request() {
        let mut bytes = vec![10, 0x80, 0, 1, 0, 2, reason::NORMAL, 0xe0, 2, b'o', b'k'];
        let Tpdu::DisconnectRequest(dr) = Tpdu::parse(&bytes).unwrap() else { panic!() };
        assert_eq!((dr.dst_ref, dr.src_ref, dr.reason), (1, 2, 128));
        assert_eq!(dr.additional_information(), Some(&b"ok"[..]));
        assert_eq!(Tpdu::DisconnectRequest(dr).to_bytes(), bytes);
        bytes.truncate(7);
        bytes[0] = 6;
        assert!(matches!(Tpdu::parse(&bytes), Ok(Tpdu::DisconnectRequest(_))));
        assert_eq!(Tpdu::parse(&[5, 0x80, 0, 1, 0, 2]), Err(TpduError::LengthIndicator(5)));
    }

    #[test]
    fn error_tpdu() {
        let bad = [2, 0x10, 0x80];
        let e = Tpdu::parse(&bad).unwrap_err();
        assert_eq!(e, TpduError::Unsupported(0x10));
        let er = ErrorTpdu::rejecting(7, &bad, &e);
        assert_eq!(er.cause, cause::INVALID_TPDU_TYPE);
        assert_eq!(er.invalid_tpdu(), Some(&bad[..]));
        let bytes = Tpdu::Error(er.clone()).to_bytes();
        assert_eq!(bytes, [9, 0x70, 0, 7, 2, 0xc1, 3, 2, 0x10, 0x80]);
        assert_eq!(Tpdu::parse(&bytes), Ok(Tpdu::Error(er)));
        // No data may follow an error's header.
        assert_eq!(Tpdu::parse(&[4, 0x70, 0, 0, 0, 1]), Err(TpduError::UnexpectedData));
        assert_eq!(Tpdu::parse(&[3, 0x70, 0, 0]), Err(TpduError::LengthIndicator(3)));
        // Rejecting an empty or huge TPDU still writes a valid error.
        let er = ErrorTpdu::rejecting(0, &[], &TpduError::Empty);
        assert_eq!(er.cause, cause::NOT_SPECIFIED);
        assert!(Tpdu::parse(&Tpdu::Error(er).to_bytes()).is_ok());
        let mut huge = vec![254u8; 300];
        huge[1] = 0x00;
        let e = Tpdu::parse(&huge).unwrap_err();
        let er = ErrorTpdu::rejecting(0, &huge, &e);
        assert_eq!(Tpdu::parse(&Tpdu::Error(er.clone()).to_bytes()), Ok(Tpdu::Error(er)));
    }

    #[test]
    fn tpdu_errors() {
        assert_eq!(Tpdu::parse(&[]), Err(TpduError::Empty));
        assert_eq!(Tpdu::parse(&[255, 0xf0]), Err(TpduError::LengthIndicator(255)));
        assert_eq!(Tpdu::parse(&[0]), Err(TpduError::Unsupported(0)));
        assert_eq!(Tpdu::parse(&[6, 0xe0, 0]), Err(TpduError::Truncated { needed: 7, have: 3 }));
        assert_eq!(Tpdu::parse(&[5, 0xe0, 0, 0, 0, 0]), Err(TpduError::LengthIndicator(5)));
        // Codes outside class 0: DC, ED, AK, EA, RJ.
        for c in [0xc0, 0x10, 0x61, 0x20, 0x51, 0x81, 0xf1, 0x71] {
            assert_eq!(Tpdu::parse(&[6, c, 0, 0, 0, 0, 0]), Err(TpduError::Unsupported(c)), "{c:#x}");
        }
        for e in [
            TpduError::Empty,
            TpduError::LengthIndicator(1),
            TpduError::Truncated { needed: 2, have: 1 },
            TpduError::Unsupported(0),
            TpduError::UnexpectedData,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn every_truncated_prefix() {
        let packets = [
            S7_CR.to_vec(),
            Tpdu::DisconnectRequest(Disconnect { dst_ref: 1, src_ref: 2, reason: 133, ..Disconnect::default() }).to_packet(),
            Tpdu::Data(Data { eot: true, number: 0, data: b"hello".to_vec() }).to_packet(),
            Tpdu::Error(ErrorTpdu::rejecting(3, &[2, 0x10, 0], &TpduError::Unsupported(0x10))).to_packet(),
        ];
        for p in &packets {
            for n in 0..p.len() {
                assert_eq!(parse_packet(&p[..n]), Ok(None), "{n} of {p:?}");
                let mut d = Decoder::new();
                d.feed(&p[..n]);
                assert_eq!(d.next_packet(), None);
                assert_eq!(d.buffered(), n);
            }
            // A TPDU cut short never panics; only its header must be whole.
            let tpdu = &p[4..];
            let li = usize::from(tpdu[0]);
            for n in 0..tpdu.len() {
                let r = Tpdu::parse(&tpdu[..n]);
                if n == 0 {
                    assert_eq!(r, Err(TpduError::Empty));
                } else if n <= li {
                    assert_eq!(r, Err(TpduError::Truncated { needed: li + 1, have: n }));
                }
            }
        }
    }

    #[test]
    fn variable_parts() {
        assert_eq!(Variable::parse(&[]), Variable::Parameters(vec![]));
        assert_eq!(Variable::parse(&[0xc0, 1, 7]), Variable::Parameters(vec![Parameter { code: 0xc0, value: vec![7] }]));
        // A length past the end, and a lone byte.
        assert_eq!(Variable::parse(&[0xc0, 2, 7]), Variable::Raw(vec![0xc0, 2, 7]));
        assert_eq!(Variable::parse(&[0xc0, 1, 7, 9]), Variable::Raw(vec![0xc0, 1, 7, 9]));
        // Writers leave out what does not fit, and the rest reads back.
        let params: Vec<Parameter> = (0..10).map(|i| Parameter { code: i, value: vec![i; 60] }).collect();
        let c = Connect { variable: Variable::Parameters(params.clone()), ..Connect::default() };
        let bytes = Tpdu::ConnectionRequest(c).to_bytes();
        assert!(bytes.len() <= MAX_HEADER + 1);
        let Ok(Tpdu::ConnectionRequest(back)) = Tpdu::parse(&bytes) else { panic!() };
        assert_eq!(back.variable, Variable::Parameters(params[..4].to_vec()));
        // A value too long for its length byte is left out.
        let c = Connect::default().with_called_tsap(&[1; 300]);
        assert_eq!(c.called_tsap().map(<[u8]>::len), Some(MAX_PARAMETER));
        let c = Connect { variable: Variable::Parameters(vec![Parameter { code: 1, value: vec![0; 256] }]), ..c };
        let Ok(Tpdu::ConnectionRequest(back)) = Tpdu::parse(&Tpdu::ConnectionRequest(c).to_bytes()) else { panic!() };
        assert_eq!(back.variable, Variable::Parameters(vec![]));
        // Raw bytes too long are cut.
        let d = Disconnect { variable: Variable::Raw(vec![0xff; 400]), ..Disconnect::default() };
        let bytes = Tpdu::DisconnectRequest(d).to_bytes();
        assert_eq!(bytes[0], 254);
        assert!(Tpdu::parse(&bytes).is_ok());
        // Adding a parameter to raw bytes replaces them.
        let c = Connect { variable: Variable::Raw(vec![1]), ..Connect::default() }.with_called_tsap(&[5]);
        assert_eq!(c.called_tsap(), Some(&[5][..]));
    }

    #[test]
    fn reassembly() {
        let seg = |eot, d: &[u8]| Data { eot, number: 0, data: d.to_vec() };
        let mut r = Reassembler::new();
        assert_eq!(r.push(&seg(false, b"ab")), Ok(None));
        assert_eq!(r.pending(), 2);
        assert_eq!(r.push(&seg(false, b"")), Ok(None));
        assert_eq!(r.push(&seg(true, b"cd")), Ok(Some(b"abcd".to_vec())));
        assert_eq!(r.pending(), 0);
        // Past the limit: one error, the rest of the message dropped.
        let mut r = Reassembler::with_limit(4);
        assert_eq!(r.push(&seg(false, b"abc")), Ok(None));
        assert_eq!(r.push(&seg(false, b"de")), Err(MessageTooLong { limit: 4 }));
        assert_eq!(r.pending(), 0);
        assert_eq!(r.push(&seg(false, b"x")), Ok(None));
        assert_eq!(r.push(&seg(true, b"y")), Ok(None));
        assert_eq!(r.push(&seg(true, b"ok")), Ok(Some(b"ok".to_vec())));
        // An over-long last segment ends the message there.
        assert_eq!(r.push(&seg(true, b"12345")), Err(MessageTooLong { limit: 4 }));
        assert_eq!(r.push(&seg(true, b"1234")), Ok(Some(b"1234".to_vec())));
        assert_eq!(Reassembler::with_limit(usize::MAX).limit, MAX_MESSAGE);
        assert!(!MessageTooLong { limit: 4 }.to_string().is_empty());
    }

    #[test]
    fn segmenting() {
        let msg: Vec<u8> = (0..=255).collect();
        let segs = segment(&msg, ISO_DEFAULT_TPDU_SIZE);
        assert_eq!(segs.len(), 3);
        assert!(segs.iter().all(|s| s.data.len() + 3 <= ISO_DEFAULT_TPDU_SIZE));
        assert_eq!(segs.iter().filter(|s| s.eot).count(), 1);
        assert!(segs[2].eot);
        let mut r = Reassembler::new();
        let mut got = None;
        for s in &segs {
            let bytes = Tpdu::Data(s.clone()).to_packet();
            assert!(bytes.len() - 4 <= ISO_DEFAULT_TPDU_SIZE);
            let Tpdu::Data(back) = tpdu_from_packet(&bytes) else { panic!() };
            got = r.push(&back).unwrap();
        }
        assert_eq!(got, Some(msg));
        assert_eq!(segment(&[], 128), vec![Data { eot: true, number: 0, data: vec![] }]);
        assert_eq!(segment(b"abc", 0).len(), 1);
        assert_eq!(segment(b"abc", usize::MAX).len(), 1);
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = S7_CR.to_vec();
        let b = Tpdu::Data(Data { eot: true, number: 0, data: b"x".to_vec() }).to_packet();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(p) = d.next_packet() {
                got.push(p.unwrap());
            }
        }
        assert_eq!(got, [a[4..].to_vec(), b[4..].to_vec()]);
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        d.feed(&[0x44, 0, 0, 7]);
        assert_eq!(d.next_packet(), Some(Err(TpktError::Version(0x44))));
        d.feed(&a);
        assert_eq!(d.next_packet(), Some(Err(TpktError::Version(0x44))));
        assert_eq!(d.buffered(), 0);
    }

    // X.224 13.2.3: when a parameter comes more than once, the later
    // value is used, and a confirm echoes only that one.
    #[test]
    fn duplicate_parameters_use_the_last() {
        let Ok(Tpdu::ConnectionRequest(cr)) = Tpdu::parse(&[0x0c, 0xe0, 0, 0, 0, 1, 0, 0xc0, 1, 0x0a, 0xc0, 1, 7]) else {
            panic!()
        };
        assert_eq!(cr.tpdu_size(), Some(128));
        let cc = cr.confirm(2).unwrap();
        assert_eq!(cc.variable, Variable::Parameters(vec![Parameter { code: parameter::TPDU_SIZE, value: vec![7] }]));
        let v = Variable::parse(&[0xc2, 1, 1, 0xc1, 1, 5, 0xc2, 1, 2]);
        assert_eq!(v.get(parameter::CALLED_TSAP), Some(&[2][..]));
        let c = Connect { variable: v, ..Connect::default() };
        let cc = c.confirm(1).unwrap();
        let Variable::Parameters(params) = &cc.variable else { panic!() };
        let codes: Vec<u8> = params.iter().map(|p| p.code).collect();
        assert_eq!(codes, [parameter::CALLING_TSAP, parameter::CALLED_TSAP]);
        assert_eq!(cc.called_tsap(), Some(&[2][..]));
    }

    // X.224 6.5.4 and table 3: class 0 answers a request only when the
    // request offers class 0 or 1.
    #[test]
    fn confirm_follows_the_class_table() {
        let Ok(Tpdu::ConnectionRequest(cr)) = Tpdu::parse(&[6, 0xe0, 0, 0, 0, 1, 0x20]) else { panic!() };
        assert_eq!(cr.class, 2);
        assert!(!cr.allows_class0());
        assert_eq!(cr.confirm(2), None);
        let with_alternatives = |class: u8, alts: &[u8]| {
            let mut c = Connect { class, ..Connect::request(1) };
            if !alts.is_empty() {
                c.variable.set(parameter::ALTERNATIVE_CLASSES, alts.iter().map(|a| a << 4).collect());
            }
            c.allows_class0()
        };
        // Preferred class, alternatives, and whether class 0 is valid.
        let table: [(u8, &[u8], bool); 16] = [
            (0, &[], true),
            (0, &[1], false),
            (1, &[], true),
            (1, &[0], true),
            (1, &[2], false),
            (2, &[], false),
            (2, &[0], true),
            (2, &[1], false),
            (2, &[2], false),
            (3, &[], false),
            (3, &[0], true),
            (3, &[1], true),
            (3, &[2], false),
            (3, &[4], false),
            (4, &[1, 0], true),
            (5, &[], false),
        ];
        for (class, alts, valid) in table {
            assert_eq!(with_alternatives(class, alts), valid, "class {class}, alternatives {alts:?}");
        }
        let mut c = Connect { class: 4, ..Connect::request(1) };
        c.variable.set(parameter::ALTERNATIVE_CLASSES, vec![0x00]);
        assert_eq!(c.confirm(3).map(|cc| cc.class), Some(0));
    }

    // A variable part longer than a header could hold is kept as raw
    // bytes, not split into a list many times its size.
    #[test]
    fn variable_parse_is_bounded() {
        assert!(matches!(Variable::parse(&[0xc1, 0].repeat(127)), Variable::Parameters(p) if p.len() == 127));
        assert_eq!(Variable::parse(&[0xc1, 0].repeat(200)), Variable::Raw([0xc1, 0].repeat(200)));
    }

    // Segments are at least the smallest TPDU size, so a tiny size does
    // not turn each byte into its own allocation.
    #[test]
    fn segment_size_has_a_floor() {
        let msg = vec![7u8; 1000];
        for size in [0, 4, 127, 128] {
            let segs = segment(&msg, size);
            assert_eq!(segs.len(), 8, "size {size}");
            assert!(segs.iter().all(|s| s.data.len() + 3 <= ISO_DEFAULT_TPDU_SIZE));
            assert_eq!(segs.iter().flat_map(|s| s.data.iter().copied()).collect::<Vec<u8>>(), msg);
        }
    }

    // After a large burst is taken out, the decoder does not keep the
    // burst's allocation.
    #[test]
    fn decoder_releases_room_after_a_burst() {
        let one = Tpdu::Data(Data { eot: true, number: 0, data: vec![1; 1000] }).to_packet();
        let mut d = Decoder::new();
        d.feed(&one.repeat(1000));
        let mut n = 0;
        while let Some(p) = d.next_packet() {
            p.unwrap();
            n += 1;
        }
        assert_eq!(n, 1000);
        assert_eq!(d.buffered(), 0);
        assert!(d.buf.capacity() <= DECODER_RETAINED, "{}", d.buf.capacity());
        // With part of a packet left over, the next feed gives the room back.
        let mut stream = one.repeat(1000);
        stream.extend_from_slice(&one[..10]);
        d.feed(&stream);
        while let Some(p) = d.next_packet() {
            p.unwrap();
        }
        d.feed(&one[10..]);
        assert!(d.buf.capacity() <= DECODER_RETAINED, "{}", d.buf.capacity());
        assert_eq!(d.next_packet(), Some(Ok(one[4..].to_vec())));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_packets_in_linear_time() {
        let one = Tpdu::Data(Data { eot: true, number: 0, data: vec![1] }).to_packet();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        d.feed(&stream);
        let mut n = 0;
        while let Some(p) = d.next_packet() {
            p.unwrap();
            n += 1;
        }
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    /// Every packet a decoder gives for `data` fed in pieces of `step`
    /// bytes, the error that ended the stream, if any, and what is left.
    fn decode(data: &[u8], step: usize) -> (Vec<Vec<u8>>, Option<TpktError>, usize) {
        let mut d = Decoder::new();
        let mut packets = Vec::new();
        for piece in data.chunks(step.max(1)) {
            d.feed(piece);
            while let Some(r) = d.next_packet() {
                match r {
                    Ok(p) => packets.push(p),
                    Err(e) => return (packets, Some(e), d.buffered()),
                }
            }
        }
        (packets, None, d.buffered())
    }

    /// The checks the fuzz target makes, on one buffer.
    fn check(data: &[u8]) {
        let (packets, error, left) = decode(data, data.len());
        for step in [1, 2, 7] {
            assert_eq!(decode(data, step), (packets.clone(), error, left), "step {step}");
        }
        // Any bytes cut into segments come back whole.
        let size = data.first().map_or(128, |&b| usize::from(b) * 3);
        let mut r = Reassembler::new();
        let mut got = None;
        for s in segment(data, size) {
            let Ok(Tpdu::Data(back)) = Tpdu::parse(&Tpdu::Data(s.clone()).to_bytes()) else { panic!() };
            assert_eq!(back, s);
            assert!(got.is_none());
            got = r.push(&back).unwrap();
        }
        assert_eq!(got.as_deref(), Some(data));
        let mut r = Reassembler::with_limit(64);
        for p in packets.iter().map(Vec::as_slice).chain([data]) {
            assert_eq!(parse_packet(&write_packet(p)).unwrap().unwrap().0.len(), p.len().clamp(MIN_TPDU, MAX_TPDU));
            match Tpdu::parse(p) {
                Ok(t) => {
                    let bytes = t.to_bytes();
                    assert_eq!(Tpdu::parse(&bytes), Ok(t.clone()), "{p:?}");
                    assert_eq!(tpdu_from_packet(&t.to_packet()), t);
                    if let Tpdu::Data(d) = &t {
                        let _ = r.push(d);
                        assert!(r.pending() <= 64);
                    }
                    if let Tpdu::ConnectionRequest(c) = &t {
                        match c.confirm(1) {
                            Some(cc) => {
                                assert_eq!(cc.class, 0);
                                let cc = Tpdu::ConnectionConfirm(cc);
                                assert_eq!(Tpdu::parse(&cc.to_bytes()), Ok(cc));
                            }
                            None => assert!(!c.allows_class0()),
                        }
                    }
                }
                Err(e) => {
                    let er = Tpdu::Error(ErrorTpdu::rejecting(0, p, &e));
                    assert_eq!(Tpdu::parse(&er.to_bytes()), Ok(er));
                }
            }
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg(0x0102_0304_0506_0708);
        for i in 0..20_000 {
            let len = rng.below(80) as usize;
            let mut b = rng.bytes(len);
            // Most buffers look like packets, so the deeper code runs.
            if i % 4 != 0 && b.len() >= 5 {
                b[0] = 3;
                let total = (rng.below(b.len() as u64 + 3)) as u16;
                b[2..4].copy_from_slice(&total.to_be_bytes());
                b[4] = rng.below(b.len().saturating_sub(4) as u64 + 2) as u8;
                if b.len() > 5 {
                    b[5] = [0xe0, 0xd0, 0x80, 0xf0, 0x70, 0xe3, 0x10][rng.below(7) as usize];
                }
            }
            check(&b);
            // The same bytes as a TPDU on its own.
            if let Ok(t) = Tpdu::parse(&b) {
                assert_eq!(Tpdu::parse(&t.to_bytes()), Ok(t));
            }
        }
    }

    #[test]
    fn lcg_fuzz_writers() {
        let mut rng = Lcg(42);
        for _ in 0..3000 {
            let mut variable = Variable::Parameters(Vec::new());
            for _ in 0..rng.below(6) {
                let n = rng.below(300) as usize;
                variable.set(rng.next() as u8, rng.bytes(n));
            }
            if rng.below(4) == 0 {
                let n = rng.below(400) as usize;
                variable = Variable::Raw(rng.bytes(n));
            }
            let n = rng.below(3000) as usize;
            let data = rng.bytes(n);
            let t = match rng.below(5) {
                0 | 1 => {
                    let c = Connect {
                        credit: rng.next() as u8,
                        dst_ref: rng.next() as u16,
                        src_ref: rng.next() as u16,
                        class: rng.next() as u8,
                        options: rng.next() as u8,
                        variable,
                        data,
                    };
                    if rng.below(2) == 0 { Tpdu::ConnectionRequest(c) } else { Tpdu::ConnectionConfirm(c) }
                }
                2 => Tpdu::DisconnectRequest(Disconnect {
                    dst_ref: rng.next() as u16,
                    src_ref: rng.next() as u16,
                    reason: rng.next() as u8,
                    variable,
                    data,
                }),
                3 => Tpdu::Data(Data { eot: rng.below(2) == 0, number: rng.below(128) as u8, data }),
                _ => Tpdu::Error(ErrorTpdu { dst_ref: rng.next() as u16, cause: rng.next() as u8, variable }),
            };
            let packet = t.to_packet();
            let back = tpdu_from_packet(&packet);
            // Reading it back again changes nothing more.
            assert_eq!(tpdu_from_packet(&back.to_packet()), back);
            // Data that fits in a packet comes back as it was.
            if let Tpdu::Data(_) = t {
                assert_eq!(back, t);
            }
            for s in segment(&packet, rng.below(200) as usize) {
                assert!(Tpdu::parse(&Tpdu::Data(s).to_bytes()).is_ok());
            }
        }
    }
}
