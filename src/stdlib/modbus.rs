//! Modbus/TCP: reading and writing frames, requests and responses, with no
//! I/O.
//!
//! Modbus is how most industrial equipment is read and controlled: a PLC
//! holds coils (single bits it can switch) and registers (16-bit values),
//! and a client reads and writes them by address. Modbus/TCP carries each
//! message over a TCP connection, usually on port 502, behind a 7-byte
//! header (the MBAP header). This module follows the Modbus Application
//! Protocol Specification v1.1b3 and the Modbus Messaging on TCP/IP
//! Implementation Guide v1.0b.
//!
//! Nothing here reads a socket. A world that plays a PLC feeds the bytes
//! it reads from a [`tcp`](crate::stdlib::tcp) connection to a
//! [`Decoder`], gets [`Frame`]s back, reads each one's [`Request`], and
//! writes the reply's bytes back to the connection. Which coils and
//! registers exist, and what they hold, is up to world code. So is whether
//! a write succeeds.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. A request that breaks the specification becomes an
//! [`Exception`] the world can send back, as a real device would.
//!
//! ```
//! use fictionet::stdlib::modbus::{Decoder, Exception, Frame, Request, Response};
//!
//! /// Holding registers 0 to 9 of a pretend tank controller.
//! fn answer(registers: &mut [u16; 10], frame: &Frame) -> Frame {
//!     let reply = match Request::parse(&frame.pdu) {
//!         Ok(Request::ReadHoldingRegisters { address, quantity }) => {
//!             let (a, n) = (usize::from(address), usize::from(quantity));
//!             match registers.get(a..a + n) {
//!                 Some(values) => Response::Registers(values.to_vec()).to_pdu(3),
//!                 None => Exception::IllegalDataAddress.to_pdu(3),
//!             }
//!         }
//!         Ok(Request::WriteSingleRegister { address, value }) => match registers.get_mut(usize::from(address)) {
//!             Some(r) => {
//!                 *r = value;
//!                 Response::WriteSingleRegister { address, value }.to_pdu(6)
//!             }
//!             None => Exception::IllegalDataAddress.to_pdu(6),
//!         },
//!         Ok(other) => Exception::IllegalFunction.to_pdu(other.function()),
//!         Err(e) => e.to_pdu(frame.function().unwrap_or(0)),
//!     };
//!     frame.reply(reply)
//! }
//!
//! let mut registers = [0u16; 10];
//! registers[2] = 1234;
//! let mut decoder = Decoder::new();
//! // Read 1 holding register at address 2, transaction 7, unit 1.
//! decoder.feed(&[0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1]);
//! let frame = decoder.next_frame().unwrap().unwrap();
//! let reply = answer(&mut registers, &frame);
//! assert_eq!(reply.to_bytes(), [0, 7, 0, 0, 0, 5, 1, 3, 2, 0x04, 0xd2]);
//! ```

/// The TCP port Modbus/TCP servers listen on.
pub const PORT: u16 = 502;
/// The longest PDU (function code and data) a frame may carry.
pub const MAX_PDU: usize = 253;
/// The length of the MBAP header, before the PDU.
pub const HEADER_LEN: usize = 7;
/// The longest frame: the header and the longest PDU.
pub const MAX_FRAME: usize = HEADER_LEN + MAX_PDU;

/// Function codes this module reads and writes.
pub mod function {
    #![allow(missing_docs)]
    pub const READ_COILS: u8 = 0x01;
    pub const READ_DISCRETE_INPUTS: u8 = 0x02;
    pub const READ_HOLDING_REGISTERS: u8 = 0x03;
    pub const READ_INPUT_REGISTERS: u8 = 0x04;
    pub const WRITE_SINGLE_COIL: u8 = 0x05;
    pub const WRITE_SINGLE_REGISTER: u8 = 0x06;
    pub const WRITE_MULTIPLE_COILS: u8 = 0x0f;
    pub const WRITE_MULTIPLE_REGISTERS: u8 = 0x10;
    /// Added to a function code in the response to say it failed.
    pub const EXCEPTION_FLAG: u8 = 0x80;
}

/// The most coils or discrete inputs one read may ask for.
pub const MAX_READ_BITS: u16 = 2000;
/// The most registers one read may ask for.
pub const MAX_READ_REGISTERS: u16 = 125;
/// The most coils one write may set.
pub const MAX_WRITE_BITS: u16 = 1968;
/// The most registers one write may set.
pub const MAX_WRITE_REGISTERS: u16 = 123;

/// One Modbus/TCP frame: the MBAP header's fields and the PDU it carries.
/// The header's protocol identifier is always 0 and its length is worked
/// out from the PDU, so neither is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Chosen by the client and copied into the reply, so it can match
    /// replies to requests.
    pub transaction: u16,
    /// The unit identifier: which device behind a gateway the frame is
    /// for. A device on its own usually ignores it.
    pub unit: u8,
    /// The function code and its data.
    pub pdu: Vec<u8>,
}

/// Why bytes are not a Modbus/TCP frame. Either way, the connection holds
/// no more frames a reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The protocol identifier was not 0, so this is not Modbus.
    Protocol(u16),
    /// The length field was below 2 (a unit and a function code) or above
    /// what a frame may hold.
    Length(u16),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Protocol(p) => write!(f, "protocol identifier {p}, not 0 (Modbus)"),
            FrameError::Length(n) => write!(f, "length field {n}, outside 2..=254"),
        }
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    /// Reads the frame at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the frame and how many bytes
    /// of `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
        if b.len() < HEADER_LEN {
            // A bad protocol identifier is known before the rest comes.
            if b.len() >= 4 {
                let protocol = be16(b, 2);
                if protocol != 0 {
                    return Err(FrameError::Protocol(protocol));
                }
            }
            return Ok(None);
        }
        let protocol = be16(b, 2);
        if protocol != 0 {
            return Err(FrameError::Protocol(protocol));
        }
        let length = be16(b, 4);
        if length < 2 || usize::from(length) > MAX_PDU + 1 {
            return Err(FrameError::Length(length));
        }
        let end = 6 + usize::from(length);
        if b.len() < end {
            return Ok(None);
        }
        let frame = Frame { transaction: be16(b, 0), unit: b[6], pdu: b[HEADER_LEN..end].to_vec() };
        Ok(Some((frame, end)))
    }

    /// The frame's bytes: the MBAP header, then the PDU. A PDU longer than
    /// [`MAX_PDU`] is cut to that length, since no frame can hold more.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pdu = &self.pdu[..self.pdu.len().min(MAX_PDU)];
        let mut out = Vec::with_capacity(HEADER_LEN + pdu.len());
        out.extend_from_slice(&self.transaction.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(pdu.len() as u16 + 1).to_be_bytes());
        out.push(self.unit);
        out.extend_from_slice(pdu);
        out
    }

    /// The function code: the PDU's first byte. A frame read by
    /// [`Frame::parse`] always has one.
    pub fn function(&self) -> Option<u8> {
        self.pdu.first().copied()
    }

    /// A frame that answers this one with `pdu`, with the same transaction
    /// and unit.
    pub fn reply(&self, pdu: Vec<u8>) -> Frame {
        Frame { transaction: self.transaction, unit: self.unit, pdu }
    }
}

/// Splits a Modbus/TCP byte stream into frames. Feed it the bytes a
/// connection reads, in order, and take frames out until it has none.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small frames costs time in proportion to their bytes.
    start: usize,
    failed: Option<FrameError>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes read from the connection. After a [`FrameError`] the
    /// stream cannot be read any further, and they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The next whole frame, if one has come. It returns `None` when it
    /// needs more bytes, and keeps returning the same error once the
    /// stream has broken. A decoder never holds more than one frame's
    /// bytes beyond what has been taken out, plus what one `feed` added.
    pub fn next_frame(&mut self) -> Option<Result<Frame, FrameError>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        match Frame::parse(&self.buf[self.start..]) {
            Ok(Some((frame, used))) => {
                self.start += used;
                Some(Ok(frame))
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

    /// How many bytes are held, waiting for the rest of a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

/// The exception codes a server answers with when it cannot do what a
/// request asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exception {
    /// The server does not support this function.
    IllegalFunction,
    /// An address, or an address plus quantity, is outside what the server
    /// has.
    IllegalDataAddress,
    /// A value in the request is not allowed, such as a quantity out of
    /// range or a byte count that does not match.
    IllegalDataValue,
    /// The server failed while doing what was asked.
    ServerDeviceFailure,
    /// The server accepted the request and will take a long time.
    Acknowledge,
    /// The server is busy; try later.
    ServerDeviceBusy,
    /// A gateway could not reach the device the unit identifier names.
    GatewayPathUnavailable,
    /// The device behind a gateway did not answer.
    GatewayTargetFailedToRespond,
    /// Any other code.
    Other(u8),
}

impl Exception {
    /// The exception code's number.
    pub fn code(self) -> u8 {
        match self {
            Exception::IllegalFunction => 0x01,
            Exception::IllegalDataAddress => 0x02,
            Exception::IllegalDataValue => 0x03,
            Exception::ServerDeviceFailure => 0x04,
            Exception::Acknowledge => 0x05,
            Exception::ServerDeviceBusy => 0x06,
            Exception::GatewayPathUnavailable => 0x0a,
            Exception::GatewayTargetFailedToRespond => 0x0b,
            Exception::Other(c) => c,
        }
    }

    /// The exception for code `c`.
    pub fn from_code(c: u8) -> Exception {
        match c {
            0x01 => Exception::IllegalFunction,
            0x02 => Exception::IllegalDataAddress,
            0x03 => Exception::IllegalDataValue,
            0x04 => Exception::ServerDeviceFailure,
            0x05 => Exception::Acknowledge,
            0x06 => Exception::ServerDeviceBusy,
            0x0a => Exception::GatewayPathUnavailable,
            0x0b => Exception::GatewayTargetFailedToRespond,
            c => Exception::Other(c),
        }
    }

    /// The PDU that answers a request for `function` with this exception.
    pub fn to_pdu(self, function: u8) -> Vec<u8> {
        vec![function | function::EXCEPTION_FLAG, self.code()]
    }
}

impl std::fmt::Display for Exception {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Exception::IllegalFunction => "illegal function",
            Exception::IllegalDataAddress => "illegal data address",
            Exception::IllegalDataValue => "illegal data value",
            Exception::ServerDeviceFailure => "server device failure",
            Exception::Acknowledge => "acknowledge",
            Exception::ServerDeviceBusy => "server device busy",
            Exception::GatewayPathUnavailable => "gateway path unavailable",
            Exception::GatewayTargetFailedToRespond => "gateway target device failed to respond",
            Exception::Other(c) => return write!(f, "exception code {c}"),
        };
        f.write_str(name)
    }
}

impl std::error::Error for Exception {}

/// A request: what a client asks a server to do, read from a PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Request {
    /// Function 1: read `quantity` coils from `address`.
    ReadCoils { address: u16, quantity: u16 },
    /// Function 2: read `quantity` discrete inputs from `address`.
    ReadDiscreteInputs { address: u16, quantity: u16 },
    /// Function 3: read `quantity` holding registers from `address`.
    ReadHoldingRegisters { address: u16, quantity: u16 },
    /// Function 4: read `quantity` input registers from `address`.
    ReadInputRegisters { address: u16, quantity: u16 },
    /// Function 5: switch the coil at `address` on or off.
    WriteSingleCoil { address: u16, value: bool },
    /// Function 6: set the holding register at `address`.
    WriteSingleRegister { address: u16, value: u16 },
    /// Function 15: set coils from `address`, one per value.
    WriteMultipleCoils { address: u16, values: Vec<bool> },
    /// Function 16: set holding registers from `address`, one per value.
    WriteMultipleRegisters { address: u16, values: Vec<u16> },
    /// Any other function, with its data unread.
    Other { function: u8, data: Vec<u8> },
}

impl Request {
    /// Reads the request in `pdu`. A request that breaks the specification
    /// gives the exception a server answers it with: an empty PDU or a
    /// function code with the exception flag set is
    /// [`Exception::IllegalFunction`], and a bad length, quantity, byte
    /// count or coil value is [`Exception::IllegalDataValue`]. Whether an
    /// address exists is the server's business, so this never gives
    /// [`Exception::IllegalDataAddress`], except for a range that runs
    /// past the last address, 65535.
    pub fn parse(pdu: &[u8]) -> Result<Request, Exception> {
        let (&function, data) = pdu.split_first().ok_or(Exception::IllegalFunction)?;
        if function & function::EXCEPTION_FLAG != 0 || function == 0 {
            return Err(Exception::IllegalFunction);
        }
        let fixed = |n: usize| if data.len() == n { Ok(()) } else { Err(Exception::IllegalDataValue) };
        let read = |max: u16| -> Result<(u16, u16), Exception> {
            fixed(4)?;
            let (address, quantity) = (be16(data, 0), be16(data, 2));
            if quantity == 0 || quantity > max {
                return Err(Exception::IllegalDataValue);
            }
            in_range(address, quantity)?;
            Ok((address, quantity))
        };
        Ok(match function {
            function::READ_COILS => {
                let (address, quantity) = read(MAX_READ_BITS)?;
                Request::ReadCoils { address, quantity }
            }
            function::READ_DISCRETE_INPUTS => {
                let (address, quantity) = read(MAX_READ_BITS)?;
                Request::ReadDiscreteInputs { address, quantity }
            }
            function::READ_HOLDING_REGISTERS => {
                let (address, quantity) = read(MAX_READ_REGISTERS)?;
                Request::ReadHoldingRegisters { address, quantity }
            }
            function::READ_INPUT_REGISTERS => {
                let (address, quantity) = read(MAX_READ_REGISTERS)?;
                Request::ReadInputRegisters { address, quantity }
            }
            function::WRITE_SINGLE_COIL => {
                fixed(4)?;
                let value = match be16(data, 2) {
                    0xff00 => true,
                    0x0000 => false,
                    _ => return Err(Exception::IllegalDataValue),
                };
                Request::WriteSingleCoil { address: be16(data, 0), value }
            }
            function::WRITE_SINGLE_REGISTER => {
                fixed(4)?;
                Request::WriteSingleRegister { address: be16(data, 0), value: be16(data, 2) }
            }
            function::WRITE_MULTIPLE_COILS => {
                let (address, quantity, bytes) = multiple(data, MAX_WRITE_BITS, |q| usize::from(q).div_ceil(8))?;
                let values = (0..usize::from(quantity)).map(|i| bytes[i / 8] >> (i % 8) & 1 == 1).collect();
                Request::WriteMultipleCoils { address, values }
            }
            function::WRITE_MULTIPLE_REGISTERS => {
                let (address, quantity, bytes) = multiple(data, MAX_WRITE_REGISTERS, |q| 2 * usize::from(q))?;
                let values = (0..usize::from(quantity)).map(|i| be16(bytes, 2 * i)).collect();
                Request::WriteMultipleRegisters { address, values }
            }
            _ => Request::Other { function, data: data.to_vec() },
        })
    }

    /// The request's function code.
    pub fn function(&self) -> u8 {
        match self {
            Request::ReadCoils { .. } => function::READ_COILS,
            Request::ReadDiscreteInputs { .. } => function::READ_DISCRETE_INPUTS,
            Request::ReadHoldingRegisters { .. } => function::READ_HOLDING_REGISTERS,
            Request::ReadInputRegisters { .. } => function::READ_INPUT_REGISTERS,
            Request::WriteSingleCoil { .. } => function::WRITE_SINGLE_COIL,
            Request::WriteSingleRegister { .. } => function::WRITE_SINGLE_REGISTER,
            Request::WriteMultipleCoils { .. } => function::WRITE_MULTIPLE_COILS,
            Request::WriteMultipleRegisters { .. } => function::WRITE_MULTIPLE_REGISTERS,
            Request::Other { function, .. } => *function,
        }
    }

    /// The request's PDU, for a world that plays a client. Values past
    /// what one request may carry are left out, so the PDU always fits in
    /// a frame.
    pub fn to_pdu(&self) -> Vec<u8> {
        let mut out = vec![self.function()];
        match self {
            Request::ReadCoils { address, quantity }
            | Request::ReadDiscreteInputs { address, quantity }
            | Request::ReadHoldingRegisters { address, quantity }
            | Request::ReadInputRegisters { address, quantity } => {
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&quantity.to_be_bytes());
            }
            Request::WriteSingleCoil { address, value } => {
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(if *value { &[0xff, 0x00] } else { &[0x00, 0x00] });
            }
            Request::WriteSingleRegister { address, value } => {
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&value.to_be_bytes());
            }
            Request::WriteMultipleCoils { address, values } => {
                let values = &values[..values.len().min(usize::from(MAX_WRITE_BITS))];
                let bytes = pack_bits(values);
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&(values.len() as u16).to_be_bytes());
                out.push(bytes.len() as u8);
                out.extend_from_slice(&bytes);
            }
            Request::WriteMultipleRegisters { address, values } => {
                let values = &values[..values.len().min(usize::from(MAX_WRITE_REGISTERS))];
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&(values.len() as u16).to_be_bytes());
                out.push((2 * values.len()) as u8);
                for v in values {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            Request::Other { data, .. } => out.extend_from_slice(&data[..data.len().min(MAX_PDU - 1)]),
        }
        out
    }
}

/// A response: what a server answers, read from or written as a PDU. A
/// response to a read does not say how many coils were asked for, so
/// [`Response::Bits`] holds every bit of the bytes it carries, up to a
/// multiple of 8.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Response {
    /// To functions 1 and 2: the coils or inputs read, first address first.
    Bits(Vec<bool>),
    /// To functions 3 and 4: the registers read.
    Registers(Vec<u16>),
    /// To function 5: the request, echoed.
    WriteSingleCoil { address: u16, value: bool },
    /// To function 6: the request, echoed.
    WriteSingleRegister { address: u16, value: u16 },
    /// To functions 15 and 16: where the write started and how many it set.
    WriteMultiple { address: u16, quantity: u16 },
    /// The request failed.
    Exception(Exception),
    /// The response to any other function, with its data unread.
    Other(Vec<u8>),
}

/// Why a PDU is not a response this module can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseError;

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a well-formed Modbus response")
    }
}

impl std::error::Error for ResponseError {}

impl Response {
    /// Reads the response in `pdu`, and the function code it answers.
    pub fn parse(pdu: &[u8]) -> Result<(u8, Response), ResponseError> {
        let (&code, data) = pdu.split_first().ok_or(ResponseError)?;
        if code & function::EXCEPTION_FLAG != 0 {
            let [e] = data else { return Err(ResponseError) };
            return Ok((code & !function::EXCEPTION_FLAG, Response::Exception(Exception::from_code(*e))));
        }
        let counted = || -> Result<&[u8], ResponseError> {
            let (&n, rest) = data.split_first().ok_or(ResponseError)?;
            if rest.len() == usize::from(n) { Ok(rest) } else { Err(ResponseError) }
        };
        let pair = || if data.len() == 4 { Ok((be16(data, 0), be16(data, 2))) } else { Err(ResponseError) };
        let response = match code {
            function::READ_COILS | function::READ_DISCRETE_INPUTS => {
                let bytes = counted()?;
                Response::Bits((0..bytes.len() * 8).map(|i| bytes[i / 8] >> (i % 8) & 1 == 1).collect())
            }
            function::READ_HOLDING_REGISTERS | function::READ_INPUT_REGISTERS => {
                let bytes = counted()?;
                if bytes.len() % 2 != 0 {
                    return Err(ResponseError);
                }
                Response::Registers(bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect())
            }
            function::WRITE_SINGLE_COIL => {
                let (address, raw) = pair()?;
                let value = match raw {
                    0xff00 => true,
                    0x0000 => false,
                    _ => return Err(ResponseError),
                };
                Response::WriteSingleCoil { address, value }
            }
            function::WRITE_SINGLE_REGISTER => {
                let (address, value) = pair()?;
                Response::WriteSingleRegister { address, value }
            }
            function::WRITE_MULTIPLE_COILS | function::WRITE_MULTIPLE_REGISTERS => {
                let (address, quantity) = pair()?;
                Response::WriteMultiple { address, quantity }
            }
            _ => Response::Other(data.to_vec()),
        };
        Ok((code, response))
    }

    /// The PDU that answers a request for `function` with this response.
    /// Values past what one PDU can carry are left out.
    pub fn to_pdu(&self, function: u8) -> Vec<u8> {
        let mut out = vec![function];
        match self {
            Response::Bits(bits) => {
                let bytes = pack_bits(&bits[..bits.len().min(8 * (MAX_PDU - 2))]);
                out.push(bytes.len() as u8);
                out.extend_from_slice(&bytes);
            }
            Response::Registers(regs) => {
                let regs = &regs[..regs.len().min((MAX_PDU - 2) / 2)];
                out.push((2 * regs.len()) as u8);
                for r in regs {
                    out.extend_from_slice(&r.to_be_bytes());
                }
            }
            Response::WriteSingleCoil { address, value } => {
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(if *value { &[0xff, 0x00] } else { &[0x00, 0x00] });
            }
            Response::WriteSingleRegister { address, value } => {
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&value.to_be_bytes());
            }
            Response::WriteMultiple { address, quantity } => {
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&quantity.to_be_bytes());
            }
            Response::Exception(e) => return e.to_pdu(function),
            Response::Other(data) => out.extend_from_slice(&data[..data.len().min(MAX_PDU - 1)]),
        }
        out
    }
}

/// The address, quantity and value bytes of a write-multiple request,
/// checked: the quantity is in range, the byte count is what the quantity
/// needs, and the bytes are all there.
fn multiple(data: &[u8], max: u16, need: impl Fn(u16) -> usize) -> Result<(u16, u16, &[u8]), Exception> {
    if data.len() < 5 {
        return Err(Exception::IllegalDataValue);
    }
    let (address, quantity, count) = (be16(data, 0), be16(data, 2), usize::from(data[4]));
    if quantity == 0 || quantity > max || count != need(quantity) || data.len() != 5 + count {
        return Err(Exception::IllegalDataValue);
    }
    in_range(address, quantity)?;
    Ok((address, quantity, &data[5..]))
}

/// Whether `quantity` items from `address` stay within the 65536
/// addresses.
fn in_range(address: u16, quantity: u16) -> Result<(), Exception> {
    if u32::from(address) + u32::from(quantity) > 0x1_0000 { Err(Exception::IllegalDataAddress) } else { Ok(()) }
}

/// Bits packed into bytes, the first in the lowest bit of the first byte.
fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Examples from the Modbus Application Protocol Specification v1.1b3,
    // section 6.

    #[test]
    fn read_coils_example() {
        let req = Request::parse(&[0x01, 0x00, 0x13, 0x00, 0x13]).unwrap();
        assert_eq!(req, Request::ReadCoils { address: 0x13, quantity: 0x13 });
        let (f, resp) = Response::parse(&[0x01, 0x03, 0xcd, 0x6b, 0x05]).unwrap();
        assert_eq!(f, 1);
        let Response::Bits(bits) = resp else { panic!() };
        // Coils 20..27 are 0xCD, low bit first: on, off, on, on, off, off, on, on.
        assert_eq!(&bits[..8], &[true, false, true, true, false, false, true, true]);
    }

    #[test]
    fn read_holding_registers_example() {
        let req = Request::parse(&[0x03, 0x00, 0x6b, 0x00, 0x03]).unwrap();
        assert_eq!(req, Request::ReadHoldingRegisters { address: 0x6b, quantity: 3 });
        let pdu = Response::Registers(vec![0x022b, 0x0000, 0x0064]).to_pdu(3);
        assert_eq!(pdu, [0x03, 0x06, 0x02, 0x2b, 0x00, 0x00, 0x00, 0x64]);
        assert_eq!(Response::parse(&pdu).unwrap(), (3, Response::Registers(vec![0x022b, 0, 0x64])));
    }

    #[test]
    fn write_single_coil_example() {
        let pdu = [0x05, 0x00, 0xac, 0xff, 0x00];
        assert_eq!(Request::parse(&pdu).unwrap(), Request::WriteSingleCoil { address: 0xac, value: true });
        // The response echoes the request.
        assert_eq!(Response::WriteSingleCoil { address: 0xac, value: true }.to_pdu(5), pdu);
        // Any value but 0xFF00 or 0x0000 is refused.
        assert_eq!(Request::parse(&[0x05, 0x00, 0xac, 0x12, 0x34]), Err(Exception::IllegalDataValue));
    }

    #[test]
    fn write_multiple_coils_example() {
        let pdu = [0x0f, 0x00, 0x13, 0x00, 0x0a, 0x02, 0xcd, 0x01];
        let req = Request::parse(&pdu).unwrap();
        let Request::WriteMultipleCoils { address, values } = &req else { panic!() };
        assert_eq!(*address, 0x13);
        assert_eq!(values.len(), 10);
        assert_eq!(&values[..], &[true, false, true, true, false, false, true, true, true, false]);
        assert_eq!(req.to_pdu(), pdu);
        assert_eq!(Response::WriteMultiple { address: 0x13, quantity: 10 }.to_pdu(0x0f), [0x0f, 0, 0x13, 0, 0x0a]);
    }

    #[test]
    fn write_multiple_registers_example() {
        let pdu = [0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0a, 0x01, 0x02];
        let req = Request::parse(&pdu).unwrap();
        assert_eq!(req, Request::WriteMultipleRegisters { address: 1, values: vec![0x000a, 0x0102] });
        assert_eq!(req.to_pdu(), pdu);
    }

    #[test]
    fn bad_requests_get_the_right_exception() {
        assert_eq!(Request::parse(&[]), Err(Exception::IllegalFunction));
        assert_eq!(Request::parse(&[0x83, 0, 0, 0, 1]), Err(Exception::IllegalFunction));
        // Quantity 0 and quantity over the limit.
        assert_eq!(Request::parse(&[0x03, 0, 0, 0, 0]), Err(Exception::IllegalDataValue));
        assert_eq!(Request::parse(&[0x03, 0, 0, 0, 126]), Err(Exception::IllegalDataValue));
        assert_eq!(Request::parse(&[0x01, 0, 0, 0x07, 0xd1]), Err(Exception::IllegalDataValue));
        // A range past address 65535.
        assert_eq!(Request::parse(&[0x03, 0xff, 0xff, 0, 2]), Err(Exception::IllegalDataAddress));
        assert!(Request::parse(&[0x03, 0xff, 0xff, 0, 1]).is_ok());
        // Wrong lengths.
        assert_eq!(Request::parse(&[0x03, 0, 0, 0]), Err(Exception::IllegalDataValue));
        assert_eq!(Request::parse(&[0x06, 0, 0, 0, 0, 0]), Err(Exception::IllegalDataValue));
        // A byte count that does not match the quantity.
        assert_eq!(Request::parse(&[0x10, 0, 1, 0, 2, 3, 0, 0, 0]), Err(Exception::IllegalDataValue));
        assert_eq!(Request::parse(&[0x0f, 0, 0, 0, 9, 1, 0xff]), Err(Exception::IllegalDataValue));
        // Missing bytes after a correct count.
        assert_eq!(Request::parse(&[0x10, 0, 1, 0, 2, 4, 0, 0, 0]), Err(Exception::IllegalDataValue));
        // Functions this module does not read stay as they are.
        assert_eq!(Request::parse(&[0x2b, 0x0e, 1, 0]), Ok(Request::Other { function: 0x2b, data: vec![0x0e, 1, 0] }));
    }

    #[test]
    fn exceptions() {
        assert_eq!(Exception::IllegalDataAddress.to_pdu(3), [0x83, 0x02]);
        assert_eq!(Response::parse(&[0x83, 0x02]).unwrap(), (3, Response::Exception(Exception::IllegalDataAddress)));
        assert_eq!(Response::parse(&[0x83]), Err(ResponseError));
        for c in 0..=255u8 {
            assert_eq!(Exception::from_code(c).code(), c);
        }
    }

    #[test]
    fn frames() {
        let bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6b, 0x00, 0x03, 0xaa];
        let (frame, used) = Frame::parse(&bytes).unwrap().unwrap();
        assert_eq!(used, 12);
        assert_eq!(frame, Frame { transaction: 1, unit: 0x11, pdu: vec![0x03, 0x00, 0x6b, 0x00, 0x03] });
        assert_eq!(frame.to_bytes(), bytes[..12]);
        // Part of a frame.
        for n in 0..12 {
            assert_eq!(Frame::parse(&bytes[..n]), Ok(None), "{n} bytes");
        }
        // Not Modbus, known from the first four bytes.
        assert_eq!(Frame::parse(&[0, 1, 0, 5]), Err(FrameError::Protocol(5)));
        // Lengths out of range.
        assert_eq!(Frame::parse(&[0, 1, 0, 0, 0, 1, 1]), Err(FrameError::Length(1)));
        assert_eq!(Frame::parse(&[0, 1, 0, 0, 0, 255, 1]), Err(FrameError::Length(255)));
        assert!(matches!(Frame::parse(&[0, 1, 0, 0, 0, 254, 1]), Ok(None)));
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = Frame { transaction: 1, unit: 1, pdu: vec![3, 0, 0, 0, 1] }.to_bytes();
        let b = Frame { transaction: 2, unit: 1, pdu: vec![6, 0, 1, 0, 9] }.to_bytes();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Decoder::new();
        // One byte at a time.
        let mut got = Vec::new();
        for byte in &stream {
            d.feed(std::slice::from_ref(byte));
            while let Some(f) = d.next_frame() {
                got.push(f.unwrap().transaction);
            }
        }
        assert_eq!(got, [1, 2]);
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        d.feed(&[0, 3, 0, 9, 0, 6, 1, 3, 0, 0, 0, 1]);
        assert_eq!(d.next_frame(), Some(Err(FrameError::Protocol(9))));
        d.feed(&a);
        assert_eq!(d.next_frame(), Some(Err(FrameError::Protocol(9))));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_takes_many_small_frames_in_linear_time() {
        let one = Frame { transaction: 1, unit: 1, pdu: vec![3, 0, 0, 0, 1] }.to_bytes();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        d.feed(&stream);
        let mut n = 0;
        while let Some(f) = d.next_frame() {
            f.unwrap();
            n += 1;
        }
        assert_eq!(n, 200_000);
        assert_eq!(d.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn writers_cap_what_they_write() {
        let req = Request::WriteMultipleRegisters { address: 0, values: vec![1; 500] };
        let pdu = req.to_pdu();
        assert!(pdu.len() <= MAX_PDU);
        let Request::WriteMultipleRegisters { values, .. } = Request::parse(&pdu).unwrap() else { panic!() };
        assert_eq!(values.len(), usize::from(MAX_WRITE_REGISTERS));
        let resp = Response::Registers(vec![7; 500]).to_pdu(3);
        assert!(resp.len() <= MAX_PDU);
        assert!(Response::parse(&resp).is_ok());
        let frame = Frame { transaction: 0, unit: 0, pdu: vec![0; 1000] };
        assert_eq!(frame.to_bytes().len(), MAX_FRAME);
        assert!(Frame::parse(&frame.to_bytes()).unwrap().is_some());
    }
}
