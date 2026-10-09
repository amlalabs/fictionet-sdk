//! Modbus/TCP: reading and writing frames, requests and responses, with no
//! I/O.
//!
//! `Frame` implements `Wire` and supports `codec::Frames<Frame>`. Request and
//! response helpers interpret its PDU. There is no device session, `Service`,
//! register store, or live transport. The observe presenter is separate from
//! this wire layer.
//!
//! Modbus is how most industrial equipment is read and controlled: a PLC
//! holds coils (single bits it can switch) and registers (16-bit values),
//! and a client reads and writes them by address. Modbus/TCP carries each
//! message over a TCP connection, usually on port 502, behind a 7-byte
//! header (the MBAP header). This module follows the Modbus Application
//! Protocol Specification v1.1b3 and the Modbus Messaging on TCP/IP
//! Implementation Guide v1.0b.
//!
//! Nothing here reads a socket. A world that plays a PLC pushes bytes
//! from a [`tcp`](fictionet::stdlib::tcp) connection into a
//! [`Stream<codec::Frames<Frame>>`](fictionet::stdlib::codec::Stream), gets [`Frame`]s back, reads each one's [`Request`], and
//! writes the reply's bytes back to the connection. Which coils and
//! registers exist, and what they hold, is up to world code. So is whether
//! a write succeeds.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. A request that breaks the specification becomes an
//! [`Exception`] the world can send back, as a real device would. Writers
//! return an [`Error`] rather than write bytes a reader would refuse
//! or read back as something else.
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::modbus::{Exception, Frame, Request, Response};
//!
//! /// Holding registers 0 to 9 of a pretend tank controller.
//! fn answer(registers: &mut [u16; 10], frame: &Frame) -> Frame {
//!     let reply = match Request::parse(&frame.pdu) {
//!         Ok(Request::ReadHoldingRegisters { address, quantity }) => {
//!             let (a, n) = (usize::from(address), usize::from(quantity));
//!             match registers.get(a..a + n) {
//!                 // A read that parsed asks for 1 to 125 registers, which
//!                 // one response always holds.
//!                 Some(values) => Response::Registers(values.to_vec()).to_pdu(3).unwrap(),
//!                 None => Exception::IllegalDataAddress.to_pdu(3),
//!             }
//!         }
//!         Ok(Request::WriteSingleRegister { address, value }) => match registers.get_mut(usize::from(address)) {
//!             Some(r) => {
//!                 *r = value;
//!                 Response::WriteSingleRegister { address, value }.to_pdu(6).unwrap()
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
//! let mut decoder = Stream::new(Frames::<Frame>::new());
//! // Read 1 holding register at address 2, transaction 7, unit 1.
//! let bytes = [0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1];
//! assert_eq!(decoder.push(&bytes), bytes.len());
//! let frame = decoder.next().unwrap().unwrap();
//! let reply = answer(&mut registers, &frame);
//! assert_eq!(reply.to_bytes().unwrap(), [0, 7, 0, 0, 0, 5, 1, 3, 2, 0x04, 0xd2]);
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Wire, be16};

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
    /// The function code and its data: 1 to [`MAX_PDU`] bytes for
    /// [`Frame::to_bytes`] to write it.
    pub pdu: Vec<u8>,
}

/// Why bytes are not a Modbus/TCP frame or a response this module can
/// read, or why a writer refused a value: its bytes would break the
/// specification, or a reader would read them back as something else.
/// After an error from [`codec::Frames<Frame>`](fictionet::stdlib::codec::Frames) the connection holds no more frames a
/// reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A frame with an empty PDU, which has no function code.
    EmptyPdu,
    /// More bytes than one PDU holds, or more values than one request or
    /// response may carry.
    TooLong,
    /// A quantity, or a number of values, of 0 or more than the function
    /// allows.
    Quantity,
    /// A range of addresses that runs past the last one, 65535.
    Address,
    /// A function code that does not go with the value: 0, one with the
    /// exception flag set, a response the function does not answer with,
    /// or a code this module reads as a typed request or response given to
    /// an `Other` variant.
    Function(u8),
    /// The protocol identifier was not 0, so this is not Modbus.
    Protocol(u16),
    /// The length field was below 2 (a unit and a function code) or above
    /// what a frame may hold.
    Length(u16),
    /// The input ended before a complete frame, including empty input.
    Truncated,
    /// Bytes follow the first complete frame.
    Trailing,
    /// A PDU is not a response this module can read.
    BadResponse,
}

fictionet::error_display!(Error, f, {
    Error::EmptyPdu => f.write_str("a frame needs a PDU of at least a function code"),
    Error::TooLong => f.write_str("more than one Modbus PDU may carry"),
    Error::Quantity => f.write_str("a quantity outside what the function allows"),
    Error::Address => f.write_str("a range of addresses past 65535"),
    Error::Function(c) => write!(f, "function code {c} does not go with this value"),
    Error::Protocol(p) => write!(f, "protocol identifier {p}, not 0 (Modbus)"),
    Error::Length(n) => write!(f, "length field {n}, outside 2..=254"),
    Error::Truncated => f.write_str("input ended before a complete Modbus frame"),
    Error::Trailing => f.write_str("bytes follow the Modbus frame"),
    Error::BadResponse => f.write_str("not a well-formed Modbus response"),
});

impl Frame {
    /// Reads the frame at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the frame and how many bytes
    /// of `b` it took.
    pub fn parse_prefix(b: &[u8]) -> Result<Option<(Frame, usize)>, Error> {
        if b.len() < HEADER_LEN {
            // A bad protocol identifier is known before the rest comes.
            if b.len() >= 4 {
                let protocol = be16(b, 2).ok_or(Error::Truncated)?;
                if protocol != 0 {
                    return Err(Error::Protocol(protocol));
                }
            }
            return Ok(None);
        }
        let protocol = be16(b, 2).ok_or(Error::Truncated)?;
        if protocol != 0 {
            return Err(Error::Protocol(protocol));
        }
        let length = be16(b, 4).ok_or(Error::Truncated)?;
        if length < 2 || usize::from(length) > MAX_PDU + 1 {
            return Err(Error::Length(length));
        }
        let end = 6 + usize::from(length);
        if b.len() < end {
            return Ok(None);
        }
        let frame = Frame {
            transaction: be16(b, 0).ok_or(Error::Truncated)?,
            unit: b[6],
            pdu: b[HEADER_LEN..end].to_vec(),
        };
        Ok(Some((frame, end)))
    }

    /// The function code: the PDU's first byte. A frame read by
    /// [`Frame::parse_prefix`] always has one.
    pub fn function(&self) -> Option<u8> {
        self.pdu.first().copied()
    }

    /// A frame that answers this one with `pdu`, with the same transaction
    /// and unit.
    pub fn reply(&self, pdu: Vec<u8>) -> Frame {
        Frame {
            transaction: self.transaction,
            unit: self.unit,
            pdu,
        }
    }
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one frame. Returns [`Error::Truncated`] for
    /// incomplete input and [`Error::Trailing`] for trailing bytes.
    /// A nonzero protocol ID or length outside 2..=254 returns
    /// [`Error::Protocol`] or [`Error::Length`].
    fn parse(b: &[u8]) -> Result<Self, Error> {
        match Self::parse_prefix(b)? {
            Some((frame, used)) if used == b.len() => Ok(frame),
            Some(_) => Err(Error::Trailing),
            None => Err(Error::Truncated),
        }
    }

    /// Appends one frame. An empty PDU returns [`Error::EmptyPdu`];
    /// a PDU over [`MAX_PDU`] bytes returns [`Error::TooLong`].
    /// Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let pdu = &self.pdu[..];
        if pdu.is_empty() {
            return Err(Error::EmptyPdu);
        }
        if pdu.len() > MAX_PDU {
            return Err(Error::TooLong);
        }
        out.extend_from_slice(&self.transaction.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(pdu.len() as u16 + 1).to_be_bytes());
        out.push(self.unit);
        out.extend_from_slice(pdu);
        Ok(())
    }
}

fictionet::prefixed! {
    /// Reads Modbus/TCP frames without holding input bytes.
    ///
    /// Use with [`codec::Stream`](fictionet::stdlib::codec::Stream) for a buffer limited
    /// to [`MAX_FRAME`]. Partial frames return [`fictionet::stdlib::codec::Step::Need`], including at
    /// EOF. The stream reports truncation at EOF and framing errors once.
    /// Each item's PDU is bounded by [`MAX_PDU`].
    ///
    /// ```
    /// use fictionet::stdlib::codec::Frames;
    /// use fictionet::stdlib::codec::{Decode, Stream, finish, pump};
    /// use fictionet::stdlib::modbus::Request;
    ///
    /// let mut requests = Stream::new(Frames::<fictionet::stdlib::modbus::Frame>::new().map(|frame| Request::parse(&frame.pdu)));
    /// let bytes = [0, 7, 0, 0, 0, 6, 1, 3, 0, 2, 0, 1];
    /// let mut count = 0;
    /// pump(&mut requests, &bytes, |request| {
    ///     assert_eq!(request, Ok(Request::ReadHoldingRegisters { address: 2, quantity: 1 }));
    ///     count += 1;
    /// })?;
    /// finish(&mut requests, |_| unreachable!())?;
    /// assert_eq!(count, 1);
    /// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::modbus::Error>>(())
    /// ```
    Frame => (Frame, Error, ());
    name = "Modbus/TCP";
    default {}
    capacity(_limit) { MAX_FRAME }

    /// Reads one frame. A nonzero protocol ID returns [`Error::Protocol`].
    /// A length outside 2..=254 returns [`Error::Length`]. Partial input
    /// returns [`fictionet::stdlib::codec::Step::Need`], including at EOF.
    #[inline]
    fn parse_prefix(
        input: &[u8],
        _limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        Frame::parse_prefix(input)
    }
}

/// The exception codes a server answers with when it cannot do what a
/// request asks. Two exceptions are equal when their codes are, so
/// `Other(1)` equals `IllegalFunction`, as it reads back.
#[derive(Clone, Copy, Debug, Eq)]
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

impl PartialEq for Exception {
    fn eq(&self, other: &Exception) -> bool {
        self.code() == other.code()
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
    /// past the last address, 65535. A PDU longer than [`MAX_PDU`] is
    /// [`Exception::IllegalDataValue`].
    pub fn parse(pdu: &[u8]) -> Result<Request, Exception> {
        let (&function, data) = pdu.split_first().ok_or(Exception::IllegalFunction)?;
        if function & function::EXCEPTION_FLAG != 0 || function == 0 {
            return Err(Exception::IllegalFunction);
        }
        if pdu.len() > MAX_PDU {
            return Err(Exception::IllegalDataValue);
        }
        let fixed = |n: usize| {
            if data.len() == n {
                Ok(())
            } else {
                Err(Exception::IllegalDataValue)
            }
        };
        let read = |max: u16| -> Result<(u16, u16), Exception> {
            fixed(4)?;
            let (address, quantity) = (
                be16(data, 0).ok_or(Exception::IllegalDataValue)?,
                be16(data, 2).ok_or(Exception::IllegalDataValue)?,
            );
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
                let value = match be16(data, 2).ok_or(Exception::IllegalDataValue)? {
                    0xff00 => true,
                    0x0000 => false,
                    _ => return Err(Exception::IllegalDataValue),
                };
                Request::WriteSingleCoil {
                    address: be16(data, 0).ok_or(Exception::IllegalDataValue)?,
                    value,
                }
            }
            function::WRITE_SINGLE_REGISTER => {
                fixed(4)?;
                Request::WriteSingleRegister {
                    address: be16(data, 0).ok_or(Exception::IllegalDataValue)?,
                    value: be16(data, 2).ok_or(Exception::IllegalDataValue)?,
                }
            }
            function::WRITE_MULTIPLE_COILS => {
                let (address, quantity, bytes) =
                    multiple(data, MAX_WRITE_BITS, |q| usize::from(q).div_ceil(8))?;
                let values = (0..usize::from(quantity))
                    .map(|i| bytes[i / 8] >> (i % 8) & 1 == 1)
                    .collect();
                Request::WriteMultipleCoils { address, values }
            }
            function::WRITE_MULTIPLE_REGISTERS => {
                let (address, quantity, bytes) =
                    multiple(data, MAX_WRITE_REGISTERS, |q| 2 * usize::from(q))?;
                let values = (0..usize::from(quantity))
                    .map(|i| be16(bytes, 2 * i).ok_or(Exception::IllegalDataValue))
                    .collect::<Result<_, _>>()?;
                Request::WriteMultipleRegisters { address, values }
            }
            _ => Request::Other {
                function,
                data: data.to_vec(),
            },
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

    /// The request's PDU, for a world that plays a client. A request
    /// [`Request::parse`] would refuse, or read back as another request,
    /// is an error: a quantity or number of values of 0 or over the
    /// function's limit, a range past address 65535, or an
    /// [`Request::Other`] with a function code this module reads, 0, the
    /// exception flag, or more data than a PDU holds.
    pub fn to_pdu(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![self.function()];
        match self {
            Request::ReadCoils { address, quantity }
            | Request::ReadDiscreteInputs { address, quantity } => {
                check_quantity(*address, usize::from(*quantity), MAX_READ_BITS)?;
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&quantity.to_be_bytes());
            }
            Request::ReadHoldingRegisters { address, quantity }
            | Request::ReadInputRegisters { address, quantity } => {
                check_quantity(*address, usize::from(*quantity), MAX_READ_REGISTERS)?;
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
                let n = check_quantity(*address, values.len(), MAX_WRITE_BITS)?;
                let bytes = pack_bits(values);
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&n.to_be_bytes());
                out.push(bytes.len() as u8);
                out.extend_from_slice(&bytes);
            }
            Request::WriteMultipleRegisters { address, values } => {
                let n = check_quantity(*address, values.len(), MAX_WRITE_REGISTERS)?;
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&n.to_be_bytes());
                out.push((2 * values.len()) as u8);
                for v in values {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            Request::Other { function, data } => {
                check_other(*function)?;
                if data.len() > MAX_PDU - 1 {
                    return Err(Error::TooLong);
                }
                out.extend_from_slice(data);
            }
        }
        Ok(out)
    }
}

/// A response: what a server answers, read from or written as a PDU. A
/// response to a read does not say how many coils were asked for, so
/// [`Response::Bits`] read from a PDU holds every bit of the bytes it
/// carries, up to a multiple of 8; the bits past the quantity asked for
/// are padding, which the specification fills with zeros.
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

impl Response {
    /// Reads the response in `pdu`, and the function code it answers. A
    /// PDU longer than [`MAX_PDU`], function code 0, or a count, quantity
    /// or range the specification does not allow for the function is an
    /// error.
    pub fn parse(pdu: &[u8]) -> Result<(u8, Response), Error> {
        if pdu.len() > MAX_PDU {
            return Err(Error::BadResponse);
        }
        let (&code, data) = pdu.split_first().ok_or(Error::BadResponse)?;
        if code & function::EXCEPTION_FLAG != 0 {
            let [e] = data else {
                return Err(Error::BadResponse);
            };
            return Ok((
                code & !function::EXCEPTION_FLAG,
                Response::Exception(Exception::from_code(*e)),
            ));
        }
        // A read's byte count: 1 to 250, which is 2000 bits or 125
        // registers.
        let counted = || -> Result<&[u8], Error> {
            let (&n, rest) = data.split_first().ok_or(Error::BadResponse)?;
            if n == 0 || usize::from(n) > MAX_READ_BYTES || rest.len() != usize::from(n) {
                return Err(Error::BadResponse);
            }
            Ok(rest)
        };
        let pair = || {
            if data.len() == 4 {
                Ok((
                    be16(data, 0).ok_or(Error::Truncated)?,
                    be16(data, 2).ok_or(Error::Truncated)?,
                ))
            } else {
                Err(Error::BadResponse)
            }
        };
        let response = match code {
            0 => return Err(Error::BadResponse),
            function::READ_COILS | function::READ_DISCRETE_INPUTS => {
                let bytes = counted()?;
                Response::Bits(
                    (0..bytes.len() * 8)
                        .map(|i| bytes[i / 8] >> (i % 8) & 1 == 1)
                        .collect(),
                )
            }
            function::READ_HOLDING_REGISTERS | function::READ_INPUT_REGISTERS => {
                let bytes = counted()?;
                if bytes.len() % 2 != 0 {
                    return Err(Error::BadResponse);
                }
                Response::Registers(
                    bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect(),
                )
            }
            function::WRITE_SINGLE_COIL => {
                let (address, raw) = pair()?;
                let value = match raw {
                    0xff00 => true,
                    0x0000 => false,
                    _ => return Err(Error::BadResponse),
                };
                Response::WriteSingleCoil { address, value }
            }
            function::WRITE_SINGLE_REGISTER => {
                let (address, value) = pair()?;
                Response::WriteSingleRegister { address, value }
            }
            function::WRITE_MULTIPLE_COILS | function::WRITE_MULTIPLE_REGISTERS => {
                let (address, quantity) = pair()?;
                let max = if code == function::WRITE_MULTIPLE_COILS {
                    MAX_WRITE_BITS
                } else {
                    MAX_WRITE_REGISTERS
                };
                check_quantity(address, usize::from(quantity), max)
                    .map_err(|_| Error::BadResponse)?;
                Response::WriteMultiple { address, quantity }
            }
            _ => Response::Other(data.to_vec()),
        };
        Ok((code, response))
    }

    /// The PDU that answers a request for `function` with this response.
    /// A response [`Response::parse`] would refuse, or read back as
    /// another response, is an error: `function` must be one the response
    /// answers ([`Response::Other`] takes any code this module does not
    /// read but 0), with 1 to 2000 bits, 1 to 125 registers, or a
    /// quantity and range a write may have. An exception can answer any
    /// function and is never an error.
    pub fn to_pdu(&self, function: u8) -> Result<Vec<u8>, Error> {
        let wrong = Err(Error::Function(function));
        let mut out = vec![function];
        match self {
            Response::Bits(bits) => {
                if !matches!(
                    function,
                    function::READ_COILS | function::READ_DISCRETE_INPUTS
                ) {
                    return wrong;
                }
                if bits.is_empty() || bits.len() > usize::from(MAX_READ_BITS) {
                    return Err(Error::Quantity);
                }
                let bytes = pack_bits(bits);
                out.push(bytes.len() as u8);
                out.extend_from_slice(&bytes);
            }
            Response::Registers(regs) => {
                if !matches!(
                    function,
                    function::READ_HOLDING_REGISTERS | function::READ_INPUT_REGISTERS
                ) {
                    return wrong;
                }
                if regs.is_empty() || regs.len() > usize::from(MAX_READ_REGISTERS) {
                    return Err(Error::Quantity);
                }
                out.push((2 * regs.len()) as u8);
                for r in regs {
                    out.extend_from_slice(&r.to_be_bytes());
                }
            }
            Response::WriteSingleCoil { address, value } => {
                if function != function::WRITE_SINGLE_COIL {
                    return wrong;
                }
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(if *value { &[0xff, 0x00] } else { &[0x00, 0x00] });
            }
            Response::WriteSingleRegister { address, value } => {
                if function != function::WRITE_SINGLE_REGISTER {
                    return wrong;
                }
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&value.to_be_bytes());
            }
            Response::WriteMultiple { address, quantity } => {
                let max = match function {
                    function::WRITE_MULTIPLE_COILS => MAX_WRITE_BITS,
                    function::WRITE_MULTIPLE_REGISTERS => MAX_WRITE_REGISTERS,
                    _ => return wrong,
                };
                check_quantity(*address, usize::from(*quantity), max)?;
                out.extend_from_slice(&address.to_be_bytes());
                out.extend_from_slice(&quantity.to_be_bytes());
            }
            Response::Exception(e) => return Ok(e.to_pdu(function)),
            Response::Other(data) => {
                check_other(function)?;
                if data.len() > MAX_PDU - 1 {
                    return Err(Error::TooLong);
                }
                out.extend_from_slice(data);
            }
        }
        Ok(out)
    }
}

/// The most bytes of coils or registers a read's response carries.
const MAX_READ_BYTES: usize = 250;

/// Checks `n` items from `address` against a function's limit, and gives
/// `n` as the quantity a PDU carries.
fn check_quantity(address: u16, n: usize, max: u16) -> Result<u16, Error> {
    let quantity = match u16::try_from(n) {
        Ok(q) if q != 0 && q <= max => q,
        _ => return Err(Error::Quantity),
    };
    in_range(address, quantity).map_err(|_| Error::Address)?;
    Ok(quantity)
}

/// Checks a function code an `Other` request or response is written with:
/// not 0, without the exception flag, and not one this module reads as a
/// typed value.
fn check_other(function: u8) -> Result<(), Error> {
    let known = matches!(
        function,
        function::READ_COILS
            | function::READ_DISCRETE_INPUTS
            | function::READ_HOLDING_REGISTERS
            | function::READ_INPUT_REGISTERS
            | function::WRITE_SINGLE_COIL
            | function::WRITE_SINGLE_REGISTER
            | function::WRITE_MULTIPLE_COILS
            | function::WRITE_MULTIPLE_REGISTERS
    );
    if known || function == 0 || function & function::EXCEPTION_FLAG != 0 {
        Err(Error::Function(function))
    } else {
        Ok(())
    }
}

/// The address, quantity and value bytes of a write-multiple request,
/// checked: the quantity is in range, the byte count is what the quantity
/// needs, and the bytes are all there.
fn multiple(
    data: &[u8],
    max: u16,
    need: impl Fn(u16) -> usize,
) -> Result<(u16, u16, &[u8]), Exception> {
    if data.len() < 5 {
        return Err(Exception::IllegalDataValue);
    }
    let (address, quantity, count) = (
        be16(data, 0).ok_or(Exception::IllegalDataValue)?,
        be16(data, 2).ok_or(Exception::IllegalDataValue)?,
        usize::from(data[4]),
    );
    if quantity == 0 || quantity > max || count != need(quantity) || data.len() != 5 + count {
        return Err(Exception::IllegalDataValue);
    }
    in_range(address, quantity)?;
    Ok((address, quantity, &data[5..]))
}

/// Whether `quantity` items from `address` stay within the 65536
/// addresses.
fn in_range(address: u16, quantity: u16) -> Result<(), Exception> {
    if u32::from(address) + u32::from(quantity) > 0x1_0000 {
        Err(Exception::IllegalDataAddress)
    } else {
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Decode, Step};
    use fictionet::stdlib::codec::{Fail, Stream, finish, pump, try_pump};
    use fictionet::stdlib::test_support;
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{assert_linear, rounds};

    // Examples from the Modbus Application Protocol Specification v1.1b3,
    // section 6.

    #[test]
    fn read_coils_example() {
        let req = Request::parse(&[0x01, 0x00, 0x13, 0x00, 0x13]).unwrap();
        assert_eq!(
            req,
            Request::ReadCoils {
                address: 0x13,
                quantity: 0x13
            }
        );
        let (f, resp) = Response::parse(&[0x01, 0x03, 0xcd, 0x6b, 0x05]).unwrap();
        assert_eq!(f, 1);
        let Response::Bits(bits) = resp else { panic!() };
        // Coils 20..27 are 0xCD, low bit first: on, off, on, on, off, off, on, on.
        assert_eq!(
            &bits[..8],
            &[true, false, true, true, false, false, true, true]
        );
    }

    #[test]
    fn read_holding_registers_example() {
        let req = Request::parse(&[0x03, 0x00, 0x6b, 0x00, 0x03]).unwrap();
        assert_eq!(
            req,
            Request::ReadHoldingRegisters {
                address: 0x6b,
                quantity: 3
            }
        );
        let pdu = Response::Registers(vec![0x022b, 0x0000, 0x0064])
            .to_pdu(3)
            .unwrap();
        assert_eq!(pdu, [0x03, 0x06, 0x02, 0x2b, 0x00, 0x00, 0x00, 0x64]);
        assert_eq!(
            Response::parse(&pdu).unwrap(),
            (3, Response::Registers(vec![0x022b, 0, 0x64]))
        );
    }

    #[test]
    fn write_single_coil_example() {
        let pdu = [0x05, 0x00, 0xac, 0xff, 0x00];
        assert_eq!(
            Request::parse(&pdu).unwrap(),
            Request::WriteSingleCoil {
                address: 0xac,
                value: true
            }
        );
        // The response echoes the request.
        assert_eq!(
            Response::WriteSingleCoil {
                address: 0xac,
                value: true
            }
            .to_pdu(5)
            .unwrap(),
            pdu
        );
        // Any value but 0xFF00 or 0x0000 is refused.
        assert_eq!(
            Request::parse(&[0x05, 0x00, 0xac, 0x12, 0x34]),
            Err(Exception::IllegalDataValue)
        );
    }

    #[test]
    fn write_multiple_coils_example() {
        let pdu = [0x0f, 0x00, 0x13, 0x00, 0x0a, 0x02, 0xcd, 0x01];
        let req = Request::parse(&pdu).unwrap();
        let Request::WriteMultipleCoils { address, values } = &req else {
            panic!()
        };
        assert_eq!(*address, 0x13);
        assert_eq!(values.len(), 10);
        assert_eq!(
            &values[..],
            &[
                true, false, true, true, false, false, true, true, true, false
            ]
        );
        assert_eq!(req.to_pdu().unwrap(), pdu);
        assert_eq!(
            Response::WriteMultiple {
                address: 0x13,
                quantity: 10
            }
            .to_pdu(0x0f)
            .unwrap(),
            [0x0f, 0, 0x13, 0, 0x0a]
        );
    }

    #[test]
    fn write_multiple_registers_example() {
        let pdu = [0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x0a, 0x01, 0x02];
        let req = Request::parse(&pdu).unwrap();
        assert_eq!(
            req,
            Request::WriteMultipleRegisters {
                address: 1,
                values: vec![0x000a, 0x0102]
            }
        );
        assert_eq!(req.to_pdu().unwrap(), pdu);
    }

    #[test]
    fn bad_requests_get_the_right_exception() {
        fictionet::assert_cases!(Request::parse;
            (&[]) => Err(Exception::IllegalFunction),
            (&[0x83, 0, 0, 0, 1]) => Err(Exception::IllegalFunction),
            // Quantity 0 and quantity over the limit.
            (&[0x03, 0, 0, 0, 0]) => Err(Exception::IllegalDataValue),
            (&[0x03, 0, 0, 0, 126]) => Err(Exception::IllegalDataValue),
            (&[0x01, 0, 0, 0x07, 0xd1]) => Err(Exception::IllegalDataValue),
            // A range past address 65535.
            (&[0x03, 0xff, 0xff, 0, 2]) => Err(Exception::IllegalDataAddress),
        );
        assert!(Request::parse(&[0x03, 0xff, 0xff, 0, 1]).is_ok());
        // Wrong lengths.
        fictionet::assert_cases!(Request::parse;
            (&[0x03, 0, 0, 0]) => Err(Exception::IllegalDataValue),
            (&[0x06, 0, 0, 0, 0, 0]) => Err(Exception::IllegalDataValue),
            // A byte count that does not match the quantity.
            (&[0x10, 0, 1, 0, 2, 3, 0, 0, 0]) => Err(Exception::IllegalDataValue),
            (&[0x0f, 0, 0, 0, 9, 1, 0xff]) => Err(Exception::IllegalDataValue),
            // Missing bytes after a correct count.
            (&[0x10, 0, 1, 0, 2, 4, 0, 0, 0]) => Err(Exception::IllegalDataValue),
            // Functions this module does not read stay as they are.
            (&[0x2b, 0x0e, 1, 0]) => Ok(Request::Other { function: 0x2b, data: vec![0x0e, 1, 0] }),
        );
    }

    #[test]
    fn exceptions() {
        assert_eq!(Exception::IllegalDataAddress.to_pdu(3), [0x83, 0x02]);
        assert_eq!(
            Response::parse(&[0x83, 0x02]).unwrap(),
            (3, Response::Exception(Exception::IllegalDataAddress))
        );
        assert_eq!(Response::parse(&[0x83]), Err(Error::BadResponse));
        for c in 0..=255u8 {
            assert_eq!(Exception::from_code(c).code(), c);
        }
    }

    #[test]
    fn frames() {
        let bytes = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6b, 0x00, 0x03, 0xaa,
        ];
        let (frame, used) = Frame::parse_prefix(&bytes).unwrap().unwrap();
        assert_eq!(used, 12);
        assert_eq!(
            frame,
            Frame {
                transaction: 1,
                unit: 0x11,
                pdu: vec![0x03, 0x00, 0x6b, 0x00, 0x03]
            }
        );
        assert_eq!(frame.to_bytes().unwrap(), bytes[..12]);
        // Part of a frame.
        for n in 0..12 {
            assert_eq!(Frame::parse_prefix(&bytes[..n]), Ok(None), "{n} bytes");
        }
        // Not Modbus, known from the first four bytes.
        assert_eq!(Frame::parse_prefix(&[0, 1, 0, 5]), Err(Error::Protocol(5)));
        // Lengths out of range.
        assert_eq!(
            Frame::parse_prefix(&[0, 1, 0, 0, 0, 1, 1]),
            Err(Error::Length(1))
        );
        assert_eq!(
            Frame::parse_prefix(&[0, 1, 0, 0, 0, 255, 1]),
            Err(Error::Length(255))
        );
        assert!(matches!(
            Frame::parse_prefix(&[0, 1, 0, 0, 0, 254, 1]),
            Ok(None)
        ));
    }

    #[test]
    fn wire_requires_exactly_one_frame() {
        for length in [1, MAX_PDU] {
            let frame = Frame {
                transaction: u16::MAX,
                unit: u8::MAX,
                pdu: vec![0x41; length],
            };
            let bytes = frame.to_bytes().unwrap();
            assert_eq!(<Frame as Wire>::parse(&bytes), Ok(frame.clone()));
            contract::check_wire::<Frame>(&bytes);
            for cut in 0..bytes.len() {
                let prefix = bytes.get(..cut).unwrap();
                assert_eq!(<Frame as Wire>::parse(prefix), Err(Error::Truncated));
                assert_eq!(Frame::parse_prefix(prefix), Ok(None));
            }
            for suffix in [&[0][..], bytes.as_slice()] {
                let mut trailing = bytes.clone();
                trailing.extend_from_slice(suffix);
                assert_eq!(<Frame as Wire>::parse(&trailing), Err(Error::Trailing));
                assert_eq!(
                    Frame::parse_prefix(&trailing),
                    Ok(Some((frame.clone(), bytes.len())))
                );
            }
        }
        for (bytes, error) in [
            (&[0, 1, 0, 5][..], Error::Protocol(5)),
            (&[0, 1, 0, 0, 0, 1, 1][..], Error::Length(1)),
            (&[0, 1, 0, 0, 0xff, 0xff, 1][..], Error::Length(u16::MAX)),
        ] {
            assert_eq!(<Frame as Wire>::parse(bytes), Err(error));
        }
    }

    #[test]
    fn wire_appends_or_leaves_the_destination_unchanged() {
        for length in [0, 1, MAX_PDU, MAX_PDU + 1] {
            let frame = Frame {
                transaction: 7,
                unit: 1,
                pdu: vec![0x41; length],
            };
            contract::check_wire_value(&frame);
            let prefix = [0x12, 0x34];
            let mut out = prefix.to_vec();
            let result = frame.write(&mut out);
            match length {
                0 => assert_eq!(result, Err(Error::EmptyPdu)),
                n if n > MAX_PDU => assert_eq!(result, Err(Error::TooLong)),
                _ => {
                    assert_eq!(result, Ok(()));
                    assert_eq!(out.get(..prefix.len()), Some(prefix.as_slice()));
                    let bytes = out.get(prefix.len()..).unwrap();
                    assert!(bytes.len() <= MAX_FRAME);
                    assert_eq!(bytes, frame.to_bytes().unwrap());
                    assert_eq!(bytes, <Frame as Wire>::to_bytes(&frame).unwrap());
                    assert_eq!(<Frame as Wire>::parse(bytes), Ok(frame));
                    continue;
                }
            }
            assert_eq!(out, prefix);
        }
    }

    #[test]
    fn codec_frames_bound_input_and_preserve_ranges() {
        let frames = [
            Frame {
                transaction: 1,
                unit: 1,
                pdu: vec![0x41; MAX_PDU],
            },
            Frame {
                transaction: 2,
                unit: 1,
                pdu: vec![0x41],
            },
            Frame {
                transaction: 3,
                unit: 1,
                pdu: vec![0x42; MAX_PDU],
            },
        ];
        let mut bytes = Vec::new();
        for frame in &frames {
            frame.write(&mut bytes).unwrap();
        }
        assert_eq!(Frames::<Frame>::new().capacity(), MAX_FRAME);
        assert_eq!(Frames::<Frame>::new().held(), 0);
        contract::check_decode(Frames::<Frame>::new, &bytes);
        for sizes in [&[][..], &[1][..], &[7, 1, MAX_FRAME][..]] {
            let mut stream = Stream::new(Frames::<Frame>::new());
            let mut expected = frames.iter();
            let mut offset = 0;
            for chunk in test_support::chunks(&bytes, sizes) {
                let mut rest = chunk;
                while !rest.is_empty() {
                    let accepted = stream.push(rest);
                    assert!(accepted > 0);
                    rest = rest.get(accepted..).unwrap();
                    assert!(stream.buffered() <= MAX_FRAME);
                    while let Some(result) = stream.with_next(|frame, raw, range| {
                        assert_eq!(Some(&frame), expected.next());
                        assert_eq!(raw, frame.to_bytes().unwrap());
                        assert_eq!(range, offset..offset + raw.len() as u64);
                        offset = range.end;
                    }) {
                        result.unwrap();
                    }
                }
            }
            finish(&mut stream, |_| panic!("unexpected frame at EOF")).unwrap();
            assert!(expected.next().is_none());
            assert_eq!(stream.offset(), bytes.len() as u64);
            assert_eq!(stream.buffered(), 0);
            assert!(stream.is_done());
            assert_eq!(stream.failed(), None);
        }
        let mut stream = Stream::new(Frames::<Frame>::new());
        assert_eq!(stream.push(&bytes), MAX_FRAME);
        assert_eq!(stream.push(&[0]), 0);
        assert_eq!(stream.next(), Some(Ok(frames.first().unwrap().clone())));
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.push(&[0]), 1);
    }

    #[test]
    fn codec_frames_report_truncation_and_framing_errors_once() {
        let frame = Frame {
            transaction: 1,
            unit: 1,
            pdu: vec![0x41; MAX_PDU],
        };
        let bytes = frame.to_bytes().unwrap();
        // Include every prefix of a maximum frame, beyond the harness's 256-byte cutoff.
        for cut in 0..bytes.len() {
            let prefix = bytes.get(..cut).unwrap();
            assert_eq!(Frames::<Frame>::new().decode(prefix, false), Ok(Step::Need));
            assert_eq!(Frames::<Frame>::new().decode(prefix, true), Ok(Step::Need));
            let mut stream = Stream::new(Frames::<Frame>::new());
            assert_eq!(stream.push(prefix), cut);
            stream.end();
            let failure = (cut > 0).then_some(Fail::Truncated { unread: cut });
            assert_eq!(stream.next(), failure.clone().map(Err));
            assert_eq!(stream.next(), None);
            assert_eq!(stream.failed(), failure.as_ref());
            assert!(stream.is_done());
        }
        assert_eq!(
            Frames::<Frame>::new().decode(&bytes, true),
            Ok(Step::Item(frame, bytes.len()))
        );
        for (bad, error) in [
            (&[0, 1, 0, 5][..], Error::Protocol(5)),
            (&[0, 1, 0, 0, 0, 0, 1][..], Error::Length(0)),
            (&[0, 1, 0, 0, 0, 1, 1][..], Error::Length(1)),
            (&[0, 1, 0, 0, 0, 255, 1][..], Error::Length(255)),
        ] {
            contract::check_decode(Frames::<Frame>::new, bad);
            let mut stream = Stream::new(Frames::<Frame>::new());
            assert_eq!(stream.push(bad), bad.len());
            assert_eq!(stream.next(), Some(Err(Fail::Protocol(error))));
            assert_eq!(stream.next(), None);
            assert_eq!(stream.failed(), Some(&Fail::Protocol(error)));
            assert_eq!(stream.unread(), bad);
            assert_eq!(stream.push(&bytes), bytes.len());
            assert_eq!(stream.unread(), bad);
            assert_eq!(stream.next(), None);
        }
    }

    #[test]
    fn codec_stack_serves_registers_and_exceptions_end_to_end() {
        const MAX_TEST_FRAMES: usize = 5;
        const MAX_TEST_BYTES: usize = MAX_TEST_FRAMES * MAX_FRAME;
        let requests = [
            (
                7,
                Request::WriteSingleRegister {
                    address: 2,
                    value: 1234,
                }
                .to_pdu()
                .unwrap(),
            ),
            (
                8,
                Request::ReadHoldingRegisters {
                    address: 2,
                    quantity: 1,
                }
                .to_pdu()
                .unwrap(),
            ),
            (9, vec![3, 0, 2, 0, 0]), // Zero quantity gets a wire exception.
            (
                10,
                Request::ReadHoldingRegisters {
                    address: 10,
                    quantity: 1,
                }
                .to_pdu()
                .unwrap(),
            ),
            (
                11,
                Request::ReadHoldingRegisters {
                    address: 2,
                    quantity: 1,
                }
                .to_pdu()
                .unwrap(),
            ),
        ];
        let mut input = Vec::new();
        for (transaction, pdu) in requests {
            Frame {
                transaction,
                unit: 17,
                pdu,
            }
            .write(&mut input)
            .unwrap();
        }
        let expected = [
            (
                7,
                17,
                Ok((
                    6,
                    Response::WriteSingleRegister {
                        address: 2,
                        value: 1234,
                    },
                )),
            ),
            (8, 17, Ok((3, Response::Registers(vec![1234])))),
            (
                9,
                17,
                Ok((3, Response::Exception(Exception::IllegalDataValue))),
            ),
            (
                10,
                17,
                Ok((3, Response::Exception(Exception::IllegalDataAddress))),
            ),
            (11, 17, Ok((3, Response::Registers(vec![1234])))),
        ];
        let make_requests = || {
            Frames::<Frame>::new().map(|frame| {
                let request = Request::parse(&frame.pdu);
                (frame, request)
            })
        };
        contract::check_decode(make_requests, &input);
        for sizes in [&[][..], &[1][..], &[7, 1, 13][..]] {
            let mut registers = [0u16; 10];
            let mut server = Stream::new(make_requests());
            let mut output = Vec::new();
            for chunk in test_support::chunks(&input, sizes) {
                let accepted = try_pump(&mut server, chunk, |(frame, request)| {
                    let response = match request {
                        Ok(Request::WriteSingleRegister { address, value }) => {
                            match registers.get_mut(usize::from(address)) {
                                Some(register) => {
                                    *register = value;
                                    Response::WriteSingleRegister { address, value }
                                }
                                None => Response::Exception(Exception::IllegalDataAddress),
                            }
                        }
                        Ok(Request::ReadHoldingRegisters { address, quantity }) => {
                            let start = usize::from(address);
                            match start
                                .checked_add(usize::from(quantity))
                                .and_then(|end| registers.get(start..end))
                            {
                                Some(values) => Response::Registers(values.to_vec()),
                                None => Response::Exception(Exception::IllegalDataAddress),
                            }
                        }
                        Ok(_) => Response::Exception(Exception::IllegalFunction),
                        Err(e) => Response::Exception(e),
                    };
                    let pdu = response.to_pdu(frame.function().unwrap_or(0))?;
                    assert!(output.len() <= MAX_TEST_BYTES - MAX_FRAME);
                    frame.reply(pdu).write(&mut output)
                })
                .unwrap();
                assert_eq!(accepted, chunk.len());
            }
            finish(&mut server, |_| panic!("unexpected request at EOF")).unwrap();
            assert_eq!(registers.get(2), Some(&1234));
            let mut client = Stream::new(
                Frames::<Frame>::new()
                    .map(|frame| (frame.transaction, frame.unit, Response::parse(&frame.pdu))),
            );
            let mut got = Vec::new();
            for chunk in test_support::chunks(&output, sizes) {
                assert_eq!(
                    pump(&mut client, chunk, |response| {
                        assert!(got.len() < MAX_TEST_FRAMES);
                        got.push(response);
                    })
                    .unwrap(),
                    chunk.len()
                );
            }
            finish(&mut client, |_| panic!("unexpected response at EOF")).unwrap();
            assert_eq!(got, expected);
            assert!(server.is_done() && client.is_done());
            assert_eq!(server.failed(), None);
            assert_eq!(client.failed(), None);
        }
    }

    #[test]
    fn stream_splits_a_stream() {
        let a = Frame {
            transaction: 1,
            unit: 1,
            pdu: vec![3, 0, 0, 0, 1],
        }
        .to_bytes()
        .unwrap();
        let b = Frame {
            transaction: 2,
            unit: 1,
            pdu: vec![6, 0, 1, 0, 9],
        }
        .to_bytes()
        .unwrap();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Stream::new(Frames::<Frame>::new());
        // One byte at a time.
        let mut got = Vec::new();
        for byte in test_support::chunks(&stream, &[1]) {
            assert_eq!(d.push(byte), 1);
            while let Some(f) = d.next() {
                got.push(f.unwrap().transaction);
            }
        }
        assert_eq!(got, [1, 2]);
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        assert_eq!(d.push(&[0, 3, 0, 9, 0, 6, 1, 3, 0, 0, 0, 1]), 12);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::Protocol(9)))));
        // Bytes after the break are taken and dropped.
        assert_eq!(d.push(&a), a.len());
        assert_eq!(d.next(), None);
        assert_eq!(d.failed(), Some(&Fail::Protocol(Error::Protocol(9))));
    }

    #[test]
    fn stream_takes_many_small_frames_in_linear_time() {
        assert_linear(
            "stream_takes_many_small_frames_in_linear_time",
            rounds(50_000),
            |size| {
                let one = Frame {
                    transaction: 1,
                    unit: 1,
                    pdu: vec![3, 0, 0, 0, 1],
                }
                .to_bytes()
                .unwrap();
                let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * size).collect();
                let mut d = Stream::new(Frames::<Frame>::new());
                let mut rest = &stream[..];
                let mut n = 0;
                while !rest.is_empty() {
                    rest = &rest[d.push(rest)..];
                    while let Some(f) = d.next() {
                        f.unwrap();
                        n += 1;
                    }
                }
                assert_eq!(n, size);
                assert_eq!(d.buffered(), 0);
            },
        );
    }

    #[test]
    fn stream_is_bounded() {
        // 64 KiB of zeros in one push: the decoder takes only what it may
        // hold, and the header it sees is already broken.
        let mut d = Stream::new(Frames::<Frame>::new());
        let zeros = vec![0u8; 64 * 1024];
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &zeros, 2 * MAX_FRAME);
        let took = d.push(&zeros);
        assert!(took <= MAX_FRAME);
        assert!(d.buffered() <= MAX_FRAME);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::Length(0)))));
        // Many longest frames pushed in one go come out the same as in
        // other chunk sizes, and the buffer never grows past the bound.
        let mut stream = Vec::new();
        for t in 0..50u16 {
            let mut pdu = vec![0x41];
            pdu.resize(MAX_PDU, t as u8);
            stream.extend(
                Frame {
                    transaction: t,
                    unit: 1,
                    pdu,
                }
                .to_bytes()
                .unwrap(),
            );
        }
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &stream, 2 * MAX_FRAME);
        let (frames, failure) = test_support::decode_all(Frames::<Frame>::new, &stream);
        assert_eq!(failure, None);
        assert_eq!(frames.len(), 50);
        // A decoder that is full gives room back once frames are taken out.
        let mut d = Stream::new(Frames::<Frame>::new());
        assert_eq!(d.push(&stream), MAX_FRAME);
        assert_eq!(d.push(&stream[MAX_FRAME..]), 0);
        assert!(d.next().unwrap().is_ok());
        assert_eq!(d.push(&stream[MAX_FRAME..]), MAX_FRAME);
    }

    #[test]
    fn review_parsers_refuse_pdus_past_max_pdu() {
        let mut long = vec![0x41];
        long.resize(MAX_PDU + 1, 0);
        assert_eq!(Request::parse(&long), Err(Exception::IllegalDataValue));
        assert_eq!(Response::parse(&long), Err(Error::BadResponse));
        // One byte shorter is a PDU a frame can carry, and reads.
        assert!(Request::parse(&long[..MAX_PDU]).is_ok());
        assert!(Response::parse(&long[..MAX_PDU]).is_ok());
    }

    #[test]
    fn review_writers_refuse_rather_than_truncate() {
        let req = Request::WriteMultipleRegisters {
            address: 0,
            values: vec![1; 124],
        };
        assert_eq!(req.to_pdu(), Err(Error::Quantity));
        let req = Request::WriteMultipleCoils {
            address: 0,
            values: vec![true; 1969],
        };
        assert_eq!(req.to_pdu(), Err(Error::Quantity));
        assert_eq!(
            Response::Registers(vec![7; 126]).to_pdu(3),
            Err(Error::Quantity)
        );
        assert_eq!(
            Request::Other {
                function: 0x41,
                data: vec![0; MAX_PDU]
            }
            .to_pdu(),
            Err(Error::TooLong)
        );
        assert_eq!(
            Response::Other(vec![0; MAX_PDU]).to_pdu(0x41),
            Err(Error::TooLong)
        );
        let frame = Frame {
            transaction: 0,
            unit: 0,
            pdu: vec![0; 1000],
        };
        assert_eq!(frame.to_bytes(), Err(Error::TooLong));
        // The longest of each still fits and reads back whole.
        let req = Request::WriteMultipleRegisters {
            address: 0,
            values: vec![1; 123],
        };
        assert_eq!(Request::parse(&req.to_pdu().unwrap()), Ok(req));
        let req = Request::WriteMultipleCoils {
            address: 0,
            values: vec![true; 1968],
        };
        assert_eq!(Request::parse(&req.to_pdu().unwrap()), Ok(req));
        let resp = Response::Registers(vec![7; 125]);
        assert_eq!(Response::parse(&resp.to_pdu(4).unwrap()), Ok((4, resp)));
        let frame = Frame {
            transaction: 0,
            unit: 0,
            pdu: vec![0x41; MAX_PDU],
        };
        let bytes = frame.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_FRAME);
        assert_eq!(Frame::parse_prefix(&bytes), Ok(Some((frame, MAX_FRAME))));
    }

    #[test]
    fn review_request_writers_check_quantity_and_range() {
        fictionet::assert_cases!(|input: Request| input.to_pdu();
            (Request::ReadHoldingRegisters { address: 0, quantity: 0 }) => Err(Error::Quantity),
            (Request::ReadInputRegisters { address: 0, quantity: 126 }) => Err(Error::Quantity),
            (Request::ReadCoils { address: 0, quantity: 2001 }) => Err(Error::Quantity),
            (Request::ReadHoldingRegisters { address: 65535, quantity: 2 }) => Err(Error::Address),
            (Request::WriteMultipleRegisters { address: 0, values: vec![] }) => Err(Error::Quantity),
            (Request::WriteMultipleCoils { address: 0, values: vec![] }) => Err(Error::Quantity),
            (Request::WriteMultipleCoils { address: 65535, values: vec![true; 2] }) => Err(Error::Address),
        );
        let last = Request::ReadDiscreteInputs {
            address: 65535,
            quantity: 1,
        };
        assert_eq!(Request::parse(&last.to_pdu().unwrap()), Ok(last));
    }

    #[test]
    fn review_empty_frame_is_refused() {
        let frame = Frame {
            transaction: 0,
            unit: 1,
            pdu: vec![],
        };
        assert_eq!(frame.to_bytes(), Err(Error::EmptyPdu));
        assert_eq!(frame.reply(vec![]).to_bytes(), Err(Error::EmptyPdu));
        let one = Frame {
            transaction: 0,
            unit: 1,
            pdu: vec![0x41],
        };
        assert_eq!(
            Frame::parse_prefix(&one.to_bytes().unwrap()),
            Ok(Some((one, 8)))
        );
    }

    #[test]
    fn review_response_writers_check_the_function() {
        assert_eq!(
            Response::Bits(vec![true]).to_pdu(3),
            Err(Error::Function(3))
        );
        assert_eq!(
            Response::Registers(vec![1]).to_pdu(1),
            Err(Error::Function(1))
        );
        assert_eq!(
            Response::WriteSingleCoil {
                address: 0,
                value: true
            }
            .to_pdu(6),
            Err(Error::Function(6))
        );
        assert_eq!(
            Response::WriteSingleRegister {
                address: 0,
                value: 1
            }
            .to_pdu(5),
            Err(Error::Function(5))
        );
        assert_eq!(
            Response::WriteMultiple {
                address: 0,
                quantity: 1
            }
            .to_pdu(3),
            Err(Error::Function(3))
        );
        assert_eq!(
            Response::Bits(vec![true]).to_pdu(0x81),
            Err(Error::Function(0x81))
        );
        // An exception answers any function.
        assert_eq!(
            Response::Exception(Exception::ServerDeviceBusy).to_pdu(0x41),
            Ok(vec![0xc1, 0x06])
        );
    }

    #[test]
    fn review_responses_check_counts_ranges_and_function() {
        // Empty reads.
        assert_eq!(Response::parse(&[0x01, 0x00]), Err(Error::BadResponse));
        assert_eq!(Response::parse(&[0x03, 0x00]), Err(Error::BadResponse));
        // More than 2000 coils or 125 registers.
        let mut bits = vec![0x01, 251];
        bits.resize(253, 0);
        assert_eq!(Response::parse(&bits), Err(Error::BadResponse));
        let mut regs = vec![0x03, 252];
        regs.resize(254, 0);
        fictionet::assert_cases!(Response::parse;
            (&regs) => Err(Error::BadResponse),
            // Write acknowledgements of 0, too many, or past address 65535.
            (&[0x10, 0, 0, 0, 0]) => Err(Error::BadResponse),
            (&[0x10, 0, 0, 0, 124]) => Err(Error::BadResponse),
            (&[0x0f, 0, 0, 0x07, 0xb1]) => Err(Error::BadResponse),
            (&[0x10, 0xff, 0xff, 0, 2]) => Err(Error::BadResponse),
        );
        assert!(Response::parse(&[0x0f, 0, 0, 0x07, 0xb0]).is_ok());
        // Function code 0.
        assert_eq!(Response::parse(&[0x00]), Err(Error::BadResponse));
        assert_eq!(Response::parse(&[0x00, 1, 2]), Err(Error::BadResponse));
        // The writers keep to the same limits.
        assert_eq!(
            Response::Bits(vec![false; 2001]).to_pdu(1),
            Err(Error::Quantity)
        );
        assert_eq!(Response::Bits(vec![]).to_pdu(1), Err(Error::Quantity));
        assert_eq!(Response::Registers(vec![]).to_pdu(3), Err(Error::Quantity));
        assert_eq!(
            Response::WriteMultiple {
                address: 0,
                quantity: 0
            }
            .to_pdu(16),
            Err(Error::Quantity)
        );
        assert_eq!(
            Response::WriteMultiple {
                address: 0,
                quantity: 124
            }
            .to_pdu(16),
            Err(Error::Quantity)
        );
        assert_eq!(
            Response::WriteMultiple {
                address: 65535,
                quantity: 2
            }
            .to_pdu(15),
            Err(Error::Address)
        );
        assert_eq!(Response::Other(vec![1]).to_pdu(0), Err(Error::Function(0)));
        let pdu = Response::Bits(vec![true; 2000]).to_pdu(2).unwrap();
        assert_eq!(
            Response::parse(&pdu),
            Ok((2, Response::Bits(vec![true; 2000])))
        );
    }

    #[test]
    fn review_other_variants_do_not_alias_typed_ones() {
        let req = Request::Other {
            function: 3,
            data: vec![0, 0, 0, 1],
        };
        assert_eq!(req.to_pdu(), Err(Error::Function(3)));
        assert_eq!(
            Request::Other {
                function: 0,
                data: vec![]
            }
            .to_pdu(),
            Err(Error::Function(0))
        );
        assert_eq!(
            Request::Other {
                function: 0x83,
                data: vec![2]
            }
            .to_pdu(),
            Err(Error::Function(0x83))
        );
        assert_eq!(
            Response::Other(vec![2, 0, 1]).to_pdu(3),
            Err(Error::Function(3))
        );
        assert_eq!(
            Response::Other(vec![2]).to_pdu(0x83),
            Err(Error::Function(0x83))
        );
        // An exception's code is what makes it, so `Other(1)` reads back
        // equal.
        let pdu = Response::Exception(Exception::Other(1)).to_pdu(3).unwrap();
        assert_eq!(
            Response::parse(&pdu),
            Ok((3, Response::Exception(Exception::Other(1))))
        );
        assert_eq!(Exception::Other(1), Exception::IllegalFunction);
        assert_ne!(Exception::Other(9), Exception::IllegalFunction);
        // Other functions round trip.
        let req = Request::Other {
            function: 0x2b,
            data: vec![0x0e, 1, 0],
        };
        assert_eq!(Request::parse(&req.to_pdu().unwrap()), Ok(req));
        let resp = Response::Other(vec![0x0e, 1]);
        assert_eq!(
            Response::parse(&resp.to_pdu(0x2b).unwrap()),
            Ok((0x2b, resp))
        );
    }

    /// Every value a writer accepts reads back the same, over a spread of
    /// constructed values.
    #[test]
    fn review_what_writers_accept_reads_back_the_same() {
        let addresses = [0u16, 1, 100, 65400, 65534, 65535];
        let counts = [
            0usize, 1, 7, 8, 9, 123, 124, 125, 126, 1968, 1969, 2000, 2001,
        ];
        for &address in &addresses {
            for &n in &counts {
                let q = n as u16;
                let reqs = [
                    Request::ReadCoils {
                        address,
                        quantity: q,
                    },
                    Request::ReadDiscreteInputs {
                        address,
                        quantity: q,
                    },
                    Request::ReadHoldingRegisters {
                        address,
                        quantity: q,
                    },
                    Request::ReadInputRegisters {
                        address,
                        quantity: q,
                    },
                    Request::WriteMultipleCoils {
                        address,
                        values: (0..n).map(|i| i % 3 == 0).collect(),
                    },
                    Request::WriteMultipleRegisters {
                        address,
                        values: (0..n).map(|i| i as u16).collect(),
                    },
                ];
                for req in reqs {
                    if let Ok(pdu) = req.to_pdu() {
                        assert!(pdu.len() <= MAX_PDU);
                        assert_eq!(Request::parse(&pdu), Ok(req));
                    }
                }
                for function in 0..=255u8 {
                    let resps = [
                        Response::Bits((0..n).map(|i| i % 3 == 0).collect()),
                        Response::Registers((0..n).map(|i| i as u16).collect()),
                        Response::WriteSingleCoil {
                            address,
                            value: n % 2 == 0,
                        },
                        Response::WriteSingleRegister { address, value: q },
                        Response::WriteMultiple {
                            address,
                            quantity: q,
                        },
                        Response::Exception(Exception::from_code(q as u8)),
                        Response::Other(vec![q as u8; n.min(300)]),
                    ];
                    for resp in resps {
                        let Ok(pdu) = resp.to_pdu(function) else {
                            continue;
                        };
                        assert!(!pdu.is_empty() && pdu.len() <= MAX_PDU);
                        let (f, back) = Response::parse(&pdu).unwrap();
                        assert_eq!(f, function & !function::EXCEPTION_FLAG);
                        match (&resp, &back) {
                            // Bits come back padded to a whole byte.
                            (Response::Bits(a), Response::Bits(b)) => {
                                assert_eq!(&b[..a.len()], &a[..]);
                                assert!(b[a.len()..].iter().all(|&x| !x));
                                assert_eq!(b.len(), a.len().div_ceil(8) * 8);
                            }
                            _ => assert_eq!(back, resp),
                        }
                    }
                }
            }
        }
    }
}
