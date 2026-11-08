//! A Modbus client behind a listening TCP port.
//!
//! [`Reader`] accepts a connection, asks its peer for registers, reports the
//! answer to world code, and closes. The TCP connector must act as the Modbus
//! server. This models a polling controller reached through a serial gateway
//! and gives worlds a way to exercise protocol roles independently of who
//! opened the transport. It is Modbus/TCP, not Modbus RTU over TCP.
//!
//! ```
//! use fictionet::stdlib::world::net::Host;
//! use fictionet_extras::reverse_modbus::{Read, Reader};
//!
//! let reader = Reader::new(1, Read::Input { address: 0, quantity: 2 }, |sample| {
//!     // Retain the result in world state, outside the connected sandbox.
//!     let _ = sample;
//! })?;
//! let host = Host::new("controller").port_server(0, reader);
//! # Ok::<(), fictionet::stdlib::protocols::modbus::Error>(())
//! ```

use fictionet::Cx;
use fictionet::stdlib::codec::{Fail, Frames, Stream, Wire};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::network::{ConnError, Connection, ConnectionExt};
use fictionet::stdlib::protocols::modbus::{self, Frame, Request, Response};
use fictionet::stdlib::world::net::{Arrival, PortServer};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// The register bank and range requested when a connection arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// Read holding registers with function three.
    Holding {
        /// First register address.
        address: u16,
        /// Number of registers.
        quantity: u16,
    },
    /// Read input registers with function four.
    Input {
        /// First register address.
        address: u16,
        /// Number of registers.
        quantity: u16,
    },
}

impl Read {
    fn request(self) -> Request {
        match self {
            Self::Holding { address, quantity } => {
                Request::ReadHoldingRegisters { address, quantity }
            }
            Self::Input { address, quantity } => Request::ReadInputRegisters { address, quantity },
        }
    }

    fn quantity(self) -> usize {
        match self {
            Self::Holding { quantity, .. } | Self::Input { quantity, .. } => usize::from(quantity),
        }
    }
}

/// A well-framed response did not answer the outstanding request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// The transaction identifier belongs to another request.
    Transaction,
    /// The response names another unit.
    Unit,
    /// The response answers another function.
    Function,
    /// The response contains a different number of registers.
    Quantity,
}

/// Why no register sample was obtained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Reading or writing the connection failed.
    Transport(ConnError),
    /// The peer closed without a complete response.
    Eof,
    /// The stream did not contain a complete, valid Modbus frame.
    Framing(Fail<modbus::Error>),
    /// The response PDU was invalid.
    Protocol(modbus::Error),
    /// A response did not match the request.
    Mismatch(Mismatch),
    /// The device returned a Modbus exception.
    Exception(modbus::Exception),
}

/// One completed attempt, delivered only to world code.
#[derive(Clone, Debug)]
pub struct Observation {
    /// The accepted TCP connection and its sandbox, when known.
    pub connection: ConnInfo,
    /// Which unit was asked.
    pub unit: u8,
    /// Which register bank and range were asked for.
    pub read: Read,
    /// Values in register-address order, or why none were obtained.
    pub result: Result<Vec<u16>, Failure>,
}

/// Requests one register sample from each peer that connects.
///
/// The observer runs synchronously and must return promptly. No application
/// deadline is imposed: a silent peer waits until transport closure or world
/// cancellation. A future dropped by its owner produces no observation.
#[derive(Clone)]
pub struct Reader {
    unit: u8,
    read: Read,
    pdu: Vec<u8>,
    observe: Arc<dyn Fn(Observation) + Send + Sync>,
}

impl Reader {
    /// Validates the register range against the Modbus specification.
    ///
    /// Each accepted connection gets a fresh transaction identifier from the
    /// world's seeded randomness. Responses must match that identifier, unit,
    /// function and register count before any values reach the observer.
    pub fn new(
        unit: u8,
        read: Read,
        observe: impl Fn(Observation) + Send + Sync + 'static,
    ) -> Result<Self, modbus::Error> {
        Ok(Self {
            unit,
            read,
            pdu: read.request().to_pdu()?,
            observe: Arc::new(observe),
        })
    }

    async fn sample(&self, fcx: &Cx, conn: &mut Box<dyn Connection>) -> Result<Vec<u16>, Failure> {
        let request = Frame {
            transaction: fcx.random_u64() as u16,
            unit: self.unit,
            pdu: self.pdu.clone(),
        };
        let bytes = request.to_bytes().map_err(Failure::Protocol)?;
        conn.write_all(fcx, &bytes)
            .await
            .map_err(Failure::Transport)?;
        let mut stream = Stream::new(Frames::<Frame>::new());
        let reply = loop {
            if let Some(frame) = stream.next() {
                break frame.map_err(Failure::Framing)?;
            }
            if stream.is_eof() {
                return Err(Failure::Eof);
            }
            let count = conn
                .read(fcx, stream.spare())
                .await
                .map_err(Failure::Transport)?;
            stream.commit(count);
            if count == 0 {
                stream.end();
            }
        };
        if reply.transaction != request.transaction {
            return Err(Failure::Mismatch(Mismatch::Transaction));
        }
        if reply.unit != request.unit {
            return Err(Failure::Mismatch(Mismatch::Unit));
        }
        let (function, response) = Response::parse(&reply.pdu).map_err(Failure::Protocol)?;
        if function != self.read.request().function() {
            return Err(Failure::Mismatch(Mismatch::Function));
        }
        match response {
            Response::Registers(values) if values.len() == self.read.quantity() => Ok(values),
            Response::Registers(_) => Err(Failure::Mismatch(Mismatch::Quantity)),
            Response::Exception(exception) => Err(Failure::Exception(exception)),
            _ => Err(Failure::Protocol(modbus::Error::BadResponse)),
        }
    }
}

impl PortServer for Reader {
    fn serve(&self, fcx: Cx, mut arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let reader = self.clone();
        Box::pin(async move {
            let result = reader.sample(&fcx, &mut arrival.conn).await;
            (reader.observe)(Observation {
                connection: arrival.info,
                unit: reader.unit,
                read: reader.read,
                result,
            });
        })
    }
}
