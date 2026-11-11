//! QUIC over the world's datagram carrier.
//!
//! A layer owns one connection and its endpoint routing state. Its lower
//! carrier must retire tracked sends, including local drops. It offers
//! independently credited, directionally cancellable byte streams above,
//! plus the connection's application datagram carrier in its control port.
//! The engine does no socket I/O. The caller supplies its monotonic epoch;
//! every subsequent timestamp is derived from the layer environment.
//!
//! This integration is under construction. Adapter queues and outgoing
//! application backings and datagram receive arenas are charged, but the
//! vendored engine's stream receive, recovery, TLS and routing allocations
//! are not yet budgeted. Configured
//! stream and flow-control limits do not constitute a heap bound.

mod layer;

pub use layer::{Control, ControlCommand, ControlEvent, Error, Quic, QuicLayer, Stream};
pub use quinn_proto::{ClientConfig, Dir, EndpointConfig, ServerConfig, StreamId, VarInt};

#[cfg(test)]
mod tests;
