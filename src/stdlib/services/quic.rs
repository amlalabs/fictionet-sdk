//! QUIC over the world's datagram carrier.
//!
//! `QuicLayer` owns one connection. `Listener` routes many connections on
//! one lower carrier and exposes a QUIC mux per child. The lower carrier
//! must retire tracked sends, including local drops. Each connection offers
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

pub use layer::{
    Connections, Control, ControlCommand, ControlEvent, Error, Listener, ListenerConfig, Quic,
    QuicLayer, Stream,
};
pub use quinn_proto::{ClientConfig, Dir, EndpointConfig, ServerConfig, StreamId, VarInt};

#[cfg(test)]
mod tests;
