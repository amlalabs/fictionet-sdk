//! QUIC over the world's datagram carrier.
//!
//! `QuicLayer` owns one connection. `Listener` routes many connections on
//! one lower carrier by connection ID and exposes a QUIC mux per child,
//! opened with its [`Accepted`] metadata and budget. The lower carrier
//! must retire tracked sends, including local drops. Each connection offers
//! independently credited, directionally cancellable byte streams above,
//! plus the connection's application datagram carrier in its control port.
//! The engine does no socket I/O. The caller supplies its monotonic epoch;
//! every subsequent timestamp is derived from the layer environment.
//!
//! This integration is under construction. Adapter queues and outgoing
//! application backings, wire input, datagram receive arenas and reassembly
//! descriptors and copies are charged. A `Listener` reserves its routing
//! tables for its connection limit, and charges each connection's storage
//! to a budget of the connection's own. Stream records, unordered-read
//! ranges, recovery and TLS allocations still need budgeting. Configured
//! stream and flow-control limits do not constitute a heap bound.

mod layer;

pub use layer::{
    Accepted, AddressValidation, Connections, Control, ControlCommand, ControlEvent, Epoch, Error,
    Listener, ListenerConfig, Quic, QuicLayer, Stream,
};
pub use quinn_proto::version::{QUIC_V1, QUIC_V2, VersionList};
pub use quinn_proto::{ClientConfig, Dir, EndpointConfig, ServerConfig, StreamId, VarInt};

#[cfg(test)]
mod tests;
