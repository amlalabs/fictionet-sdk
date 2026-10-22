//! The integration tests that run on any machine, one module per area. The
//! tests that need user namespaces, root or a tun device are in `tests/host`.

#[macro_use]
mod common;

mod asn1_codec;
mod bodies_codec;
mod cme_unknown_enum;
mod codec_tools;
mod codegen;
#[cfg(feature = "std")]
mod compose;
#[cfg(feature = "std")]
mod core;
mod datagrams_codec;
mod db_codec;
#[cfg(feature = "std")]
mod determinism;
#[cfg(feature = "std")]
mod e2e;
#[cfg(feature = "std")]
mod entropy;
#[cfg(feature = "std")]
mod fd_limit;
mod features;
#[cfg(feature = "std")]
mod flood;
mod formats_codec;
#[cfg(feature = "web-proxy")]
mod forward;
mod frames_codec;
mod grpc_codec;
mod h3_codec;
mod handoff_codec;
mod hpack_codec;
mod http1;
mod http2_grpc;
#[cfg(feature = "std")]
mod http2_server;
#[cfg(feature = "std")]
mod httpd;
mod industrial_codec;
mod interactive_codec;
mod json_schema;
mod jsonrpc_codec;
mod lab;
#[cfg(feature = "std")]
mod listen;
mod mail_codec;
mod media_codec;
mod messaging_codec;
#[cfg(feature = "std")]
mod packets;
mod protocol_primitives;
mod resp_codec;
mod rpc_codec;
mod rpc_nfs_codec;
mod rtp_rtcp_rules;
#[cfg(feature = "std")]
mod sandbox;
mod sbe_codegen;
#[cfg(feature = "std")]
mod serve_cancellation;
mod serve_decoder;
mod serve_harness;
#[cfg(feature = "std")]
mod serve_limits;
#[cfg(feature = "std")]
mod services;
mod sse_codec;
mod streams_codec;
#[cfg(feature = "std")]
mod stress;
mod tcp_reassembly;
#[cfg(feature = "std")]
mod tcpudp;
mod text_codec;
#[cfg(feature = "std")]
mod tls;
#[cfg(feature = "std")]
mod tls_determinism;
#[cfg(feature = "std")]
mod tls_write_cancellation;
#[cfg(feature = "std")]
mod web;
mod wire_codec;
mod writer_allocation;
