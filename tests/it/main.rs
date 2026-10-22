//! The integration tests that run on any machine, one module per area. The
//! tests that need user namespaces, root or a tun device are in `tests/host`.

#[macro_use]
mod common;

mod asn1_codec;
mod bodies_codec;
mod cme_unknown_enum;
mod codegen;
mod compose;
mod core;
mod dashboard_js;
mod datagrams_codec;
mod db_codec;
mod determinism;
mod e2e;
mod entropy;
mod fd_limit;
mod features;
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
mod http2_server;
mod httpd;
mod industrial_codec;
mod interactive_codec;
mod json_schema;
mod jsonrpc_codec;
mod lab;
mod listen;
mod mail_codec;
mod media_codec;
mod messaging_codec;
mod observe;
mod packets;
mod protocol_primitives;
mod resp_codec;
mod rpc_codec;
mod rpc_nfs_codec;
mod rtp_rtcp_rules;
mod sandbox;
mod sbe_codegen;
mod serve_cancellation;
mod serve_decoder;
mod serve_harness;
mod serve_limits;
mod services;
mod sse_codec;
mod streams_codec;
mod stress;
mod tcp_reassembly;
mod tcpudp;
mod text_codec;
mod tls;
mod tls_determinism;
mod tls_write_cancellation;
mod web;
mod wire_codec;
mod writer_allocation;
