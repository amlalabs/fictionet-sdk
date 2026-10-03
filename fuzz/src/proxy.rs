//! The proxy's modules, compiled from the `fictionet` binary's own source
//! files, so the fuzz targets reach its parsers.

#[path = "../../src/bin/fictionet/proxy/auth.rs"]
pub mod auth;
#[path = "../../src/bin/fictionet/proxy/dns.rs"]
pub mod dns;
#[path = "../../src/bin/fictionet/proxy/http.rs"]
pub mod http;
#[path = "../../src/bin/fictionet/proxy/link.rs"]
pub mod link;
#[path = "../../src/bin/fictionet/proxy/pump.rs"]
pub mod pump;
#[path = "../../src/bin/fictionet/proxy/socks5.rs"]
pub mod socks5;
#[path = "../../src/bin/fictionet/proxy/stack.rs"]
pub mod stack;

/// The binary logs to stderr. Fuzzing does not need it.
pub(crate) fn log(_line: &str) {}
