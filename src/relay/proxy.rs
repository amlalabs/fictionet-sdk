//! The protocol side of `fictionet attach --type https_proxy` and
//! `--type socks5`: reading what a proxy client sends, and what the door
//! answers, with no sockets. The binary runs these over its connections;
//! the fuzz targets call them directly.
//!
//! The HTTP door reads request heads with [`stdlib::http1`](crate::stdlib::http1)
//! and the SOCKS5 door reads the handshake with
//! [`stdlib::socks`](crate::stdlib::socks).

pub mod auth;
pub mod dns;
pub mod http;
pub mod socks5;

use std::net::{Ipv4Addr, Ipv6Addr};

/// Where a client wants to go, as it named it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    Name(String),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Name(n) => f.write_str(n),
            Host::V4(a) => write!(f, "{a}"),
            Host::V6(a) => write!(f, "[{a}]"),
        }
    }
}

impl Host {
    /// Reads a host as it appears in a URL or a CONNECT target: a name, an
    /// IPv4 address, or an IPv6 address in brackets.
    pub fn parse(s: &str) -> Option<Host> {
        if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            return inner.parse().ok().map(Host::V6);
        }
        if let Ok(a) = s.parse::<Ipv4Addr>() {
            return Some(Host::V4(a));
        }
        dns::normalize(s).map(Host::Name)
    }
}
