use std::net::IpAddr;

use fictionet::stdlib::{ip, tcp, udp};
use fictionet::{Cx, End, Interface};

/// TCP and UDP endpoints on one sandbox cable.
pub struct Machine {
    pub tcp: tcp::Endpoint,
    pub udp: udp::Endpoint,
    _icmp: End,
}

/// Builds a machine at the address on the cable.
pub fn sandbox(fcx: &Cx, end: impl Interface, addr: impl Into<IpAddr>) -> Machine {
    let addr = addr.into();
    let (t, u, i, _o) = ip::split_protocols(fcx, end);
    Machine {
        tcp: tcp::endpoint(fcx, t, addr),
        udp: udp::endpoint(fcx, u, addr),
        _icmp: i,
    }
}
