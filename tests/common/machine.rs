use std::net::IpAddr;

use fictionet::{Attacher, Cx};

use crate::sandbox::{Machine, sandbox};

/// Attaches a named machine at the address.
pub fn machine(fcx: &Cx, attacher: &Attacher, name: &str, addr: impl Into<IpAddr>) -> Machine {
    sandbox(fcx, attacher.attach(name).unwrap(), addr)
}
