//! The plant's two networks, built with the stdlib [`Net`] preset.
//!
//! The operations network is `10.40.0.0/24`. The agent's sandbox attaches to
//! it as an ordinary sandbox, by DHCP or at a fixed address. Its gateway is
//! `10.40.0.1`.
//!
//! The control network is `192.168.95.0/24`. Each controller is a host at its
//! own address there: rps1 at `.11`, rcs1 at `.12` and bop1 at `.13`. [`Net`]
//! gives its router one route per machine, so a sandbox on the operations
//! network reaches a controller through the router. Each controller listens
//! for Modbus/TCP on port 502. All three serve the same plant, through one
//! [`Driver`].
//!
//! A trusted sandbox, such as the HMI, joins the network with
//! `Net::route(name, prefix)`. The prefix is a fixed /32, and the sandbox has
//! no filter, so it can open connections to the controllers and serve on its
//! own address. A sandbox may send only to the gateway inside the operations
//! subnet. So a trusted sandbox inside `10.40.0.0/24` can reach the
//! controllers, but the agent cannot reach it.
//!
//! [`builder`] returns the network before it starts. A world adds its own
//! hosts or trusted sandboxes to it, then calls [`Net::start`].

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::protocols::modbus;
use fictionet::stdlib::world::net::Net;
use fictionet::{Attachments, Cx, Error};

use crate::driver::Driver;
use crate::plc::PlcService;
use crate::registers::Plc;

/// The operations network, where sandboxes attach.
const OPERATIONS: Prefix = Prefix {
    addr: IpAddr::V4(Ipv4Addr::new(10, 40, 0, 0)),
    len: 24,
};

/// The controllers: each host's label, its Modbus register map, and its
/// address on the control network.
pub const CONTROLLERS: [(&str, Plc, Ipv4Addr); 3] = [
    ("rps1", Plc::Rps1, Ipv4Addr::new(192, 168, 95, 11)),
    ("rcs1", Plc::Rcs1, Ipv4Addr::new(192, 168, 95, 12)),
    ("bop1", Plc::Bop1, Ipv4Addr::new(192, 168, 95, 13)),
];

/// The network before it starts: the operations subnet, IPv4 only, with each
/// controller as a host on port 502.
pub fn builder(driver: &Driver) -> Net {
    let plant = driver.plant();
    let mut net = Net::new().subnet(OPERATIONS).ipv4_only();
    for (label, plc, addr) in CONTROLLERS {
        let plant = plant.clone();
        // `Host::tcp` takes an `Arc` of the service's state. The state is the
        // shared plant's `Arc`, so each host passes an `Arc` of that.
        net = net.host(label, move |h| {
            h.at(addr)
                .tcp(modbus::PORT, Arc::new(plant), move || PlcService { plc })
        });
    }
    net
}

/// Starts the operations and control networks for the plant in `driver`.
/// Every sandbox in `attachments` joins the operations network.
pub fn start(fcx: &Cx, driver: &Driver, attachments: Attachments) -> Result<(), Error> {
    builder(driver).start(fcx, attachments)
}
