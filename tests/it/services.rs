//! The service layer: `serve` (the Service trait, the driver, the
//! harness), events, `httpd` and `net`, each
//! tested on its own and together in one world: a PLC
//! that speaks Modbus/TCP and a web server, on one `Net`, with the
//! dashboard's decoder reading both from the packets.

use crate::common::echo_service;
use crate::common::io;
use crate::common::world;
use fictionet_test_support::certs;
use fictionet_test_support::{Done, timeout};

mod driver;
mod network;
mod tls;

use echo_service::{Echo, Ticker};
use fictionet_test_support::sandbox::{Machine, machine};
use io::read_some;
use world::world;

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use fictionet::prelude::*;
use fictionet::stdlib::codec::{Ending, LineError, Lines, Wire};
use fictionet::stdlib::dissect::{Dissector, Registry};
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::network::{ConnError, ip, tcp, udp};
use fictionet::stdlib::protocols::dns::op::{Message, Query};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::protocols::modbus::{
    self, Exception, Frame, Request as MbRequest, Response as MbResponse,
};
use fictionet::stdlib::services::serve::ConnInfo;
use fictionet::stdlib::services::serve::{
    self, Budget, Flow, Harness, HarnessError, Pending, PendingDriver, ServeOptions, Served,
    Upgrade,
};
use fictionet::stdlib::web::httpd::{self, Http1};
use fictionet::stdlib::world::net::{Arrival, Host, Net, PortServer, PreparedShare, Sni};
use fictionet::{Cx, block_on, lab, pair};

// ---------------------------------------------------------------------------
// Running a world in a test

/// Two machines joined by a cable: a server at 10.9.0.1 and a client at
/// 10.9.0.2.
fn two_machines(fcx: &Cx) -> (tcp::Endpoint, udp::Endpoint, tcp::Endpoint, udp::Endpoint) {
    let (a, b) = pair();
    let (at, au, _ai, _ao) = ip::split_protocols(fcx, a);
    let (bt, bu, _bi, _bo) = ip::split_protocols(fcx, b);
    let server: IpAddr = Ipv4Addr::new(10, 9, 0, 1).into();
    let client: IpAddr = Ipv4Addr::new(10, 9, 0, 2).into();
    (
        tcp::endpoint(fcx, at, server),
        udp::endpoint(fcx, au, server),
        tcp::endpoint(fcx, bt, client),
        udp::endpoint(fcx, bu, client),
    )
}

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);

// ---------------------------------------------------------------------------
// Services used below

/// A PLC's state: sixteen holding registers.
#[derive(Default)]
struct Plant {
    registers: Mutex<[u16; 16]>,
    /// Register 0 is the setpoint; above this is unsafe.
    limit: u16,
    unsafe_writes: AtomicUsize,
}

/// A Modbus/TCP PLC, built from `stdlib::protocols::modbus`.
struct Plc;

service_fixture! {
    Plc => (fictionet::stdlib::codec::Frames<modbus::Frame>, Plant, Infallible);

    decoder(self) {
        fictionet::stdlib::codec::Frames::<modbus::Frame>::new()
    }

    on_item(self, frame: Frame; plant, driver) -> Flow {
        let mut registers = plant.registers.lock().unwrap();
        let pdu = match MbRequest::parse(&frame.pdu) {
            Ok(MbRequest::ReadHoldingRegisters { address, quantity }) => {
                let (a, n) = (usize::from(address), usize::from(quantity));

                match registers.get(a..a + n) {
                    Some(values) => MbResponse::Registers(values.to_vec()).to_pdu(3).unwrap(),
                    None => Exception::IllegalDataAddress.to_pdu(3),
                }
            }
            Ok(MbRequest::WriteSingleRegister { address, value }) => {
                match registers.get_mut(usize::from(address)) {
                    Some(r) => {
                        *r = value;
                        if address == 0 && value > plant.limit { plant.unsafe_writes.fetch_add(1, Ordering::SeqCst); }


                        MbResponse::WriteSingleRegister { address, value }
                            .to_pdu(6)
                            .unwrap()
                    }
                    None => Exception::IllegalDataAddress.to_pdu(6),
                }
            }
            Ok(other) => Exception::IllegalFunction.to_pdu(other.function()),
            Err(e) => e.to_pdu(frame.function().unwrap_or(0)),
        };
        frame.reply(pdu).write(driver.reply()).unwrap();
        Ok(Flow::Continue)
    }
}

/// A Modbus/TCP request frame.
fn mb(transaction: u16, request: MbRequest) -> Vec<u8> {
    Frame {
        transaction,
        unit: 1,
        pdu: request.to_pdu().unwrap(),
    }
    .to_bytes()
    .unwrap()
}

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
