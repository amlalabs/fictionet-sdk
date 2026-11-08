//! The service layer: stacks run over live connections and sockets,
//! `httpd` and `net`, each tested on its own and together in one world: a
//! PLC that speaks Modbus/TCP and a web server, on one `Net`, with the
//! dashboard's decoder reading both from the packets.

use crate::common::echo_stack;
use crate::common::io;
use crate::common::line_stack;
use fictionet_test_support::certs;
use fictionet_test_support::world;
use fictionet_test_support::{Done, timeout};

mod network;
mod program;
mod stacks;
mod tls;

use echo_stack::{Echo, Ticker, echo_datagrams};
use fictionet_test_support::sandbox::{Machine, machine};
use io::read_some;
use line_stack::{DatagramApp, Datagrammed, LineApp, LineOut, Lined, Sends};
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
use fictionet::stdlib::codec::{Frames, LineError, Wire};
use fictionet::stdlib::dissect::{Dissector, Registry};
use fictionet::stdlib::layer::{
    self, Admit, Budget, Chain, Decoded, Env, Framed, Framing, Layer, MessageCommand, MessageEvent,
    Owned, Top,
};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::network::{ConnError, ip, tcp, udp};
use fictionet::stdlib::protocols::dns::op::{Message, Query};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::protocols::modbus::{
    self, Exception, Frame, Request as MbRequest, Response as MbResponse,
};
use fictionet::stdlib::services::stack::{self, Job, Polling, StreamLimits};
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
// Stacks used below

/// A PLC's state: sixteen holding registers.
#[derive(Default)]
struct Plant {
    registers: Mutex<[u16; 16]>,
    /// Register 0 is the setpoint; above this is unsafe.
    limit: u16,
    unsafe_writes: AtomicUsize,
}

/// The port a PLC reads requests from: Modbus/TCP frames.
type ModbusPort = Framing<Frames<Frame>, Frame>;

/// A Modbus/TCP PLC, built from `stdlib::protocols::modbus`, over a framed
/// stream: one answer for each request, in turn.
struct Plc {
    plant: Arc<Plant>,
    reply: Option<Owned<Frame>>,
    over: bool,
    end_sent: bool,
}

impl Plc {
    /// A PLC for `plant` as a stack.
    fn stack(plant: Arc<Plant>) -> Chain<Framed<Frames<Frame>, Frame>, Plc> {
        let plc = Plc {
            plant,
            reply: None,
            over: false,
            end_sent: false,
        };
        Chain::new(Framed::new(Frames::new()), plc)
    }

    /// The answer to `frame`.
    fn answer(&self, frame: &Frame) -> Frame {
        let plant = &self.plant;
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
                        if address == 0 && value > plant.limit {
                            plant.unsafe_writes.fetch_add(1, Ordering::SeqCst);
                        }
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
        frame.reply(pdu)
    }
}

impl Layer for Plc {
    type Lower = ModbusPort;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: MessageEvent<Decoded<Frames<Frame>>>,
    ) -> Result<Admit<MessageEvent<Decoded<Frames<Frame>>>>, Infallible> {
        match event {
            MessageEvent::Message(Ok(frame)) => {
                if self.reply.is_some() {
                    return Ok(Admit::Blocked(MessageEvent::Message(Ok(frame))));
                }
                let reply = self.answer(&frame);
                // A reply the budget has no room for is not sent.
                if let Some(charge) = env.budget().charge(reply.pdu.len() + 8) {
                    self.reply = Some(Owned::new(reply, charge));
                }
            }
            MessageEvent::Message(Err(_)) | MessageEvent::Ended => self.over = true,
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self) -> Option<MessageCommand<Owned<Frame>>> {
        if let Some(reply) = self.reply.take() {
            return Some(MessageCommand::Send(reply));
        }
        if self.over && !self.end_sent {
            self.end_sent = true;
            return Some(MessageCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
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
