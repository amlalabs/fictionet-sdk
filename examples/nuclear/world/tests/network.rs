//! The controllers over the operations network: a sandbox reads their
//! registers, writes through them into the shared plant, and is refused on a
//! closed port.

use std::net::{Ipv4Addr, SocketAddr};

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::{ConnError, ConnectionExt};
use fictionet::stdlib::protocols::modbus::{Frame, Request, Response};
use fictionet::stdlib::world::sandbox;
use fictionet::{Cx, RunOptions, Seed};
use nuclear_world::driver::Driver;
use nuclear_world::registers::{self, Plc};
use nuclear_world::{Config, network};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 40, 0, 50);
const RPS1: Ipv4Addr = Ipv4Addr::new(192, 168, 95, 11);
const RCS1: Ipv4Addr = Ipv4Addr::new(192, 168, 95, 12);
const BOP1: Ipv4Addr = Ipv4Addr::new(192, 168, 95, 13);
const MODBUS: u16 = 502;

/// Sends one request on `conn` and returns the response to it.
async fn exchange<C: ConnectionExt + Send>(fcx: &Cx, conn: &mut C, request: &Request) -> Response {
    let pdu = request.to_pdu().expect("the request is valid");
    let bytes = Frame {
        transaction: 1,
        unit: 1,
        pdu,
    }
    .to_bytes()
    .expect("the frame encodes");
    conn.write_all(fcx, &bytes)
        .await
        .expect("the request is sent");
    let mut received = Vec::new();
    loop {
        if let Some((frame, _)) =
            Frame::parse_prefix(&received).expect("the reply is a Modbus frame")
        {
            assert_eq!(frame.transaction, 1, "the reply answers this request");
            let (function, response) =
                Response::parse(&frame.pdu).expect("the reply PDU is well formed");
            assert_eq!(function, request.function());
            return response;
        }
        let mut buf = [0u8; 512];
        let n = conn.read(fcx, &mut buf).await.expect("the reply arrives");
        assert_ne!(n, 0, "the controller closed the connection before replying");
        received.extend_from_slice(&buf[..n]);
    }
}

#[test]
fn a_sandbox_reads_rcs1_and_a_closed_port_refuses() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(1)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let (attacher, attachments) = fictionet::attachments();
            network::start(&fcx, &driver, attachments)?;
            let client = sandbox::machine(&fcx, attacher.attach("operator")?, CLIENT);

            let mut conn = client
                .tcp
                .connect(&fcx, SocketAddr::new(RCS1.into(), MODBUS))
                .await
                .expect("rcs1 accepts Modbus/TCP on port 502");
            let expected = registers::input_registers(Plc::Rcs1, &driver.snapshot());
            let response = exchange(
                &fcx,
                &mut conn,
                &Request::ReadInputRegisters {
                    address: 4,
                    quantity: 1,
                },
            )
            .await;
            assert_ne!(expected[4], 0, "pressurizer pressure is a live count");
            assert_eq!(response, Response::Registers(vec![expected[4]]));

            let refused = client
                .tcp
                .connect(&fcx, SocketAddr::new(RCS1.into(), 102))
                .await
                .err();
            assert_eq!(refused, Some(ConnError::Refused));
            fcx.cancel();
            Ok(())
        },
    ));
    result.unwrap();
}

#[test]
fn each_controller_serves_its_own_map_and_a_write_reaches_the_shared_plant() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(2)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let (attacher, attachments) = fictionet::attachments();
            network::start(&fcx, &driver, attachments)?;
            let client = sandbox::machine(&fcx, attacher.attach("operator")?, CLIENT);

            for (addr, plc) in [(RPS1, Plc::Rps1), (RCS1, Plc::Rcs1), (BOP1, Plc::Bop1)] {
                let mut conn = client
                    .tcp
                    .connect(&fcx, SocketAddr::new(addr.into(), MODBUS))
                    .await
                    .expect("each controller accepts Modbus/TCP on port 502");
                let expected = registers::input_registers(plc, &driver.snapshot());
                if plc == Plc::Rps1 {
                    assert_eq!(expected.len(), 5);
                    assert_eq!(expected[4], driver.snapshot().telemetry.heartbeat);
                }
                let response = exchange(
                    &fcx,
                    &mut conn,
                    &Request::ReadInputRegisters {
                        address: 0,
                        quantity: expected.len() as u16,
                    },
                )
                .await;
                assert_eq!(response, Response::Registers(expected), "{plc:?}");
            }

            // A rod demand written through rps1 is applied to the plant the
            // driver holds, so the driver's snapshot counts it.
            let mut rps = client
                .tcp
                .connect(&fcx, SocketAddr::new(RPS1.into(), MODBUS))
                .await
                .expect("rps1 accepts Modbus/TCP on port 502");
            let echo = exchange(
                &fcx,
                &mut rps,
                &Request::WriteSingleRegister {
                    address: 0,
                    value: 480,
                },
            )
            .await;
            assert_eq!(
                echo,
                Response::WriteSingleRegister {
                    address: 0,
                    value: 480
                }
            );
            assert_eq!(driver.snapshot().operator_actions, 1);
            fcx.cancel();
            Ok(())
        },
    ));
    result.unwrap();
}
