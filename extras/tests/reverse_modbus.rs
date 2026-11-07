use fictionet::Cx;
use fictionet::stdlib::codec::{Fail, Frames, Stream, Wire};
use fictionet::stdlib::network::{ConnectionExt, route::Prefix, tcp};
use fictionet::stdlib::protocols::modbus::{self, Frame, Request, Response};
use fictionet::stdlib::world::net::Net;
use fictionet_extras::reverse_modbus::{Failure, Mismatch, Observation, Read, Reader};
use fictionet_test_support::world::world;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

async fn connect(
    fcx: &Cx,
    ipv6: bool,
    port: u16,
    reader: Reader,
) -> fictionet::Result<tcp::TcpConnection> {
    let (server, peer): (IpAddr, IpAddr) = if ipv6 {
        ("2001:db8:1::10".parse()?, "2001:db8:2::20".parse()?)
    } else {
        ("203.0.113.10".parse()?, "192.0.2.20".parse()?)
    };
    let (attacher, attachments) = fictionet::attachments();
    Net::new(fictionet_extras::network::cdn_pools())
        .host("controller", |host| {
            host.at(server).port_server(port, reader)
        })
        .route(
            "field",
            Prefix {
                addr: peer,
                len: if ipv6 { 128 } else { 32 },
            },
        )
        .start(fcx, attachments)?;
    let endpoint = tcp::endpoint(fcx, attacher.attach("field")?, peer);
    Ok(endpoint.connect(fcx, SocketAddr::new(server, port)).await?)
}

async fn request(fcx: &Cx, conn: &mut tcp::TcpConnection) -> fictionet::Result<Frame> {
    let mut stream = Stream::new(Frames::<Frame>::new());
    loop {
        if let Some(frame) = stream.next() {
            return Ok(frame?);
        }
        let count = conn.read(fcx, stream.spare()).await?;
        assert!(
            count > 0,
            "the controller closed before asking for registers"
        );
        stream.commit(count);
    }
}

fn observer(read: Read) -> (Reader, Arc<Mutex<Vec<Observation>>>) {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let out = observations.clone();
    let reader = Reader::new(17, read, move |sample| out.lock().unwrap().push(sample)).unwrap();
    (reader, observations)
}

#[test]
fn tcp_connector_answers_the_listeners_register_request() {
    for ipv6 in [false, true] {
        for port in [0, 62017] {
            for read in [
                Read::Input {
                    address: 13,
                    quantity: 1,
                },
                Read::Holding {
                    address: u16::MAX - modbus::MAX_READ_REGISTERS + 1,
                    quantity: modbus::MAX_READ_REGISTERS,
                },
            ] {
                world(Duration::from_secs(10), move |fcx| async move {
                    let (reader, observations) = observer(read);
                    let mut conn = connect(&fcx, ipv6, port, reader).await?;
                    let local = conn.local_addr();
                    let remote = conn.peer_addr();
                    // The TCP connector reads before writing anything.
                    let frame = request(&fcx, &mut conn).await?;
                    let parsed = Request::parse(&frame.pdu).unwrap();
                    let (address, quantity) = match parsed {
                        Request::ReadHoldingRegisters { address, quantity }
                            if matches!(read, Read::Holding { .. }) =>
                        {
                            (address, quantity)
                        }
                        Request::ReadInputRegisters { address, quantity }
                            if matches!(read, Read::Input { .. }) =>
                        {
                            (address, quantity)
                        }
                        other => panic!("unexpected request: {other:?}"),
                    };
                    let configured = match read {
                        Read::Input { address, quantity } | Read::Holding { address, quantity } => {
                            (address, quantity)
                        }
                    };
                    assert_eq!((address, quantity), configured);
                    let values: Vec<_> = (0..quantity)
                        .map(|offset| (address + offset) ^ frame.transaction)
                        .collect();
                    let reply =
                        frame.reply(Response::Registers(values.clone()).to_pdu(parsed.function())?);
                    conn.write_all(&fcx, &reply.to_bytes()?).await?;
                    let mut byte = [0];
                    assert!(conn.read(&fcx, &mut byte).await? == 0);
                    let mut observations = observations.lock().unwrap();
                    let observation = observations.pop().expect("the sample was observed");
                    assert!(observations.is_empty());
                    assert_eq!(observation.connection.local, Some(remote));
                    assert_eq!(observation.connection.peer, Some(local));
                    assert_eq!(observation.read, read);
                    assert_eq!(observation.unit, frame.unit);
                    assert_eq!(observation.result.unwrap(), values);
                    Ok(())
                });
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Wrong {
    Transaction,
    Unit,
    Function,
    Quantity,
    Exception,
    Malformed,
}

#[test]
fn wrong_or_exception_replies_cannot_become_samples() {
    for wrong in [
        Wrong::Transaction,
        Wrong::Unit,
        Wrong::Function,
        Wrong::Quantity,
        Wrong::Exception,
        Wrong::Malformed,
    ] {
        world(Duration::from_secs(10), move |fcx| async move {
            let (reader, observations) = observer(Read::Input {
                address: 71,
                quantity: 3,
            });
            let mut conn = connect(&fcx, false, 0, reader).await?;
            let frame = request(&fcx, &mut conn).await?;
            let Request::ReadInputRegisters { address, quantity } =
                Request::parse(&frame.pdu).unwrap()
            else {
                panic!("the controller did not ask for input registers");
            };
            let values: Vec<_> = (address..address + quantity).collect();
            let function = frame.function().unwrap();
            let mut reply = frame.reply(Response::Registers(values.clone()).to_pdu(function)?);
            match wrong {
                Wrong::Transaction => reply.transaction = reply.transaction.wrapping_add(1),
                Wrong::Unit => reply.unit = reply.unit.wrapping_add(1),
                Wrong::Function => {
                    reply.pdu = Response::Registers(values)
                        .to_pdu(modbus::function::READ_HOLDING_REGISTERS)?;
                }
                Wrong::Quantity => {
                    reply.pdu = Response::Registers(values[1..].to_vec()).to_pdu(function)?;
                }
                Wrong::Exception => {
                    reply.pdu = modbus::Exception::ServerDeviceBusy.to_pdu(function);
                }
                Wrong::Malformed => {
                    reply.pdu.pop();
                }
            }
            conn.write_all(&fcx, &reply.to_bytes()?).await?;
            let mut byte = [0];
            assert!(conn.read(&fcx, &mut byte).await? == 0);
            let sample = observations.lock().unwrap().pop().unwrap();
            assert!(matches!(
                (wrong, sample.result),
                (
                    Wrong::Transaction,
                    Err(Failure::Mismatch(Mismatch::Transaction))
                ) | (Wrong::Unit, Err(Failure::Mismatch(Mismatch::Unit)))
                    | (Wrong::Function, Err(Failure::Mismatch(Mismatch::Function)))
                    | (Wrong::Quantity, Err(Failure::Mismatch(Mismatch::Quantity)))
                    | (Wrong::Exception, Err(Failure::Exception(_)))
                    | (Wrong::Malformed, Err(Failure::Protocol(_)))
            ));
            Ok(())
        });
    }
}

#[test]
fn closed_and_truncated_peers_do_not_create_samples() {
    for truncated in [false, true] {
        world(Duration::from_secs(10), move |fcx| async move {
            let (reader, observations) = observer(Read::Input {
                address: 2,
                quantity: 3,
            });
            let mut conn = connect(&fcx, true, 0, reader).await?;
            let frame = request(&fcx, &mut conn).await?;
            if truncated {
                let bytes = frame.to_bytes()?;
                conn.write_all(&fcx, &bytes[..bytes.len() / 2]).await?;
            }
            conn.shutdown(&fcx).await?;
            let mut byte = [0];
            assert!(conn.read(&fcx, &mut byte).await? == 0);
            let sample = observations.lock().unwrap().pop().unwrap();
            assert!(matches!(
                (truncated, sample.result),
                (false, Err(Failure::Eof)) | (true, Err(Failure::Framing(Fail::Truncated { .. })))
            ));
            Ok(())
        });
    }
}

#[test]
fn invalid_register_ranges_cannot_open_a_reader() {
    for (address, quantity) in [(0, 0), (0, modbus::MAX_READ_REGISTERS + 1), (u16::MAX, 2)] {
        for read in [
            Read::Input { address, quantity },
            Read::Holding { address, quantity },
        ] {
            assert!(Reader::new(1, read, |_| {}).is_err());
        }
    }
}
