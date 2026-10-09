//! A Modbus gateway that accepts nonzero protocol identifiers on a simulated network.
use fictionet::events::Transport;
use fictionet::observe::{Conversation, Decoded, Layer, Match, Place, Present, Registry};
use fictionet::stdlib::{
    ConnectionExt,
    codec::{Decode, Frames, Step, Wire},
    ip,
    net::Net,
    serve::{Driver, Flow, Service},
    tcp,
};
use fictionet::{Cx, Seed, block_on, lab};
use std::{convert::Infallible, net::Ipv4Addr, sync::Arc};

#[allow(dead_code)]
mod modbus;

struct Plc;
impl Service for Plc {
    type Decoder = Frames<modbus::Frame>;
    type State = ();
    type Error = Infallible;
    fn decoder(&self) -> Self::Decoder {
        Frames::new()
    }
    fn on_item(
        &mut self,
        frame: modbus::Frame,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Infallible> {
        let pdu = match modbus::Request::parse(&frame.pdu) {
            Ok(modbus::Request::ReadHoldingRegisters {
                address: 42,
                quantity: 1,
            }) => modbus::Response::Registers(vec![0xc0de]).to_pdu(3).unwrap(),
            _ => modbus::Exception::IllegalDataAddress.to_pdu(frame.function().unwrap_or(0)),
        };
        frame.reply(pdu).write(driver.reply()).unwrap();
        Ok(Flow::Continue)
    }
}

struct Gateway(Frames<modbus::Frame>);
impl Decode for Gateway {
    type Item = modbus::Frame;
    type Error = modbus::Error;
    const NAME: &'static str = "Modbus gateway";
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        self.0.decode(bytes, eof)
    }
}
impl Present for Gateway {
    fn summary(frame: &modbus::Frame) -> String {
        format!("Gateway transaction {}", frame.transaction)
    }
    fn fields(frame: &modbus::Frame, bytes: &[u8], layer: &mut Layer) {
        layer.field("Transaction", frame.transaction.to_string(), (0, 2));
        layer.field(
            "Protocol identifier",
            u16::from_be_bytes([bytes[2], bytes[3]]).to_string(),
            (2, 4),
        );
    }
}
fn registry() -> Registry {
    let mut registry = Registry::new();
    registry.register(
        "gateway",
        |selection| {
            if selection.transport == Transport::Tcp
                && [selection.ports.0, selection.ports.1].contains(&modbus::PORT)
            {
                Match::Yes
            } else {
                Match::No
            }
        },
        |_| [Gateway(Frames::new()), Gateway(Frames::new())],
    );
    registry
}

async fn read_planted_register(fcx: Cx) -> fictionet::Result {
    fcx.observe_protocols(registry());
    let (attacher, attachments) = fictionet::attachments();
    let address = Ipv4Addr::new(10, 30, 0, 3);
    Net::new()
        .ipv4_only()
        .host("plc", |host| {
            host.at(address).tcp(modbus::PORT, Arc::new(()), || Plc)
        })
        .start(&fcx, attachments)?;
    let cable = attacher.attach("operator")?;
    let (link, _udp, _icmp, _other) = ip::split_protocols(&fcx, cable);
    let client = tcp::endpoint(&fcx, link, Ipv4Addr::new(10, 0, 0, 2).into());
    let mut conn = client.connect(&fcx, (address, modbus::PORT).into()).await?;
    let mut request = modbus::Frame {
        transaction: 7,
        unit: 1,
        pdu: modbus::Request::ReadHoldingRegisters {
            address: 42,
            quantity: 1,
        }
        .to_pdu()?,
    }
    .to_bytes()?;
    request[3] = 1;
    assert!(fictionet::stdlib::modbus::Frame::parse(&request).is_err());
    conn.write_all(&fcx, &request).await?;
    let mut bytes = Vec::new();
    let reply = loop {
        if let Some((reply, _)) = modbus::Frame::parse_prefix(&bytes)? {
            break reply;
        }
        let mut buffer = [0; 256];
        let read = conn.read(&fcx, &mut buffer).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "gateway closed before replying",
            )
            .into());
        }
        bytes.extend_from_slice(&buffer[..read]);
    };
    assert_eq!(
        modbus::Response::parse(&reply.pdu)?,
        (3, modbus::Response::Registers(vec![0xc0de]))
    );
    let mut conversation = Conversation::with_registry(40000, modbus::PORT, registry());
    let mut packet = Decoded::default();
    conversation.data(
        false,
        &request,
        Place {
            offset: Some(0),
            len: request.len(),
            ..Place::default()
        },
        &mut packet,
        &[],
    );
    assert_eq!(packet.layers[0].summary, "Gateway transaction 7");
    println!(
        "Modbus gateway: register 42 = 0xc0de; {}",
        packet.layers[0].summary
    );
    fcx.cancel();
    Ok(())
}
fn main() -> fictionet::Result {
    block_on(lab(Seed::from_u64(7), read_planted_register))
}
