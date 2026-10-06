//! Copy `src/stdlib/modbus.rs` here, edit it, and plug it into the codec tools.
//! The copied file's `fictionet::stdlib::...` imports need no change.
//! Its marked edit adds `Frame::planted_reply`: register 42 holds 0xc0de.
//! `Stream` and `Decode::map` drive the copy; `Wire` writes its replies.
//! Run with `cargo run --example custom_protocol`. No network or root is needed.
//! Compare the files with `diff -u src/stdlib/modbus.rs examples/custom_protocol/modbus.rs`.

#[allow(dead_code)]
mod modbus;

use fictionet::stdlib::codec::{Decode, Stream, Wire, finish, pump, try_pump};
use fictionet::stdlib::modbus as client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = client::Frame {
        transaction: 7,
        unit: 1,
        pdu: client::Request::ReadHoldingRegisters {
            address: 42,
            quantity: 1,
        }
        .to_pdu()?,
    };
    let mut bytes = Vec::new();
    request.write(&mut bytes)?;

    let mut server = Stream::new(modbus::Frames.map(|frame| frame.planted_reply()));
    let mut reply_bytes = Vec::new();
    for chunk in bytes.chunks(3) {
        let taken = try_pump(&mut server, chunk, |reply| reply?.write(&mut reply_bytes))?;
        if taken != chunk.len() {
            return Err("the copied server stopped before reading the request".into());
        }
    }
    finish(&mut server, |_| {})?;

    let mut replies = Stream::new(client::Frames);
    let mut received = Vec::new();
    pump(&mut replies, &reply_bytes, |frame| received.push(frame))?;
    finish(&mut replies, |frame| received.push(frame))?;
    let [reply] = received.as_slice() else {
        return Err("expected one reply from the copied server".into());
    };
    let (function, response) = client::Response::parse(&reply.pdu)?;
    if reply.transaction != request.transaction
        || reply.unit != request.unit
        || function != client::function::READ_HOLDING_REGISTERS
    {
        return Err("the reply did not match the request".into());
    }
    let client::Response::Registers(values) = response else {
        return Err("expected a register response".into());
    };
    let [value] = values.as_slice() else {
        return Err("expected one register value".into());
    };
    if *value != 0xc0de {
        return Err("the copied server returned the wrong value".into());
    }
    println!("Copied Modbus server: holding register 42 = 0x{value:04x} ({value})");
    Ok(())
}
