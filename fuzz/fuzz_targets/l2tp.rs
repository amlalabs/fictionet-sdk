//! L2TP wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::l2tp::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Avp>(data);
    contract::check_wire::<ControlMessage>(data);
    contract::check_wire::<V2Packet>(data);
    contract::check_wire::<V3Control>(data);
    contract::check_wire::<V3Data<0>>(data);
    contract::check_wire::<V3Data<4>>(data);
    contract::check_wire::<V3Data<8>>(data);
    contract::check_wire::<Packet>(data);
    contract::check_wire_value(&ControlMessage::zlb());
    assert!(ControlMessage::zlb().to_bytes().is_ok());
    for n in 0..=data.len().min(256) {
        let part = Packet::parse(&data[..n]);
        if n < 2 {
            assert_eq!(part, Err(Error::Truncated));
        }
        let _ = ControlMessage::parse(&data[..n]);
    }
    if let Ok(message) = ControlMessage::parse(data) {
        let control = V3Control::new(1, 2, 3, &message).unwrap();
        contract::check_wire_value(&control);
        assert!(control.to_bytes().is_ok());
        assert_eq!(control.message(), Ok(message.clone()));
        let body = message.to_bytes().unwrap();
        if !body.is_empty() {
            let long = body.repeat(MAX_MESSAGE / body.len() + 1);
            let control = V3Control {
                connection: 1,
                ns: 0,
                nr: 0,
                payload: long,
            };
            contract::check_wire_value(&control);
            assert_eq!(control.to_bytes(), Err(Error::Unwritable));
        }
    }
    let byte = |i: usize| data.get(i).copied().unwrap_or(0);
    let code = u16::from_be_bytes([byte(0), byte(1)]);
    assert_eq!(MessageType::from_code(code).code(), code);
    let avp = Avp {
        mandatory: byte(2) & 1 != 0,
        hidden: byte(2) & 2 != 0,
        reserved: byte(3),
        vendor: u16::from(byte(4)),
        attribute: code,
        value: data[..data.len().min(MAX_AVP_VALUE + 1)].to_vec(),
    };
    contract::check_wire_value(&avp);
    let message = ControlMessage {
        message_type: (byte(2) & 4 != 0).then(|| MessageType::from_code(code)),
        mandatory: byte(2) & 1 != 0,
        vendor: u16::from(byte(4)),
        reserved: byte(5),
        avps: vec![avp],
    };
    contract::check_wire_value(&message);
    let packet = V2Packet {
        control: byte(2) & 1 != 0,
        has_length: byte(2) & 2 != 0,
        sequence: (byte(2) & 4 != 0).then_some((code, 0)),
        offset_pad: (byte(2) & 8 != 0).then_some(vec![byte(3)]),
        priority: byte(2) & 16 != 0,
        tunnel: code,
        session: code,
        payload: data[..data.len().min(MAX_DATAGRAM + 1)].to_vec(),
    };
    contract::check_wire_value(&packet);
    let cookie = data[..data.len().min(12)].to_vec();
    macro_rules! cookie {
        ($len:expr) => {
            contract::check_wire_value(&V3Data::<$len> {
                session: 1,
                cookie,
                payload: vec![],
            })
        };
    }
    match cookie.len() {
        4 => cookie!(4),
        8 => cookie!(8),
        _ => cookie!(0),
    }
});
