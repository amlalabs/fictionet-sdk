//! IKE wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::ike::*;
use libfuzzer_sys::fuzz_target;

fn check_chain(first: u8, data: &[u8]) {
    if let Ok(payloads) = parse_payloads(first, data) {
        let message = Message {
            initiator_spi: 0, responder_spi: 0, minor_version: 0,
            exchange: exchange::INFORMATIONAL, flags: 0, message_id: 0,
            payloads: payloads.clone(),
        };
        contract::check_wire_value(&message);
        let bytes = message.to_bytes().unwrap();
        assert_eq!(bytes[16], first);
        assert_eq!(parse_payloads(first, &bytes[HEADER_LEN..]), Ok(payloads));
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Header>(data);
    contract::check_wire::<Message>(data);
    contract::check_wire::<NatT>(data);
    check_chain(33, data);
    check_chain(40, data);
    check_chain(41, data);
    check_chain(46, data);
    if let Ok(message) = Message::parse(data) {
        let bytes = message.to_bytes().unwrap();
        for n in 0..bytes.len().min(200) {
            assert_eq!(Message::parse(&bytes[..n]), Err(Error::Short));
        }
        let natt = NatT::Ike(message);
        contract::check_wire_value(&natt);
        assert!(natt.to_bytes().is_ok());
    }
    if let Some((&first, rest)) = data.split_first() {
        check_chain(first, rest);
    }
    for n in 0..data.len().min(200) {
        let _ = Message::parse(&data[..n]);
        let _ = NatT::parse(&data[..n]);
    }
});
