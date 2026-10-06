//! IKE wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::ike::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Header>(data);
    contract::check_wire::<Message>(data);
    contract::check_wire::<NatT>(data);
    contract::check_wire::<Payloads<33>>(data);
    contract::check_wire::<Payloads<40>>(data);
    contract::check_wire::<Payloads<41>>(data);
    contract::check_wire::<Payloads<46>>(data);
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
        // The runtime reader still accepts any first type, including unknown types.
        let _ = parse_payloads(first, rest);
        match first {
            0 => contract::check_wire::<Payloads<0>>(rest),
            1 => contract::check_wire::<Payloads<1>>(rest),
            33 => contract::check_wire::<Payloads<33>>(rest),
            34 => contract::check_wire::<Payloads<34>>(rest),
            35 => contract::check_wire::<Payloads<35>>(rest),
            36 => contract::check_wire::<Payloads<36>>(rest),
            37 => contract::check_wire::<Payloads<37>>(rest),
            38 => contract::check_wire::<Payloads<38>>(rest),
            39 => contract::check_wire::<Payloads<39>>(rest),
            40 => contract::check_wire::<Payloads<40>>(rest),
            41 => contract::check_wire::<Payloads<41>>(rest),
            42 => contract::check_wire::<Payloads<42>>(rest),
            43 => contract::check_wire::<Payloads<43>>(rest),
            44 => contract::check_wire::<Payloads<44>>(rest),
            45 => contract::check_wire::<Payloads<45>>(rest),
            46 => contract::check_wire::<Payloads<46>>(rest),
            47 => contract::check_wire::<Payloads<47>>(rest),
            48 => contract::check_wire::<Payloads<48>>(rest),
            49 => contract::check_wire::<Payloads<49>>(rest),
            50 => contract::check_wire::<Payloads<50>>(rest),
            51 => contract::check_wire::<Payloads<51>>(rest),
            52 => contract::check_wire::<Payloads<52>>(rest),
            53 => contract::check_wire::<Payloads<53>>(rest),
            54 => contract::check_wire::<Payloads<54>>(rest),
            127 => contract::check_wire::<Payloads<127>>(rest),
            255 => contract::check_wire::<Payloads<255>>(rest),
            _ => {}
        }
    }
    for n in 0..data.len().min(200) {
        let _ = Message::parse(&data[..n]);
        let _ = NatT::parse(&data[..n]);
    }
});
