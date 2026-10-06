//! QUIC datagrams and frame payloads after protection is removed.
#![no_main]

use fictionet::stdlib::{
    codec::{Wire, contract},
    quic::{self, Datagram, Frame, Payload, Reassembler, VarInt},
};
use libfuzzer_sys::fuzz_target;

fn check_payload(bytes: &[u8]) {
    contract::check_wire::<Payload>(bytes);
    if let Ok(payload) = Payload::parse(bytes) {
        assert!(payload.to_bytes().unwrap().len() <= bytes.len());
    }
}

fn datagram<const N: usize>(bytes: &[u8]) {
    contract::check_wire::<Datagram<N>>(bytes);
    let (packets, _) = quic::split_datagram(bytes, N);
    if !packets.is_empty() {
        contract::check_wire_value(&Datagram::<N>(packets.clone()));
    }
    for packet in packets {
        if let Some(payload) = packet.payload() {
            check_payload(payload);
        }
        let value = Datagram::<N>(vec![packet]);
        contract::check_wire_value(&value);
        if let Ok(bytes) = value.to_bytes() {
            assert_eq!(quic::Packet::parse(&bytes, N), Ok((value.0[0].clone(), bytes.len())));
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&pick, bytes)) = input.split_first() else { return };
    contract::check_wire::<VarInt>(bytes);
    contract::check_wire::<Frame>(bytes);
    check_payload(bytes);
    // Every legal short-header ID length, plus one past the limit.
    macro_rules! dispatch {
        ($($n:literal),* $(,)?) => {
            match pick % 22 {
                $($n => datagram::<$n>(bytes),)*
                _ => datagram::<21>(bytes),
            }
        };
    }
    dispatch!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20);
    let mut ordered = Reassembler::new();
    if ordered.insert(0, bytes).is_ok() {
        let mut reversed = Reassembler::new();
        for (offset, byte) in bytes.iter().enumerate().rev() {
            reversed.insert(offset as u64, std::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(ordered.read(), reversed.read());
    }
});
