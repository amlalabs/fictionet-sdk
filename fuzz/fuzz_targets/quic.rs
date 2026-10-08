//! QUIC datagrams and frame payloads after protection is removed.
#![no_main]

use fictionet::stdlib::{
    codec::{Wire},
    test_support::contract,
    quic::{self, Datagram, Frame, Reassembler, VarInt},
};
use fictionet::stdlib::quic::harness::check_payload;
use libfuzzer_sys::fuzz_target;

fn datagram<const N: usize>(bytes: &[u8]) {
    contract::check_wire::<Datagram<N>>(bytes);
    let (packets, _) = quic::split_datagram(bytes, N);
    // With a legal ID length, every packet read can be written, together and one at a time.
    let writable = N <= 20;
    if !packets.is_empty() {
        let value = Datagram::<N>(packets.clone());
        contract::check_wire_value(&value);
        if writable {
            assert_eq!(quic::split_datagram(&value.to_bytes().unwrap(), N), (packets.clone(), None));
        }
    }
    for packet in packets {
        if let Some(payload) = packet.payload() {
            check_payload(payload);
        }
        let value = Datagram::<N>(vec![packet]);
        contract::check_wire_value(&value);
        let written = value.to_bytes();
        if writable {
            assert!(written.is_ok());
        }
        if let Ok(bytes) = written {
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
