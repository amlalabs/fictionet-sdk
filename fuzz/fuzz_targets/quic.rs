//! QUIC datagrams and frame payloads after protection is removed.
#![no_main]

use fictionet::stdlib::{
    codec::{Wire, contract},
    quic::{Datagram, Frame, Payload, Reassembler, VarInt},
};
use libfuzzer_sys::fuzz_target;

fn datagram<const N: usize>(bytes: &[u8]) {
    contract::check_wire::<Datagram<N>>(bytes);
    if let Ok(value) = Datagram::<N>::parse(bytes) {
        for packet in value.0 {
            if let Some(payload) = packet.payload() {
                contract::check_wire::<Payload>(payload);
            }
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&pick, bytes)) = input.split_first() else { return };
    contract::check_wire::<VarInt>(bytes);
    contract::check_wire::<Frame>(bytes);
    contract::check_wire::<Payload>(bytes);
    // Every legal short-header ID length, plus one past the limit.
    match pick % 22 {
        0 => datagram::<0>(bytes),
        1 => datagram::<1>(bytes),
        2 => datagram::<2>(bytes),
        3 => datagram::<3>(bytes),
        4 => datagram::<4>(bytes),
        5 => datagram::<5>(bytes),
        6 => datagram::<6>(bytes),
        7 => datagram::<7>(bytes),
        8 => datagram::<8>(bytes),
        9 => datagram::<9>(bytes),
        10 => datagram::<10>(bytes),
        11 => datagram::<11>(bytes),
        12 => datagram::<12>(bytes),
        13 => datagram::<13>(bytes),
        14 => datagram::<14>(bytes),
        15 => datagram::<15>(bytes),
        16 => datagram::<16>(bytes),
        17 => datagram::<17>(bytes),
        18 => datagram::<18>(bytes),
        19 => datagram::<19>(bytes),
        20 => datagram::<20>(bytes),
        _ => datagram::<21>(bytes),
    }
    let mut ordered = Reassembler::new();
    if ordered.insert(0, bytes).is_ok() {
        let mut reversed = Reassembler::new();
        for (offset, byte) in bytes.iter().enumerate().rev() {
            reversed.insert(offset as u64, std::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(ordered.read(), reversed.read());
    }
});
