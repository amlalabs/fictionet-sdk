//! NBDGM wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::{contract, Wire};
use fictionet::stdlib::nbdgm::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Name>(data);
    contract::check_wire::<Packet>(data);
    if let Ok(packet) = Packet::parse(data) {
        let mut reassembler = Reassembler::new();
        for fragment in packet.split(32).unwrap() {
            contract::check_wire_value(&fragment);
            let _ = reassembler.push(fragment);
        }
    }
});
