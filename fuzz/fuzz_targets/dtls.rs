//! DTLS wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::{contract, Wire};
use fictionet::stdlib::dtls::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Record<0>>(data);
    contract::check_wire::<Record<1>>(data);
    contract::check_wire::<Record<8>>(data);
    contract::check_wire::<Datagram<0>>(data);
    contract::check_wire::<Datagram<1>>(data);
    contract::check_wire::<Datagram<8>>(data);
    contract::check_wire::<Fragment>(data);
    contract::check_wire::<Fragments>(data);
    contract::check_wire::<Handshake>(data);
    contract::check_wire::<ClientHello>(data);
    contract::check_wire::<ServerHello>(data);
    contract::check_wire::<HelloVerifyRequest>(data);
    if let Ok(fragments) = Fragments::parse(data).map(|fragments| fragments.0) {
        let mut reassembler = Reassembler::new();
        for fragment in fragments {
            let _ = reassembler.add(&fragment);
            assert!(reassembler.buffered() <= MAX_REASSEMBLY_BYTES);
            while let Some(message) = reassembler.next_message() {
                contract::check_wire_value(&message);
            }
        }
    }
});
