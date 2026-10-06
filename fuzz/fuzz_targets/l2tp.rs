//! L2TP wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::contract;
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
});
