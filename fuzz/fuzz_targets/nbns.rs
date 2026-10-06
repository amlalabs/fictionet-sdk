//! NBNS wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::nbns::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Name>(data);
    contract::check_wire::<RrName>(data);
    contract::check_wire::<Packet>(data);
});
