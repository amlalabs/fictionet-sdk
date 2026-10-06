//! IKE wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::contract;
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
});
