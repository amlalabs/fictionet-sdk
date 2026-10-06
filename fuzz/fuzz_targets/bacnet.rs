//! BACNET wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::bacnet::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Bvlc>(data);
    contract::check_wire::<Npdu>(data);
    contract::check_wire::<Apdu>(data);
    contract::check_wire::<Tag>(data);
    contract::check_wire::<Value>(data);
    contract::check_wire::<Values>(data);
    contract::check_wire::<WhoIs>(data);
    contract::check_wire::<IAm>(data);
    contract::check_wire::<ContextValue<0>>(data);
    contract::check_wire::<ContextValue<1>>(data);
    contract::check_wire::<ContextValue<2>>(data);
    contract::check_wire::<ContextValue<3>>(data);
    contract::check_wire::<ContextValue<4>>(data);
    contract::check_wire::<ContextValue<5>>(data);
    contract::check_wire::<ContextValue<6>>(data);
    contract::check_wire::<ContextValue<7>>(data);
    contract::check_wire::<ContextValue<8>>(data);
    contract::check_wire::<ContextValue<9>>(data);
    contract::check_wire::<ContextValue<10>>(data);
    contract::check_wire::<ContextValue<11>>(data);
    contract::check_wire::<ContextValue<12>>(data);
});
