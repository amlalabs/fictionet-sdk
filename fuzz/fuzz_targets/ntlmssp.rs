//! NTLMSSP wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::ntlmssp::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Version>(data);
    contract::check_wire::<UnicodeName>(data);
    contract::check_wire::<MicInput>(data);
    contract::check_wire::<AvPairs>(data);
    contract::check_wire::<Negotiate>(data);
    contract::check_wire::<Challenge>(data);
    contract::check_wire::<Authenticate>(data);
    contract::check_wire::<Message>(data);
    contract::check_wire::<LmV2Response>(data);
    contract::check_wire::<NtResponse>(data);
    contract::check_wire::<NtlmV2Response>(data);
    contract::check_wire::<ClientChallenge>(data);
    contract::check_wire::<AvPair>(data);
});
