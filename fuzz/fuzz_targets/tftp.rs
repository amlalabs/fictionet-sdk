//! TFTP wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::tftp::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Packet>(data);
    contract::check_wire::<NetasciiByte>(data);
    contract::check_decode_with_alloc_limit(|| Netascii, data, 4);
});
