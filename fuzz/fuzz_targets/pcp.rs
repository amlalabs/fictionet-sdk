//! PCP wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::pcp::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Request>(data);
    contract::check_wire::<Response>(data);
    contract::check_wire::<NatPmpRequest>(data);
    contract::check_wire::<NatPmpResponse>(data);
    contract::check_wire::<Reply>(data);
    for speaks in [Speaks::Both, Speaks::Pcp, Speaks::NatPmp] {
        if let Incoming::Reply(reply) = receive(data, speaks, std::net::Ipv4Addr::LOCALHOST.into(), 1) {
            contract::check_wire_value(&reply);
        }
    }
});
