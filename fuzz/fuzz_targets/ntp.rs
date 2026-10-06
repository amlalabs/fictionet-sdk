//! NTP wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::{contract, Wire};
use fictionet::stdlib::ntp::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Packet>(data);
    contract::check_wire::<Timestamp>(data);
    contract::check_wire::<KissCode>(data);
    if let Ok(packet) = Packet::parse(data) {
        if let Ok(reply) = server_reply(&packet, &ServerInfo::default(), packet.receive, packet.transmit) {
            contract::check_wire_value(&reply);
        }
    }
});
