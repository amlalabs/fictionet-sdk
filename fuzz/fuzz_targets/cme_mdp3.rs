//! CME MDP 3.0: generated SBE messages, hand-written packets, and the
//! size-prefixed message framer.
#![no_main]

use fictionet::stdlib::cme_mdp3::{Message, Messages, PACKET_HEADER, Packet};
use fictionet::stdlib::codec::contract::{check_decode_with_alloc_limit, check_wire};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 8192;

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    check_wire::<Message>(data);
    check_wire::<Packet>(data);
    check_decode_with_alloc_limit(|| Messages, data, 4 * usize::from(u16::MAX));
    if let Some(body) = data.get(PACKET_HEADER..) {
        check_decode_with_alloc_limit(|| Messages, body, 4 * usize::from(u16::MAX));
    }
});
