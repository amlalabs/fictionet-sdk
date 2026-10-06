//! The SOCKS5 proxy door (`fictionet attach --type socks5`), where the
//! agent is the client: the greeting, the username/password login and the
//! request, read from a stream in pieces of any size.
#![no_main]

use fictionet::stdlib::{codec::contract, socks::{ClientMessages, Greeting, AuthRequest, Request, MAX_MESSAGE}};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: fictionet_fuzz::doors::Input| {
    contract::check_decode_with_alloc_limit(ClientMessages::new, &input.bytes, 2 * MAX_MESSAGE);
    contract::check_wire::<Greeting>(&input.bytes);
    contract::check_wire::<AuthRequest>(&input.bytes);
    contract::check_wire::<Request>(&input.bytes);
    fictionet_fuzz::doors::socks5(input);
});
