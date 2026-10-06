//! WIREGUARD wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::wireguard::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Message>(data);
    contract::check_wire::<Initiation>(data);
    contract::check_wire::<Response>(data);
    contract::check_wire::<CookieReply>(data);
    contract::check_wire::<Data>(data);
    contract::check_wire::<Plaintext>(data);
    let mut window = ReplayWindow::new();
    for bytes in data.chunks_exact(8) {
        let counter = u64::from_le_bytes(bytes.try_into().unwrap());
        let before = window.clone();
        if window.accept(counter) { assert!(!window.accept(counter)); }
        else { assert_eq!(window, before); }
    }
});
