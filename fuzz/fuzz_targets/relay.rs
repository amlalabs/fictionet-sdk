//! The relay protocol's decoder: every message from `fictionet attach`,
//! which forwards the agent's packets.
#![no_main]

use fictionet::relay::{Message, decode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(message) = decode(data) else { return };
    // What decodes, encodes back to the same bytes. A `hello` whose kind or
    // name is longer than 255 bytes cannot decode, so nothing is cut.
    let bytes = message.encode();
    assert_eq!(bytes, data);
    assert_eq!(decode(&bytes), Ok(message.clone()));
    if let Message::Hello(h) = message {
        assert!(h.kind.is_ascii() && h.kind.len() <= 255 && h.name.len() <= 255);
    }
});
