//! Recoverable JSON-RPC stdio lines, boundaries, limits, and reply writes.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};
use fictionet::stdlib::{
    json::Limits,
    jsonrpc::{Message, Messages},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let (max, limits, data) = match input {
        [a, b, rest @ ..] if a & 0x80 != 0 => (
            usize::from(*b) * 4,
            Limits {
                size: usize::from(*b) * 4,
                depth: usize::from(a & 15),
                elements: usize::from(a >> 4 & 7) * 8 + 1,
            },
            rest,
        ),
        _ => (4096, Limits::default(), input),
    };
    let make = || Messages::with_limits(max, limits);
    contract::check_decode_with_alloc_limit(make, data, 2 * make().capacity());
    contract::check_decode_with_held_limit(make, data, 0);
    contract::check_wire::<Message>(data);
    let (items, failure) = decode_all(make, data);
    assert_eq!(failure, None);
    for item in items {
        match item {
            Ok(message) => {
                contract::check_wire_value(&message);
                let mut bytes = Vec::new();
                message.write_line(&mut bytes).unwrap();
                assert_eq!(decode_all(make, &bytes), (vec![Ok(message)], None));
            }
            Err(error) => contract::check_wire_value(&Message::Response(error.response())),
        }
    }
    // Direct envelope edits must either round-trip or refuse transactionally.
    if let Ok(value) = fictionet::stdlib::json::Value::parse(data) {
        let message = Message::Response(fictionet::stdlib::jsonrpc::Response { value });
        contract::check_wire_value(&message);
        let mut out = vec![42];
        if message.write_line(&mut out).is_err() {
            assert_eq!(out, [42]);
        }
    }
});
