//! JSON texts, bounded values, and streams used by web APIs.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};
use fictionet::stdlib::json::{self, Limits, Value, Values};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let (limits, data) = match input {
        [a, b, rest @ ..] if a & 0x80 != 0 => (
            Limits { depth: usize::from(a & 0x0f), size: usize::from(*b) * 4,
                elements: usize::from(a >> 4 & 0x07) * 4 + 1 }, rest),
        [_, _, rest @ ..] => (Limits::default(), rest),
        _ => (Limits::default(), input),
    };
    let make = || Values::with_limits(limits);
    contract::check_decode_with_alloc_limit(make, data, 2 * make().capacity());
    contract::check_wire::<Value>(data);
    let (values, error) = decode_all(make, data);
    for value in &values {
        contract::check_wire_value(value);
        // Canonical escaping can exceed a tight input-size cap.
        if value.validate(&limits).is_ok() {
            let bytes = value.to_bytes().unwrap();
            assert_eq!(json::parse_with(&bytes, &limits).as_ref(), Ok(value));
        }
    }
    if let Ok(value) = json::parse_with(data, &limits) {
        contract::check_wire_value(&value);
        assert_eq!((values, error), (vec![value], None));
    }
});
