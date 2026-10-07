//! SSE raw fields, comments, ignored fields, UTF-8, and line boundaries.
#![no_main]

use fictionet::stdlib::codec::{
    Wire,
    contract::{check_decode, check_decode_with_held_limit, check_wire, check_wire_value},
    test_support::decode_all,
};
use fictionet::stdlib::sse::{Line, RawLines};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_decode(RawLines::default, data);
    check_decode_with_held_limit(|| RawLines::with_limit(32), data, 0);
    check_decode(|| RawLines::with_limit(0), data);
    check_wire::<Line>(data);
    for line in decode_all(RawLines::default, data).0 {
        check_wire_value(&line);
        // A field name with a later BOM cannot be encoded at stream start.
        if let Ok(bytes) = line.to_bytes() {
            assert_eq!(decode_all(RawLines::default, &bytes), (vec![line], None));
        }
    }
    let text = String::from_utf8_lossy(data).into_owned();
    for line in [
        Line::Comment(text.clone()),
        Line::Data(text.clone()),
        Line::Event(text.clone()),
        Line::Id(text.clone()),
        Line::Retry(text.clone()),
        Line::Ignored {
            name: text.clone(),
            value: text,
        },
    ] {
        check_wire_value(&line);
    }
});
