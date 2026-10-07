//! SSE dispatch, ID/retry state, bounded event assembly, and strict writing.
#![no_main]

use fictionet::stdlib::codec::{
    Wire,
    contract::{check_decode, check_decode_with_held_limit, check_wire, check_wire_value},
    test_support::decode_all,
};
use fictionet::stdlib::sse::{Event, Events, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_decode(Events::default, data);
    check_decode_with_held_limit(
        || {
            Events::with_limits(Limits {
                line: 32,
                event: 128,
            })
        },
        data,
        192,
    );
    check_decode(|| Events::with_limits(Limits { line: 0, event: 0 }), data);
    check_wire::<Event>(data);
    for event in decode_all(Events::default, data).0 {
        check_wire_value(&event);
        let bytes = event.to_bytes().unwrap();
        assert_eq!(decode_all(Events::default, &bytes), (vec![event], None));
    }
    let text = String::from_utf8_lossy(data).into_owned();
    check_wire_value(&Event::new(text.clone()));
    check_wire_value(&Event {
        event: text.clone(),
        data: "x".into(),
        id: String::new(),
    });
    check_wire_value(&Event {
        event: "message".into(),
        data: "x".into(),
        id: text,
    });
});
