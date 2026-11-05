//! SSE dispatch, ID/retry state, bounded event assembly, and strict writing.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::sse::{Event, Events, Limits};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Events::default()),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(Events::default, data),
    );
    let limited = || {
        Events::with_limits(Limits {
            line: 32,
            event: 128,
        })
    };
    assert_eq!(
        decode_chunks(
            &mut Stream::new(limited()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.held() <= 192);
            }
        ),
        decode_all(limited, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Events::with_limits(Limits { line: 0, event: 0 })),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| Events::with_limits(Limits { line: 0, event: 0 }), data),
    );
    if let Ok(value) = <Event as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    for event in decode_all(Events::default, data).0 {
        let _ = assert_write(&event);
        let bytes = event.to_bytes().unwrap();
        assert_eq!(decode_all(Events::default, &bytes), (vec![event], None));
    }
    let text = String::from_utf8_lossy(data).into_owned();
    let _ = assert_write(&Event::new(text.clone()));
    let _ = assert_write(&Event {
        event: text.clone(),
        data: "x".into(),
        id: String::new(),
    });
    let _ = assert_write(&Event {
        event: "message".into(),
        data: "x".into(),
        id: text,
    });
});
