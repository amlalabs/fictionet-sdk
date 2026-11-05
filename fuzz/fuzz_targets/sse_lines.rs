//! SSE raw fields, comments, ignored fields, UTF-8, and line boundaries.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::sse::{Line, RawLines};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(RawLines::default()),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(RawLines::default, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(RawLines::with_limit(32)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert_eq!(s.held(), 0);
            }
        ),
        decode_all(|| RawLines::with_limit(32), data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(RawLines::with_limit(0)),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| RawLines::with_limit(0), data),
    );
    if let Ok(value) = <Line as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    for line in decode_all(RawLines::default, data).0 {
        let _ = assert_write(&line);
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
        let _ = assert_write(&line);
    }
});
