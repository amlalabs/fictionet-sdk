//! JSON texts, bounded values, and streams used by web APIs.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::json::{self, Limits, Value, Values};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let (limits, data) = match input {
        [a, b, rest @ ..] if a & 0x80 != 0 => (
            Limits {
                depth: usize::from(a & 0x0f),
                size: usize::from(*b) * 4,
                elements: usize::from(a >> 4 & 0x07) * 4 + 1,
            },
            rest,
        ),
        [_, _, rest @ ..] => (Limits::default(), rest),
        _ => (Limits::default(), input),
    };
    let make = || Values::with_limits(limits);
    let bound = 2 * make().capacity();
    assert_eq!(
        decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= bound);
        }),
        decode_all(make, data),
    );
    if let Ok(value) = <Value as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let (values, error) = decode_all(make, data);
    for value in &values {
        let _ = assert_write(value);
        assert!(value.validate(&limits).is_ok());
        let bytes = value.to_bytes().unwrap();
        assert_eq!(json::parse_with(&bytes, &limits).as_ref(), Ok(value));
    }
    if let Ok(value) = json::parse_with(data, &limits) {
        let _ = assert_write(&value);
        assert_eq!((values, error), (vec![value], None));
    }
});
