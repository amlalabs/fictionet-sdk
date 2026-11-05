#![no_main]
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::dissect::protocols::Modbus;
use fictionet::stdlib::test_support::{chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Modbus::new(true)),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| Modbus::new(true), data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Modbus::new(false)),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| Modbus::new(false), data),
    );
});
