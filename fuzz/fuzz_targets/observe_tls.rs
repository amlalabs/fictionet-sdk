#![no_main]
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::dissect::protocols::TlsRecords;
use fictionet::stdlib::test_support::{chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(TlsRecords::default()),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(TlsRecords::default, data),
    );
});
