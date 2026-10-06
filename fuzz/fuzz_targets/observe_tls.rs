#![no_main]
use libfuzzer_sys::fuzz_target;
use fictionet::observe::protocols::TlsRecords;
use fictionet::stdlib::codec::contract::check_decode;

fuzz_target!(|data: &[u8]| {
    check_decode(TlsRecords::default, data);
});
