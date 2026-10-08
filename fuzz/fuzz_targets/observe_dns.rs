#![no_main]
use libfuzzer_sys::fuzz_target;
use fictionet::observe::protocols::Dns;
use fictionet::stdlib::test_support::contract::check_decode;

fuzz_target!(|data: &[u8]| {
    check_decode(|| Dns::new(true), data);
    check_decode(|| Dns::new(false), data);
});
