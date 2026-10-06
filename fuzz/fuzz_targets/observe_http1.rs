#![no_main]
use libfuzzer_sys::fuzz_target;
use fictionet::observe::protocols::Http1;
use fictionet::stdlib::codec::contract::check_decode;

fuzz_target!(|data: &[u8]| {
    check_decode(Http1::default, data);
});
