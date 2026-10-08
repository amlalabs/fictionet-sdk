#![no_main]
use libfuzzer_sys::fuzz_target;
use fictionet::observe::protocols::Dhcp;
use fictionet::stdlib::test_support::contract::check_decode;

fuzz_target!(|data: &[u8]| {
    check_decode(Dhcp::default, data);
});
