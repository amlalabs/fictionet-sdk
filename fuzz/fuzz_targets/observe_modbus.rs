#![no_main]
use fictionet::observe::protocols::Modbus;
use fictionet::stdlib::test_support::contract::check_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_decode(|| Modbus::new(true), data);
    check_decode(|| Modbus::new(false), data);
});
