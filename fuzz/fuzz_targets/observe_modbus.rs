#![no_main]
use libfuzzer_sys::fuzz_target;
use fictionet::observe::protocols::Modbus;
use fictionet::stdlib::codec::contract::check_decode;

fuzz_target!(|data: &[u8]| {
    check_decode(|| Modbus::new(true), data);
    check_decode(|| Modbus::new(false), data);
});
