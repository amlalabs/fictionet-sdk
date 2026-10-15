//! Internet Message Format headers and structured field values.
#![no_main]

use fictionet::stdlib::imf::harness;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check_message(data);
    harness::check_value(&String::from_utf8_lossy(data));
});
