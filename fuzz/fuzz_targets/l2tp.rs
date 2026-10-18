//! L2TP wire units and their codec contracts.
#![no_main]

use fictionet::stdlib::protocols::l2tp::harness;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check(data);
});
