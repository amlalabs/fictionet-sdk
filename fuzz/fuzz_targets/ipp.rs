//! IPP heads, documents, and attribute values.
#![no_main]

use fictionet::stdlib::ipp::harness;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check(data);
});
