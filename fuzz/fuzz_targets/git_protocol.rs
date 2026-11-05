//! Git packets and payloads through shared contracts.
#![no_main]
use fictionet::stdlib::protocols::git_protocol::{MAX_DATA, Packet, harness};
use fictionet::stdlib::test_support::assert_write;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check(data);
    let _ = assert_write(&Packet::Data(data[..data.len().min(MAX_DATA + 1)].to_vec()));
});
