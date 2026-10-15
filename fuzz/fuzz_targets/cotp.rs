//! TPKT packets and class 0 COTP TPDUs, as a world playing an ISO
//! transport server reads them.
#![no_main]

use fictionet::stdlib::cotp::harness;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check_buffer(data, 4096);
});
