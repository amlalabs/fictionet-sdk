//! DNS queries as a server receives them: `Request::parse` over UDP and
//! TCP never panics and gives exactly one outcome that agrees with the
//! bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fictionet_fuzz::dns::parse_request(data);
});
