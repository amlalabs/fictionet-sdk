//! FastCGI records, name and value pairs, and requests and responses put
//! back together, as a world playing an application or a web server reads
//! them.
#![no_main]

use fictionet::stdlib::fastcgi::harness;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check(data);
});
