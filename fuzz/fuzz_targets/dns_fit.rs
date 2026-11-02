//! DNS replies written within a size limit: `fit` stays within the limit,
//! and what it writes parses back with whole RRsets.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fictionet_fuzz::dns::fit_reply(data);
});
