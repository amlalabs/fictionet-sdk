//! DNS messages, as the world's DNS server and attach's resolver read
//! them (hickory-proto's `Message`), and the resolver's check of an answer.
#![no_main]

use fictionet::stdlib::protocols::dns::op::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Message::from_vec(data) {
        // Write unless the questions alone exceed 65535 bytes, then reparse.
        // Values must match, or dropped records must set TC and retain a
        // prefix of each record section.
        fictionet_fuzz::dns::round_trip(&m);
        for q in &m.queries {
            let _ = q.name().to_ascii();
        }
    }
    fictionet_fuzz::doors::dns_answer(data);
});
