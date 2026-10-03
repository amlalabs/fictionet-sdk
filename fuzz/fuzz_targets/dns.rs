//! DNS messages, as the world's DNS server and attach's resolver read
//! them (hickory-proto's `Message`), and the resolver's check of an answer.
#![no_main]

use fictionet::stdlib::dns::op::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = Message::from_vec(data) {
        // What was read can be written, and that reads again.
        if let Ok(bytes) = m.to_vec() {
            let _ = Message::from_vec(&bytes);
        }
        for q in &m.queries {
            let _ = q.name().to_ascii();
        }
    }
    fictionet_fuzz::doors::dns_answer(data);
});
