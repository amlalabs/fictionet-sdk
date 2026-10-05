//! IGMP messages, as a world playing a host or a multicast router reads
//! them.
#![no_main]

use fictionet::stdlib::igmp::{Decoder, Message, checksum};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check(data);
    // The same bytes with the checksum set right, so the parser looks past
    // it.
    if data.len() >= 4 {
        let mut fixed = data.to_vec();
        fixed[2] = 0;
        fixed[3] = 0;
        let c = checksum(&fixed);
        fixed[2..4].copy_from_slice(&c.to_be_bytes());
        check(&fixed);
    }
});

fn check(data: &[u8]) {
    let parsed = Message::parse(data);

    // The message, fed two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    let _ = whole.feed(data);
    assert_eq!(whole.finish(), parsed);
    let mut bytewise = Decoder::new();
    for b in data {
        let _ = bytewise.feed(std::slice::from_ref(b));
    }
    assert_eq!(bytewise.finish(), parsed);

    if let Ok(m) = &parsed {
        // A message read can be written, and reads back the same.
        let bytes = m.to_bytes().unwrap();
        assert!(bytes.len() <= data.len());
        assert_eq!(checksum(&bytes), 0);
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(m));
    }
}
