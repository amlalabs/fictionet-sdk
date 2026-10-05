//! GRE packets, plain and PPTP, as a world playing a tunnel endpoint reads
//! them.
#![no_main]

use fictionet::stdlib::gre::{Decoder, Header, Packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = Packet::parse(data);

    // The packet, fed two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    let _ = whole.feed(data);
    assert_eq!(whole.finish(), parsed);
    let mut bytewise = Decoder::new();
    for b in data {
        let _ = bytewise.feed(std::slice::from_ref(b));
    }
    assert_eq!(bytewise.finish(), parsed);

    if let Ok(p) = &parsed {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
        assert!(bytes.len() <= data.len());
        assert_eq!(Packet::parse(&bytes).as_ref(), Ok(p));
        let (header, payload) = Header::split(data).unwrap();
        assert_eq!(&header, &p.header);
        assert_eq!(payload, &p.payload[..]);
        if let Header::Pptp(h) = &p.header {
            // RFC 2637 section 4.1: the flags bits 9 to 12 are zero, and
            // the S bit is set exactly when a payload is present.
            assert_eq!(data[1] & 0x78, 0);
            assert_eq!(h.sequence.is_some(), !p.payload.is_empty());
        }
    }
    // Any bytes as the start of a header on their own. An error there is
    // the error of the whole.
    if let Err(e) = Header::parse_prefix(data) {
        assert_eq!(parsed, Err(e));
    }
});
