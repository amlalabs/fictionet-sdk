//! Geneve datagrams, as a world playing a tunnel endpoint reads them.
#![no_main]

use fictionet::stdlib::geneve::{Decoder, Header, Packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = Packet::parse(data);

    // The datagram, fed two ways: all at once, and a byte at a time.
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
        // A reply on the same network can always be written.
        let reply = p.reply(payload.to_vec());
        assert!(Packet::parse(&reply.to_bytes().unwrap()).is_ok());
    }
    // Any bytes as the start of a header on their own.
    let _ = Header::parse_prefix(data);
});
