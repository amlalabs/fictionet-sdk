//! NetBIOS session packets, as a world playing a file server on port 139
//! reads them.
#![no_main]

use fictionet::stdlib::nbss::{Decoder, Name, Packet, decode_first_level};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(Ok(p)) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(p)) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);

    // A small limit reads the same packets, up to the first one too long.
    let mut small = Decoder::with_limit(64);
    small.feed(data);
    let mut limited = Vec::new();
    while let Some(Ok(p)) = small.next_packet() {
        limited.push(p);
    }
    assert_eq!(&packets[..limited.len()], &limited[..]);

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
        let (back, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, p);
        assert_eq!(used, bytes.len());
    }
    // Any bytes as a name on their own.
    if let Some((name, used)) = Name::parse(data) {
        assert_eq!(name.to_bytes(), data[..used]);
    }
    let _ = decode_first_level(data);
});
