//! VXLAN and VXLAN-GPE datagrams, as a world playing a tunnel endpoint
//! reads them.
#![no_main]

use fictionet::stdlib::vxlan::{Error, GpePacket, HEADER_LEN, MAX_DATAGRAM, MAX_PAYLOAD, Packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as a VXLAN datagram. A packet read can be written, at the
    // same length, and reads back the same.
    if let Ok(p) = Packet::parse(data) {
        assert!(p.frame.len() <= MAX_PAYLOAD);
        assert_eq!(p.frame, data[HEADER_LEN..]);
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(Packet::parse(&bytes), Ok(p));
    }

    // The bytes as a VXLAN-GPE datagram, the same way.
    if let Ok(g) = GpePacket::parse(data) {
        assert_eq!(g.payload, data[HEADER_LEN..]);
        let bytes = g.to_bytes();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(GpePacket::parse(&bytes), Ok(g));
    }

    // The datagram growing a byte at a time: each prefix reads or fails
    // without a panic. One shorter than the header is Truncated, and the
    // header decides alike for every prefix that holds it. Only the header
    // decides, so the first bytes are enough.
    let whole = (Packet::parse(data).map(|_| ()), GpePacket::parse(data).map(|_| ()));
    for n in 0..data.len().min(4 * HEADER_LEN) {
        let prefix = (Packet::parse(&data[..n]).map(|_| ()), GpePacket::parse(&data[..n]).map(|_| ()));
        if n < HEADER_LEN {
            assert_eq!(prefix, (Err(Error::Truncated(n)), Err(Error::Truncated(n))));
        } else if data.len() <= MAX_DATAGRAM {
            assert_eq!(prefix, whole);
        }
    }
});
