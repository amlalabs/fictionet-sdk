//! NetBIOS datagram service packets, as a world playing the machines on a
//! LAN reads them, and the reassembler that puts fragments back together.
#![no_main]

use fictionet::stdlib::nbdgm::{ErrorCode, MAX_PENDING, Packet, Reassembler};
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

fuzz_target!(|data: &[u8]| {
    let here = Ipv4Addr::new(10, 0, 0, 1);
    let mut reassembler = Reassembler::new();
    // The whole input as one datagram, and every prefix of it, as if it
    // came one byte more at a time.
    for n in 0..=data.len() {
        let Ok(p) = Packet::parse(&data[..n]) else { continue };
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.to_bytes(), bytes);
        // Replies and fragments read back too.
        if let Some(r) = p.query_response(here, 138, true) {
            assert_eq!(Packet::parse(&r.to_bytes()).unwrap(), r);
        }
        let e = p.error(here, 138, ErrorCode::DestinationNameNotPresent);
        assert_eq!(Packet::parse(&e.to_bytes()).unwrap(), e);
        let mut whole = None;
        for f in p.split(1 + n % 64) {
            assert_eq!(Packet::parse(&f.to_bytes()).unwrap(), f);
            if let Some(w) = reassembler.push(f) {
                assert!(w.flags.first && !w.flags.more);
                whole = Some(w);
            }
            assert!(reassembler.pending() <= MAX_PENDING);
        }
        // The fragments of a datagram put back together give its data.
        if let Some(d) = p.as_datagram() {
            let got = whole.as_ref().and_then(Packet::as_datagram).map(|w| &w.data);
            assert_eq!(got, Some(&d.data));
        }
    }
});
