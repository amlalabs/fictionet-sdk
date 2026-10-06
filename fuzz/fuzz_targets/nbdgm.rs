//! NetBIOS datagram service packets, as a world playing the machines on a
//! LAN reads them, and the reassembler that puts fragments back together.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::nbdgm::{ErrorCode, MAX_PENDING, Name, Packet, Reassembler};
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Name>(data);
    contract::check_wire::<Packet>(data);

    let here = Ipv4Addr::new(10, 0, 0, 1);
    let mut reassembler = Reassembler::new();
    // Check short prefixes and the whole datagram with bounded prefix work.
    for n in (0..=data.len().min(256)).chain((data.len() > 256).then_some(data.len())) {
        let Ok(p) = Packet::parse(&data[..n]) else {
            continue;
        };
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.to_bytes().unwrap(), bytes);
        // Replies and fragments read back too.
        for present in [true, false] {
            if let Some(r) = p.query_response(here, 138, present) {
                contract::check_wire_value(&r);
                assert!(r.to_bytes().is_ok());
            }
        }
        let e = p.error(here, 138, ErrorCode::DestinationNameNotPresent);
        contract::check_wire_value(&e);
        assert!(e.to_bytes().is_ok());
        let mut whole = None;
        for f in p.split(1 + n % 64).unwrap() {
            contract::check_wire_value(&f);
            assert!(f.to_bytes().is_ok());
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
