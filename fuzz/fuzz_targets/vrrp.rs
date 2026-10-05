//! VRRP advertisements, as a world playing a router reads them.
#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::vrrp::{Advertisement, Decoder, Endpoints, GROUP_V4, GROUP_V6, checksum};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ends = [
        Endpoints::V4 { source: Ipv4Addr::new(192, 168, 1, 2), destination: GROUP_V4 },
        Endpoints::V6 { source: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2), destination: GROUP_V6 },
    ];
    for e in &ends {
        check(data, e);
        // The same bytes with the checksum set right, so the parser looks
        // past it.
        if let Some(c) = checksum(data, e) {
            let mut fixed = data.to_vec();
            fixed[6..8].copy_from_slice(&c.to_be_bytes());
            check(&fixed, e);
        }
    }
});

fn check(data: &[u8], e: &Endpoints) {
    let parsed = Advertisement::parse(data, e);

    // The advertisement, fed two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new(*e);
    let _ = whole.feed(data);
    assert_eq!(whole.finish(), parsed);
    let mut bytewise = Decoder::new(*e);
    for b in data {
        let _ = bytewise.feed(std::slice::from_ref(b));
    }
    assert_eq!(bytewise.finish(), parsed);

    if let Ok(a) = &parsed {
        // An advertisement read can be written, and reads back the same.
        let bytes = a.to_bytes(e).unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(checksum(&bytes, e), Some(u16::from_be_bytes([bytes[6], bytes[7]])));
        assert_eq!(Advertisement::parse(&bytes, e).as_ref(), Ok(a));
    }
}
