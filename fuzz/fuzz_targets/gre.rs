//! GRE packets, plain and PPTP, as a world playing a tunnel endpoint reads
//! them.
#![no_main]

use fictionet::stdlib::gre::{Header, Packet};
use fictionet::stdlib::{codec::{Wire, Collect}, test_support::contract, gre};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(|| Collect::<gre::Packet>::new(gre::MAX_PACKET), data, 2 * (gre::MAX_PACKET + 1));
    contract::check_wire::<gre::Packet>(data);

    let payload = data.iter().take(gre::MAX_PACKET + 1).copied().collect();
    let packet = Packet {
        header: Header::Pptp(gre::PptpHeader {
            call_id: 1,
            sequence: data.first().copied().map(u32::from),
            ack: None,
        }),
        payload,
    };
    contract::check_wire_value(&packet);

    let parsed = Packet::parse(data);

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
