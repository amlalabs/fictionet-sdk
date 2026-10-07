//! PIM version 2 messages, as a world playing a multicast router reads
//! them.
#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::pim::{
    ALL_PIM_ROUTERS_V4, ALL_PIM_ROUTERS_V6, CandidateRp, Endpoints, Message, Error, checksum,
};
use fictionet::stdlib::{codec::{Wire, Collect, Decode, contract}, pim};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ends = [
        Endpoints::V4 { source: Ipv4Addr::new(10, 0, 0, 2), destination: ALL_PIM_ROUTERS_V4 },
        Endpoints::V6 { source: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2), destination: ALL_PIM_ROUTERS_V6 },
    ];
    for e in &ends {
        check(data, e);
        // The same bytes with the checksum set right, so the parser looks
        // past it.
        if let Some(c) = checksum(data, e) {
            let mut fixed = data.to_vec();
            fixed[2..4].copy_from_slice(&c.to_be_bytes());
            check(&fixed, e);
        }
    }
});

fn check(data: &[u8], e: &Endpoints) {
    contract::check_decode_with_alloc_limit(|| Collect::<pim::Datagram>::new(pim::MAX_MESSAGE), data, 2 * (pim::MAX_MESSAGE + 1));
    contract::check_decode_with_alloc_limit(
        || Collect::<pim::Datagram>::new(pim::MAX_MESSAGE)
            .map(|datagram| Message::parse(&datagram.0, e)),
        data,
        2 * (pim::MAX_MESSAGE + 1),
    );
    contract::check_wire::<pim::Datagram>(data);
    contract::check_wire_value(&pim::Datagram(
        data.iter().take(pim::MAX_MESSAGE + 1).copied().collect(),
    ));

    let parsed = Message::parse(data, e);

    if let Ok(m) = &parsed {
        assert!(data.len() <= e.max_message());
        // Checked against the input bytes, not the parsed value: a
        // Bootstrap keeps its No-Forward bit.
        if let Message::Bootstrap(b) = m {
            assert_eq!(b.no_forward, data[1] & 0x80 != 0);
        }
        // A C-RP-Adv with no groups is read, as RFC 5059 asks of a BSR,
        // but never written.
        if let Message::CandidateRp(CandidateRp { groups, .. }) = m
            && groups.is_empty()
        {
            assert_eq!(m.frame(e).and_then(|frame| frame.to_bytes()), Err(Error::Count));
            return;
        }
        // Any other message read can be written, and reads back the same.
        let bytes = m.frame(e).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(m.encoded_len(), Ok(bytes.len()));
        assert_eq!(checksum(&bytes, e), Some(u16::from_be_bytes([bytes[2], bytes[3]])));
        assert_eq!(Message::parse(&bytes, e).as_ref(), Ok(m));
    }
}
