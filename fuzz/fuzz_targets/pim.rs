//! PIM version 2 messages, as a world playing a multicast router reads
//! them.
#![no_main]
use fictionet::stdlib::ip::Endpoints;

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::pim::{
    ALL_PIM_ROUTERS_V4, ALL_PIM_ROUTERS_V6, CandidateRp, Error, Message, checksum,
};
use fictionet::stdlib::{
    codec::{Collect, Decode},
    pim,
    test_support::contract,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ends = [
        Endpoints::V4 {
            source: Ipv4Addr::new(10, 0, 0, 2),
            destination: ALL_PIM_ROUTERS_V4,
        },
        Endpoints::V6 {
            source: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
            destination: ALL_PIM_ROUTERS_V6,
        },
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
    contract::check_decode_with_alloc_limit(
        || Collect::bytes(pim::MAX_MESSAGE),
        data,
        2 * (pim::MAX_MESSAGE + 1),
    );
    contract::check_decode_with_alloc_limit(
        || Collect::bytes(pim::MAX_MESSAGE).map(|datagram| Message::parse(&datagram, e)),
        data,
        2 * (pim::MAX_MESSAGE + 1),
    );
    let raw = data[..data.len().min(pim::MAX_MESSAGE)].to_vec();
    assert_eq!(
        fictionet::stdlib::test_support::decode_all(|| Collect::bytes(pim::MAX_MESSAGE), &raw),
        (vec![raw], None)
    );

    let parsed = Message::parse(data, e);

    if let Ok(m) = &parsed {
        assert!(
            data.len()
                <= match e {
                    Endpoints::V4 { .. } => pim::MAX_MESSAGE_V4,
                    Endpoints::V6 { .. } => pim::MAX_MESSAGE,
                }
        );
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
            assert_eq!(m.frame(e), Err(Error::Count));
            return;
        }
        // Any other message read can be written, and reads back the same.
        let bytes = m.frame(e).unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(m.encoded_len(), Ok(bytes.len()));
        assert_eq!(
            checksum(&bytes, e),
            Some(u16::from_be_bytes([bytes[2], bytes[3]]))
        );
        assert_eq!(Message::parse(&bytes, e).as_ref(), Ok(m));
    }
}
