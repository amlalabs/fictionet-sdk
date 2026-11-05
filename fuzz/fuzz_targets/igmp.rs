//! IGMP messages, as a world playing a host or a multicast router reads
//! them.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use std::net::Ipv4Addr;

use fictionet::stdlib::network::ip::checksum;
use fictionet::stdlib::protocols::igmp::Message;
use fictionet::stdlib::protocols::igmp::harness::conforms;
use fictionet::stdlib::{
    codec::{Collect, Wire},
    protocols::igmp,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check(data);
    // The same bytes with the checksum set right, so the parser looks past
    // it.
    if data.len() >= 4 {
        let mut fixed = data.to_vec();
        fixed[2] = 0;
        fixed[3] = 0;
        let c = checksum(&fixed);
        fixed[2..4].copy_from_slice(&c.to_be_bytes());
        check(&fixed);
    }
});

fn check(data: &[u8]) {
    let bound = 2 * (igmp::MAX_MESSAGE + 1);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Collect::<igmp::Message>::new(igmp::MAX_MESSAGE)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(|| Collect::<igmp::Message>::new(igmp::MAX_MESSAGE), data),
    );
    if let Ok(value) = <igmp::Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <igmp::Code as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Some((value, _)) = data.split_first_chunk::<4>() {
        let _ = assert_write(&igmp::Code(u32::from_be_bytes(*value)));
    }

    let query = Message::QueryV3(igmp::QueryV3 {
        max_resp_code: 100,
        group: Ipv4Addr::UNSPECIFIED,
        suppress: false,
        qrv: data.first().copied().unwrap_or(0),
        qqic: 125,
        sources: vec![],
    });
    let _ = assert_write(&query);
    let parsed = Message::parse(data);

    if let Ok(m) = &parsed {
        assert_eq!(Message::receive(data).as_ref(), Ok(m));
    }
    if let Ok(m) = Message::receive(data) {
        // A message read follows the RFCs, checked apart from the module's
        // own rules, can be written, and reads back the same.
        assert!(conforms(&m), "{m:?}");
        let bytes = m.to_bytes().unwrap();
        assert_eq!(m.encoded_len(), Ok(bytes.len()));
        assert!(bytes.len() <= data.len());
        assert_eq!(checksum(&bytes), 0);
        assert_eq!(Message::parse(&bytes), Ok(m));
    }
}
