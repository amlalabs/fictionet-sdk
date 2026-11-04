//! MLDv2 reports, as a multicast router or a switch that watches MLD
//! reads them.
#![no_main]

use std::net::Ipv6Addr;

use fictionet::stdlib::network::ip::{protocol, transport_checksum};
use fictionet::stdlib::protocols::mld::{ALL_MLDV2_ROUTERS, Report};
use libfuzzer_sys::fuzz_target;

const SOURCE: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

fuzz_target!(|data: &[u8]| {
    check(data);
    // The same bytes with the checksum set right, so the reader looks past
    // it.
    if data.len() >= 4 {
        let mut fixed = data.to_vec();
        fixed[2..4].copy_from_slice(&[0, 0]);
        let sum = transport_checksum(
            SOURCE.into(),
            ALL_MLDV2_ROUTERS.into(),
            protocol::ICMPV6,
            &fixed,
        );
        fixed[2..4].copy_from_slice(&sum.to_be_bytes());
        check(&fixed);
    }
    // The bytes as a whole IPv6 packet.
    let _ = Report::from_packet(data);
});

fn check(data: &[u8]) {
    let parsed = Report::parse(data);
    if let Ok(r) = Report::receive(SOURCE, ALL_MLDV2_ROUTERS, data) {
        // A report received also parses, writes, and reads back the same,
        // in a packet too.
        assert_eq!(parsed.as_ref(), Ok(&r));
        let bytes = r.emit(SOURCE, ALL_MLDV2_ROUTERS).unwrap();
        assert!(bytes.len() <= data.len());
        assert_eq!(
            Report::receive(SOURCE, ALL_MLDV2_ROUTERS, &bytes),
            Ok(r.clone())
        );
        assert_eq!(Report::from_packet(&r.packet(SOURCE).unwrap()), Ok(r));
    }
}
