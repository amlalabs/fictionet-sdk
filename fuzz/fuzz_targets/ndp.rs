//! IPv6 neighbor discovery messages, as a host or router on the link
//! reads them.
#![no_main]

use std::net::Ipv6Addr;

use fictionet::stdlib::network::ip::{protocol, transport_checksum};
use fictionet::stdlib::protocols::ndp::{Envelope, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for (source, destination) in [
        ("fe80::1", "ff02::1"),
        ("fe80::2", "fe80::1"),
        ("::", "ff02::1:ff00:1"),
    ] {
        let envelope = Envelope {
            source: source.parse::<Ipv6Addr>().unwrap(),
            destination: destination.parse::<Ipv6Addr>().unwrap(),
            hop_limit: 255,
        };
        check(data, &envelope);
        // The same bytes with the checksum set right, so the reader looks
        // past it.
        if data.len() >= 4 {
            let mut fixed = data.to_vec();
            fixed[2..4].copy_from_slice(&[0, 0]);
            let sum = transport_checksum(
                envelope.source.into(),
                envelope.destination.into(),
                protocol::ICMPV6,
                &fixed,
            );
            fixed[2..4].copy_from_slice(&sum.to_be_bytes());
            check(&fixed, &envelope);
        }
    }
});

fn check(data: &[u8], envelope: &Envelope) {
    let parsed = Message::parse(data);
    if let Ok(m) = Message::receive(envelope, data) {
        // A message received also parses, writes, and reads back the same.
        assert_eq!(parsed.as_ref(), Ok(&m));
        let bytes = m.emit(envelope.source, envelope.destination).unwrap();
        assert!(bytes.len() <= data.len());
        assert_eq!(Message::receive(envelope, &bytes), Ok(m));
    }
}
