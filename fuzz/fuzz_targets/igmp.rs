//! IGMP messages, as a world playing a host or a multicast router reads
//! them.
#![no_main]

use std::net::Ipv4Addr;

use fictionet::stdlib::igmp::{Decoder, Message, RecordType, checksum};
use fictionet::stdlib::{codec::{Collect, contract}, igmp};
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
    contract::check_decode(|| Collect::<igmp::Message>::new(igmp::MAX_MESSAGE), data);
    contract::check_wire::<igmp::Message>(data);

    let query = Message::QueryV3(igmp::QueryV3 {
        max_resp_code: 100,
        group: Ipv4Addr::UNSPECIFIED,
        suppress: false,
        qrv: data.first().copied().unwrap_or(0),
        qqic: 125,
        sources: vec![],
    });
    contract::check_wire_value(&query);
    let parsed = Message::parse(data);

    // The message, fed two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    let _ = whole.feed(data);
    assert_eq!(whole.finish(), parsed);
    let mut bytewise = Decoder::new();
    for b in data {
        let _ = bytewise.feed(std::slice::from_ref(b));
    }
    assert_eq!(bytewise.finish(), parsed);

    if let Ok(m) = &parsed {
        // A message read follows the RFCs, checked apart from the module's
        // own rules, can be written, and reads back the same.
        assert!(conforms(m), "{m:?}");
        let bytes = m.to_bytes().unwrap();
        assert_eq!(m.encoded_len(), Ok(bytes.len()));
        assert!(bytes.len() <= data.len());
        assert_eq!(checksum(&bytes), 0);
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(m));
    }
}

/// The rules of RFC 1112, RFC 2236 and RFC 3376 for a message sent.
fn conforms(m: &Message) -> bool {
    let multicast = |a: &Ipv4Addr| (224..=239).contains(&a.octets()[0]);
    let zero = |a: &Ipv4Addr| a.octets() == [0; 4];
    let unicast = |a: &Ipv4Addr| !multicast(a) && !zero(a) && a.octets() != [255; 4];
    let len = match m {
        Message::Query { max_resp_time: 0, group } if !zero(group) => return false,
        Message::Query { group, .. } if !zero(group) && !multicast(group) => return false,
        Message::ReportV1 { group } | Message::ReportV2 { group } | Message::Leave { group }
            if !multicast(group) =>
        {
            return false;
        }
        Message::QueryV3(q) => {
            if q.qrv > 7 || !(zero(&q.group) || multicast(&q.group)) || !q.sources.iter().all(unicast) {
                return false;
            }
            if zero(&q.group) && !q.sources.is_empty() {
                return false;
            }
            12 + 4 * q.sources.len()
        }
        Message::ReportV3 { records } => {
            let mut len = 8;
            for r in records {
                if matches!(r.kind, RecordType::Other(1..=6))
                    || !multicast(&r.group)
                    || !r.sources.iter().all(unicast)
                {
                    return false;
                }
                len += 8 + 4 * r.sources.len();
            }
            len
        }
        _ => 8,
    };
    // An IPv4 packet holds 65535 bytes, 24 of them the header with Router
    // Alert.
    len + 24 <= 65_535
}
