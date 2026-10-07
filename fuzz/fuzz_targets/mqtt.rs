//! MQTT 3.1.1 packets, as a world playing a broker reads them, and topic
//! matching on any strings.
#![no_main]

use fictionet::stdlib::mqtt::{
    ConnAck, ConnectReturnCode, Packets, MAX_PACKET, Packet, Publish, QoS, check_topic_filter, check_topic_name,
    topic_matches,
};
use libfuzzer_sys::fuzz_target;
use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Packet>(data);
    contract::check_wire::<fictionet::stdlib::mqtt::RemainingLength>(data);
    let small = usize::from(data.first().copied().unwrap_or(0) & 0x3f);
    for limit in [fictionet::stdlib::mqtt::DEFAULT_MAX_PACKET, MAX_PACKET, small] {
        let make = || Packets::with_limit(limit);
        contract::check_decode_with_alloc_limit(make, data, 2 * make().capacity());
    }
    let packets = decode_all(Packets::new, data).0;
    if let Ok(packet) = Packet::parse(data) {
        if data.len() <= fictionet::stdlib::mqtt::DEFAULT_MAX_PACKET {
            assert_eq!(packets.first(), Some(&packet));
        } else {
            // Exact parsing allows packets above the default stream limit.
            assert_eq!(decode_all(|| Packets::with_limit(MAX_PACKET), data).0.first(), Some(&packet));
        }
    }
    for packet in packets {
        contract::check_wire_value(&packet);
        assert_eq!(packet.encoded_len(), Ok(packet.to_bytes().unwrap().len()));
    }

    // Values built from the bytes, not read: whatever the writer takes
    // reads back as the same value.
    if let [a, b, c, rest @ ..] = data {
        let mut built = Vec::new();
        if let Some(code) = ConnectReturnCode::from_code(*b % 8) {
            built.push(Packet::ConnAck(ConnAck { session_present: a & 1 != 0, code }));
        }
        if let (Some(qos), Ok(topic)) = (QoS::from_level(a & 3), std::str::from_utf8(&rest[..rest.len().min(8)])) {
            let id = u16::from_be_bytes([*b, *c]);
            built.push(Packet::Publish(Publish {
                dup: a & 4 != 0,
                qos,
                retain: a & 8 != 0,
                topic: topic.to_string(),
                packet_id: if a & 16 != 0 { Some(id) } else { None },
                payload: rest.to_vec(),
            }));
        }
        for p in built {
            contract::check_wire_value(&p);
            let written = p.to_bytes();
            assert_eq!(p.encoded_len(), written.as_ref().map(Vec::len).map_err(|e| *e));
            if let Ok(bytes) = written {
                assert_eq!(Packet::parse(&bytes), Ok(p));
            }
        }
    }

    // The bytes as a filter and a topic, split at the first 0xff.
    let (a, b) = match data.iter().position(|&x| x == 0xff) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &data[..0]),
    };
    if let (Ok(filter), Ok(topic)) = (std::str::from_utf8(a), std::str::from_utf8(b)) {
        if topic_matches(filter, topic) {
            assert!(check_topic_filter(filter).is_ok() && check_topic_name(topic).is_ok());
        }
        if check_topic_name(topic).is_ok() {
            assert!(topic_matches(topic, topic));
        }
    }
});
