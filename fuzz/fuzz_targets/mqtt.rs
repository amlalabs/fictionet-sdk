//! MQTT 3.1.1 packets, as a world playing a broker reads them, and topic
//! matching on any strings.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::protocols::mqtt::ConnAck;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::mqtt::ConnectReturnCode;

use fictionet::stdlib::protocols::mqtt::MAX_PACKET;

use fictionet::stdlib::protocols::mqtt::Packet;

use fictionet::stdlib::protocols::mqtt::Publish;

use fictionet::stdlib::protocols::mqtt::QoS;

use fictionet::stdlib::protocols::mqtt::check_topic_filter;

use fictionet::stdlib::protocols::mqtt::check_topic_name;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::mqtt::topic_matches;
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <fictionet::stdlib::protocols::mqtt::RemainingLength as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let small = usize::from(data.first().copied().unwrap_or(0) & 0x3f);
    for limit in [
        fictionet::stdlib::protocols::mqtt::DEFAULT_MAX_PACKET,
        MAX_PACKET,
        small,
    ] {
        let make = || Frames::<Packet>::with_limit(limit);
        let bound = 2 * make().capacity();
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
                assert!(s.allocated() <= bound);
            }),
            decode_all(make, data),
        );
    }
    let packets = decode_all(Frames::<Packet>::new, data).0;
    if let Ok(packet) = Packet::parse(data) {
        if data.len() <= fictionet::stdlib::protocols::mqtt::DEFAULT_MAX_PACKET {
            assert_eq!(packets.first(), Some(&packet));
        } else {
            // Exact parsing allows packets above the default stream limit.
            assert_eq!(
                decode_all(|| Frames::<Packet>::with_limit(MAX_PACKET), data)
                    .0
                    .first(),
                Some(&packet)
            );
        }
    }
    for packet in packets {
        let _ = assert_write(&packet);
        assert_eq!(packet.encoded_len(), Ok(packet.to_bytes().unwrap().len()));
    }

    // Values built from the bytes, not read: whatever the writer takes
    // reads back as the same value.
    if let [a, b, c, rest @ ..] = data {
        let mut built = Vec::new();
        if let Some(code) = ConnectReturnCode::from_code(*b % 8) {
            built.push(Packet::ConnAck(ConnAck {
                session_present: a & 1 != 0,
                code,
            }));
        }
        if let (Some(qos), Ok(topic)) = (
            QoS::from_level(a & 3),
            std::str::from_utf8(&rest[..rest.len().min(8)]),
        ) {
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
            let _ = assert_write(&p);
            let written = p.to_bytes();
            assert_eq!(
                p.encoded_len(),
                written.as_ref().map(Vec::len).map_err(|e| *e)
            );
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
