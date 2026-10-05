//! MQTT 3.1.1 packets, as a world playing a broker reads them, and topic
//! matching on any strings.
#![no_main]

use fictionet::stdlib::mqtt::{Decoder, MAX_PACKET, Packet, check_topic_filter, check_topic_name, topic_matches};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time. The
    // decoders take packets as large as Packet::parse does, so a large
    // input reads the same both ways.
    let mut whole = Decoder::with_max_packet(MAX_PACKET);
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(Ok(p)) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = Decoder::with_max_packet(MAX_PACKET);
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(p)) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
        let (back, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, p);
        assert_eq!(used, bytes.len());
    }
    if let Ok(Some((p, used))) = Packet::parse(data) {
        assert!(used <= data.len());
        assert_eq!(packets.first(), Some(&p));
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
