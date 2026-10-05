//! MQTT 3.1.1 packets, as a world playing a broker reads them, and topic
//! matching on any strings.
#![no_main]

use fictionet::stdlib::mqtt::{
    ConnAck, ConnectReturnCode, Decoder, Error, Frames, MAX_PACKET, Packet, Publish, QoS, check_topic_filter, check_topic_name,
    topic_matches,
};
use libfuzzer_sys::fuzz_target;
use fictionet::stdlib::codec::contract;

/// Feeds `data` to `d` in pieces of `piece` bytes, taking packets out as
/// they come, until it ends or the stream breaks. It returns the packets,
/// the error if there was one, and the bytes still held.
fn run(d: &mut Decoder, data: &[u8], piece: usize) -> (Vec<Packet>, Option<Error>, usize) {
    let mut packets = Vec::new();
    for chunk in data.chunks(piece.max(1)) {
        let mut rest = chunk;
        loop {
            let n = d.feed(rest);
            assert!(d.buffered() <= d.capacity());
            rest = &rest[n..];
            let mut took = false;
            while let Some(p) = d.next_packet() {
                match p {
                    Ok(p) => packets.push(p),
                    Err(e) => return (packets, Some(e), d.buffered()),
                }
                took = true;
            }
            if rest.is_empty() {
                break;
            }
            assert!(n > 0 || took, "a full decoder gave nothing");
        }
    }
    (packets, None, d.buffered())
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_decode(|| Frames::with_limit(MAX_PACKET), data);
    contract::check_wire::<Packet>(data);
    // The stream, split two ways: all at once, and a byte at a time. The
    // packets, the error and the bytes left must agree, at the largest
    // limit, which Packet::parse uses, and at a small one taken from the
    // input.
    let whole = run(&mut Decoder::with_max_packet(MAX_PACKET), data, data.len());
    assert_eq!(run(&mut Decoder::with_max_packet(MAX_PACKET), data, 1), whole);
    let small = usize::from(data.first().copied().unwrap_or(0) & 0x3f);
    contract::check_decode(|| Frames::with_limit(small), data);
    let small_whole = run(&mut Decoder::with_max_packet(small), data, data.len());
    assert_eq!(run(&mut Decoder::with_max_packet(small), data, 1), small_whole);
    let packets = whole.0;

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
        contract::check_wire::<Packet>(&bytes);
        assert_eq!(p.encoded_len(), Ok(bytes.len()));
        let (back, used) = Packet::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, p);
        assert_eq!(used, bytes.len());
    }
    if let Ok(Some((p, used))) = Packet::parse(data) {
        assert!(used <= data.len());
        assert_eq!(packets.first(), Some(&p));
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
                assert_eq!(Packet::parse(&bytes), Ok(Some((p, bytes.len()))));
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
