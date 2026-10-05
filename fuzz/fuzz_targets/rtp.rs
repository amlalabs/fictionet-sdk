//! RTP and RTCP packets, as a world playing a media server reads them from
//! UDP datagrams and RFC 4571 streams.
#![no_main]

use fictionet::stdlib::rtp::{
    Decoder, MAX_BUFFERED, MAX_PACKET, Packet, RtpPacket, check_compound, parse_compound,
    parse_packets, write_compound, write_packets,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as one RTP datagram. A packet read can be written, never
    // longer, and reads back the same.
    if let Ok(mut p) = RtpPacket::parse(data) {
        let bytes = p.to_bytes();
        assert!(bytes.len() <= data.len());
        assert!(bytes.capacity() <= MAX_PACKET);
        assert_eq!(RtpPacket::parse(&bytes), Ok(p.clone()));
        // A payload far longer than any packet is cut, and never sizes
        // the writer's buffer.
        p.payload.resize(p.payload.len() + 2 * MAX_PACKET, 0x5a);
        let bytes = p.to_bytes();
        assert!(bytes.len() <= MAX_PACKET && bytes.capacity() <= MAX_PACKET);
        assert!(RtpPacket::parse(&bytes).is_ok());
    }

    // The bytes as RTCP packets, the same way, and each packet alone.
    if let Ok(packets) = parse_packets(data) {
        let bytes = write_packets(&packets);
        assert!(bytes.len() <= data.len());
        assert_eq!(parse_packets(&bytes).as_ref(), Ok(&packets));
        for p in &packets {
            assert_eq!(parse_packets(&p.to_bytes()), Ok(vec![p.clone()]));
        }
        // The compound rules hold for the datagram exactly when they hold
        // for its packets, and then write_compound writes the same bytes.
        let ok = check_compound(&packets).is_ok();
        assert_eq!(parse_compound(data).is_ok(), ok);
        if ok {
            assert_eq!(write_compound(&packets), Ok(bytes));
        }
    }
    let _ = Packet::parse(data);

    // The bytes as an RFC 4571 stream, split two ways: in feeds as large
    // as the decoder takes, and a byte at a time. Both give the same
    // packets, and neither holds more than MAX_BUFFERED bytes.
    let mut whole = Decoder::new();
    let mut packets = Vec::new();
    let mut rest = data;
    loop {
        let used = whole.feed(rest);
        rest = &rest[used..];
        assert!(whole.buffered() <= MAX_BUFFERED);
        while let Some(p) = whole.next_packet() {
            packets.push(p);
        }
        if rest.is_empty() {
            break;
        }
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
        while let Some(p) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);
    assert_eq!(whole.buffered(), bytewise.buffered());
    for p in &packets {
        // An empty packet is an RFC 4571 null frame, which carries nothing.
        if !p.is_empty() {
            let _ = Packet::parse(p);
        }
    }
});
