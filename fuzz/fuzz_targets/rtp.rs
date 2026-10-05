//! RTP and RTCP packets, as a world playing a media server reads them from
//! UDP datagrams and RFC 4571 streams.
#![no_main]

use fictionet::stdlib::rtp::{
    Decoder, MAX_BUFFERED, Packet, RtpPacket, check_compound, parse_packets, write_packets,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as one RTP datagram. A packet read can be written, never
    // longer, and reads back the same.
    if let Ok(p) = RtpPacket::parse(data) {
        let bytes = p.to_bytes();
        assert!(bytes.len() <= data.len());
        assert_eq!(RtpPacket::parse(&bytes), Ok(p));
    }

    // The bytes as RTCP packets, the same way, and each packet alone.
    if let Ok(packets) = parse_packets(data) {
        let bytes = write_packets(&packets);
        assert!(bytes.len() <= data.len());
        assert_eq!(parse_packets(&bytes).as_ref(), Ok(&packets));
        for p in &packets {
            assert_eq!(parse_packets(&p.to_bytes()), Ok(vec![p.clone()]));
        }
        let _ = check_compound(&packets);
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
        let _ = Packet::parse(p);
    }
});
