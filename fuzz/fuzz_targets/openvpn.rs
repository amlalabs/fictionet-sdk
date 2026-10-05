//! OpenVPN packets, as a world playing an OpenVPN server reads them from
//! UDP datagrams and TCP streams.
#![no_main]

use fictionet::stdlib::openvpn::{
    ControlKind, Decoder, Error, MAX_HMAC_LEN, MAX_PACKET, Packet, Wrapping, frame, split_first_byte, split_tcp,
};
use libfuzzer_sys::fuzz_target;

const WRAPPINGS: [Wrapping; 6] = [
    Wrapping::None,
    Wrapping::TlsAuth { hmac_len: 0 },
    Wrapping::TlsAuth { hmac_len: 20 },
    Wrapping::TlsAuth { hmac_len: 32 },
    Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN },
    Wrapping::TlsCrypt,
];

fuzz_target!(|data: &[u8]| {
    // The bytes as one UDP datagram, read with each wrapping.
    for w in WRAPPINGS {
        if let Ok(p) = Packet::parse(data, w) {
            // A packet read is written back byte for byte.
            assert_eq!(p.to_bytes(), data);
            assert_eq!(Packet::parse(data, p.wrapping()), Ok(p.clone()));
            let tcp = p.to_tcp_bytes();
            let (inner, used) = split_tcp(&tcp).unwrap().unwrap();
            assert_eq!(inner, data);
            assert_eq!(used, tcp.len());
        }
    }

    // A wrapping with an HMAC too long refuses every control packet.
    let too_long = Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN + 1 };
    if let Some(&first) = data.first()
        && data.len() <= MAX_PACKET
        && ControlKind::from_opcode(split_first_byte(first).0).is_some()
    {
        assert_eq!(Packet::parse(data, too_long), Err(Error::HmacLen(MAX_HMAC_LEN + 1)));
    } else if let Ok(p) = Packet::parse(data, too_long) {
        assert_eq!(p.wrapping(), Wrapping::None);
    }

    // The bytes as a TCP stream, split two ways: all at once, and a byte at
    // a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(Ok(p)) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(p)) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);

    for bytes in &packets {
        // A packet taken from the stream frames back the same.
        let framed = frame(bytes).unwrap();
        assert_eq!(split_tcp(&framed), Ok(Some((&bytes[..], framed.len()))));
        for w in WRAPPINGS {
            if let Ok(p) = Packet::parse(bytes, w) {
                assert_eq!(&p.to_bytes(), bytes);
            }
        }
    }
});
