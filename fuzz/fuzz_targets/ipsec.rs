//! ESP and AH packets, UDP-encapsulated datagrams and ESP plaintexts, as a
//! world playing a VPN gateway reads them.
#![no_main]

use fictionet::stdlib::ipsec::{AhPacket, Decoder, Kind, Packet, Plaintext};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for kind in [Kind::Esp, Kind::Ah, Kind::Udp] {
        let parsed = Packet::parse(kind, data);

        // The packet, fed two ways: all at once, and a byte at a time.
        let mut whole = Decoder::new(kind);
        let _ = whole.feed(data);
        assert_eq!(whole.finish(), parsed);
        let mut bytewise = Decoder::new(kind);
        for b in data {
            let _ = bytewise.feed(std::slice::from_ref(b));
        }
        assert_eq!(bytewise.finish(), parsed);

        if let Ok(p) = &parsed {
            // A packet read writes the same bytes back.
            let bytes = p.to_bytes().unwrap();
            assert_eq!(bytes, data);
            assert_eq!(Packet::parse(kind, &bytes).as_ref(), Ok(p));
            if let Packet::Ah(a) = p {
                let (header, payload) = AhPacket::split(data).unwrap();
                assert_eq!(&header, &a.header);
                assert_eq!(payload, &a.payload[..]);
                assert_eq!(a.header.to_bytes_for_icv().unwrap().len(), a.header.len());
            }
            if let Packet::Esp(e) = p {
                for icv in [0, 12, 16] {
                    if let Ok((before, icv_bytes)) = e.split_icv(icv) {
                        assert_eq!(before.len() + icv_bytes.len(), e.payload.len());
                    }
                }
            }
        }
    }

    // Any bytes as a decrypted ESP payload.
    if let Ok(plain) = Plaintext::parse(data) {
        assert_eq!(plain.to_bytes().unwrap(), data);
    }
});
