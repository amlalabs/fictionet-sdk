//! ESP and AH packets, UDP-encapsulated datagrams and ESP plaintexts, as a
//! world playing a VPN gateway reads them.
#![no_main]

use fictionet::stdlib::ipsec::{AhPacket, Datagram, Decoder, IpsecError, Kind, Packet, Plaintext, MAX_DATAGRAM, MAX_PADDING};
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
                // For the ICV's computation only the tag is zeroed; any
                // padding after it keeps its bytes (RFC 4302, 3.3.3.2.1).
                let header_bytes = a.header.to_bytes().unwrap();
                for tag in [0, 12, 16, 32, a.header.icv.len()] {
                    match a.header.to_bytes_for_icv(tag) {
                        Ok(z) => {
                            assert!(tag <= a.header.icv.len());
                            assert_eq!(z.len(), a.header.len());
                            assert_eq!(&z[..12], &header_bytes[..12]);
                            assert!(z[12..12 + tag].iter().all(|&b| b == 0));
                            assert_eq!(&z[12 + tag..], &header_bytes[12 + tag..]);
                        }
                        Err(e) => {
                            assert!(tag > a.header.icv.len());
                            assert_eq!(e, IpsecError::Truncated);
                        }
                    }
                }
            }
            if let Packet::Udp(d) = p {
                assert!(data.len() <= MAX_DATAGRAM);
                if let Datagram::Esp(_) | Datagram::Ike(_) = d {
                    assert_eq!(d.fits_ipv4(), data.len() <= MAX_DATAGRAM - 20);
                }
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

    // The bytes as data to pad, with the first byte picking the block size:
    // the result is a multiple of it and of 4 (RFC 4303, section 2.4), and
    // reads back.
    if let Some((&b, rest)) = data.split_first() {
        let block = usize::from(b) + 1;
        match Plaintext::padded(rest.to_vec(), 4, block) {
            Ok(plain) => {
                assert_eq!(plain.len() % 4, 0);
                assert_eq!(plain.len() % block, 0);
                assert!(plain.has_default_padding());
                assert_eq!(Plaintext::parse(&plain.to_bytes().unwrap()), Ok(plain));
            }
            Err(IpsecError::Padding(n)) => assert!(n > MAX_PADDING && block > 64 && block % 4 != 0),
            Err(e) => assert_eq!(e, IpsecError::TooLong),
        }
    }
});
