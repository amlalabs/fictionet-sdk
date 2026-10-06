//! ESP and AH packets, UDP-encapsulated datagrams and ESP plaintexts, as a
//! world playing a VPN gateway reads them.
#![no_main]

use fictionet::stdlib::ipsec::{AhPacket, EspPacket, Datagram, IpsecError, Plaintext, MAX_DATAGRAM, MAX_PADDING};
use fictionet::stdlib::{codec::{Wire, Collect, contract}, ipsec};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(|| Collect::<ipsec::EspPacket>::new(ipsec::MAX_PACKET), data, 2 * (ipsec::MAX_PACKET + 1));
    contract::check_wire::<ipsec::EspPacket>(data);
    contract::check_decode_with_alloc_limit(|| Collect::<ipsec::AhPacket>::new(ipsec::MAX_PACKET), data, 2 * (ipsec::MAX_PACKET + 1));
    contract::check_wire::<ipsec::AhPacket>(data);
    contract::check_decode_with_alloc_limit(|| Collect::<ipsec::Datagram>::new(ipsec::MAX_DATAGRAM), data, 2 * (ipsec::MAX_DATAGRAM + 1));
    contract::check_wire::<ipsec::Datagram>(data);

    let packet = ipsec::EspPacket {
        spi: data.first().copied().map_or(0, u32::from),
        sequence: 1,
        payload: data.iter().take(ipsec::MAX_PACKET + 1).copied().collect(),
    };
    contract::check_wire_value(&packet);
    contract::check_wire_value(&Datagram::Esp(packet));
    if let Ok(a) = AhPacket::parse(data) {
        let (header, payload) = AhPacket::split(data).unwrap();
        assert_eq!(header, a.header);
        assert_eq!(payload, &a.payload);
        let header_bytes = a.header.to_bytes().unwrap();
        for tag in [0, 12, 16, 32, a.header.icv.len()] {
            match a.header.for_icv(tag) {
                Ok(header) => {
                    contract::check_wire_value(&header);
                    let z = header.to_bytes().unwrap();
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
    if let Ok(d) = Datagram::parse(data) {
        assert_eq!(d.to_bytes().unwrap(), data);
        assert!(data.len() <= MAX_DATAGRAM);
        assert_eq!(d.fits_ipv4(), data.len() <= MAX_DATAGRAM - 20);
    }
    if let Ok(e) = EspPacket::parse(data) {
        assert_eq!(e.to_bytes().unwrap(), data);
        for icv in [0, 12, 16] {
            if let Ok((before, tag)) = e.split_icv(icv) {
                assert_eq!(before.len() + tag.len(), e.payload.len());
            }
        }
    }
    contract::check_wire::<Plaintext>(data);
    contract::check_wire::<ipsec::AhHeader>(data);

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
