//! Geneve datagrams, as a world playing a tunnel endpoint reads them, and
//! headers built from any field values, as a world writes them.
#![no_main]

use fictionet::stdlib::geneve::{GeneveOption, Header, Packet};
use fictionet::stdlib::{codec::{Wire, Collect}, test_support::contract, geneve};
use libfuzzer_sys::fuzz_target;

/// A packet built from any field values, valid or not. Each option takes
/// a class, a type with its critical bit, and a data length that need not
/// be a multiple of 4; the first 8 bytes give the fixed fields.
fn packet_from(data: &[u8]) -> Option<Packet> {
    let (fixed, mut rest) = data.split_first_chunk::<8>()?;
    let mut options = Vec::new();
    // At most 70 options: enough to pass the 63 a header holds.
    while options.len() < 70 {
        let Some((h, tail)) = rest.split_first_chunk::<4>() else { break };
        let n = usize::from(h[3]).min(tail.len());
        let (body, after) = tail.split_at(n);
        options.push(GeneveOption {
            class: u16::from_be_bytes([h[0], h[1]]),
            kind: (h[2] & 0x7f) | (h[3] & 0x80),
            critical: h[2] & 0x80 != 0,
            data: body.to_vec(),
        });
        rest = after;
    }
    let header = Header {
        control: fixed[0] & 1 != 0,
        protocol: u16::from_be_bytes([fixed[1], fixed[2]]),
        vni: u32::from_be_bytes([fixed[3], fixed[4], fixed[5], fixed[6]]),
        options,
    };
    Some(Packet { header, payload: rest.to_vec() })
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(|| Collect::<geneve::Packet>::new(geneve::MAX_DATAGRAM), data, 2 * (geneve::MAX_DATAGRAM + 1));
    contract::check_wire::<geneve::Packet>(data);
    contract::check_wire::<Header>(data);

    let parsed = Packet::parse(data);

    if let Ok(p) = &parsed {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
        assert!(bytes.len() <= data.len());
        assert_eq!(Packet::parse(&bytes).as_ref(), Ok(p));
        let (header, payload) = Header::split(data).unwrap();
        assert_eq!(&header, &p.header);
        assert_eq!(payload, &p.payload[..]);
        // A reply on the same network can always be written, with no
        // options or with every option kept.
        let reply = p.reply(payload.to_vec());
        assert!(Packet::parse(&reply.to_bytes().unwrap()).is_ok());
        let echo = Packet { header: p.header.clone(), payload: payload.to_vec() };
        assert_eq!(Packet::parse(&echo.to_bytes().unwrap()), Ok(echo));
    }
    // Any bytes as the start of a header on their own.
    let _ = Header::parse_prefix(data);

    // The writer, on any field values: it writes bytes that read back the
    // same, or refuses and leaves the buffer alone.
    if let Some(p) = packet_from(data) {
        contract::check_wire_value(&p);
        contract::check_wire_value(&p.header);
        let mut out = vec![0xee];
        match p.write(&mut out) {
            Ok(()) => assert_eq!(Packet::parse(&out[1..]).as_ref(), Ok(&p)),
            Err(_) => assert_eq!(out, [0xee]),
        }
        let mut out = vec![0xee];
        match p.header.write(&mut out) {
            Ok(()) => assert_eq!(Header::parse_prefix(&out[1..]), Ok(Some((p.header.clone(), out.len() - 1)))),
            Err(_) => assert_eq!(out, [0xee]),
        }
    }
});
