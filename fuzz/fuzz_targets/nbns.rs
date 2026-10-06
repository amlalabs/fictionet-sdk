//! NetBIOS name service packets, as a world playing the machines on a LAN
//! reads them, and the answers it builds from them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::nbns::{
    MAX_DATAGRAM, MAX_PACKET, Name, NbEntry, NodeName, NodeType, Packet, ParseError, RrName,
    decode_first_level, rcode,
};
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

/// The prefixes of an input that are checked: every one of the first 256,
/// then about 256 more spread over the rest, so a long input costs linear
/// time, not quadratic.
fn prefixes(len: usize) -> impl Iterator<Item = usize> {
    let step = (len / 256).max(1);
    (0..len.min(256)).chain((256..len).step_by(step))
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Name>(data);
    contract::check_wire::<RrName>(data);
    contract::check_wire::<Packet>(data);
    // The bytes as one datagram, and its prefixes, as if it came a byte at
    // a time. None of them panics.
    for n in prefixes(data.len()) {
        let _ = Packet::parse(&data[..n]);
    }
    if let Ok(p) = Packet::parse(data) {
        // A parsed packet stays within the packet limit.
        contract::check_wire_value(&p);
        assert!(p.to_bytes().unwrap().len() <= MAX_PACKET);
        for q in &p.questions {
            let _ = q.name.to_string();
        }
        for r in p.answers.iter().chain(&p.authority).chain(&p.additional) {
            let _ = r.name.to_string();
        }
        // Reply constructors bound their lists before serialization.
        if p.request().is_ok() {
            let name = Name::new("WORLD", 0x20);
            let owners: Vec<NbEntry> = data
                .chunks(4)
                .take(1024)
                .map(|c| NbEntry {
                    group: c[0] & 1 != 0,
                    node_type: NodeType::from_bits(u16::from(c[0] >> 1)),
                    address: Ipv4Addr::new(c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0), 1),
                })
                .collect();
            let names: Vec<NodeName> = data
                .chunks(16)
                .take(1024)
                .map(|c| NodeName {
                    bytes: [c[0]; 16],
                    flags: 0x0400,
                })
                .collect();
            for r in [
                p.query_response(name.clone(), 1, owners),
                p.negative_query_response(name.clone(), rcode::NAM_ERR),
                p.node_status_response(name.clone(), names, [0; 6]),
                p.wack(name, 2),
                p.wack(RrName::null(), 2),
            ] {
                contract::check_wire_value(&r);
                assert!(r.to_bytes().unwrap().len() <= MAX_DATAGRAM);
            }
        }
    }
    // Any 32 bytes as a first-level label.
    if let Some(name) = decode_first_level(data) {
        let bytes = Name {
            bytes: name,
            scope: vec![],
        }
        .to_bytes()
        .unwrap();
        assert_eq!(&bytes[1..33], data);
    }
    // Any text as a scope: the writer either refuses the name or writes
    // one that reads back the same.
    if let Ok(text) = std::str::from_utf8(data) {
        let name = Name::new("W", 0x20).with_scope(text);
        let q = Packet::name_query(1, name.clone(), false);
        match q.to_bytes() {
            Ok(bytes) => assert_eq!(Packet::parse(&bytes).unwrap().questions[0].name, name),
            Err(e) => assert_eq!(e, ParseError::Unwritable),
        }
    }
});
