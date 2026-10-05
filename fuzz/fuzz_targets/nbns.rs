//! NetBIOS name service packets, as a world playing the machines on a LAN
//! reads them, and the answers it builds from them.
#![no_main]

use fictionet::stdlib::nbns::{
    MAX_DATAGRAM, MAX_PACKET, Name, NbEntry, NodeName, NodeType, Packet, RrName, decode_first_level,
    encode_first_level, rcode,
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

/// Writes `p` in at most `limit` bytes and reads it back. With TC clear
/// on `p`, TC on the result says the writer left something out; without
/// it, the packet reads back the same.
fn round_trip(p: &Packet, limit: usize) {
    let mut p = p.clone();
    p.flags.truncated = false;
    let bytes = p.to_bytes_within(limit);
    assert!(bytes.len() <= limit);
    let back = Packet::parse(&bytes).unwrap();
    if !back.flags.truncated {
        assert_eq!(back, p);
    }
}

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram, and its prefixes, as if it came a byte at
    // a time. None of them panics.
    for n in prefixes(data.len()) {
        let _ = Packet::parse(&data[..n]);
    }
    if let Ok(p) = Packet::parse(data) {
        // A packet read can be written, in one datagram or in the most a
        // datagram can hold.
        round_trip(&p, MAX_DATAGRAM);
        round_trip(&p, MAX_PACKET);
        for q in &p.questions {
            let _ = q.name.to_string();
        }
        for r in p.answers.iter().chain(&p.authority).chain(&p.additional) {
            let _ = r.name.to_string();
        }
        // Every answer to a request reads back as written, or is marked
        // cut. The owner and name lists grow with the input.
        if p.request().is_ok() {
            let name = Name::new("WORLD", 0x20);
            let owners: Vec<NbEntry> = data
                .chunks(4)
                .map(|c| NbEntry {
                    group: c[0] & 1 != 0,
                    node_type: NodeType::from_bits(u16::from(c[0] >> 1)),
                    address: Ipv4Addr::new(c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0), 1),
                })
                .collect();
            let names: Vec<NodeName> = data.chunks(16).map(|c| NodeName { bytes: [c[0]; 16], flags: 0x0400 }).collect();
            for r in [
                p.query_response(name.clone(), 1, owners),
                p.negative_query_response(name.clone(), rcode::NAM_ERR),
                p.node_status_response(name.clone(), names, [0; 6]),
                p.wack(name, 2),
                p.wack(RrName::null(), 2),
            ] {
                round_trip(&r, MAX_DATAGRAM);
                round_trip(&r, MAX_PACKET);
            }
        }
    }
    // Any 32 bytes as a first-level label.
    if let Some(name) = decode_first_level(data) {
        assert_eq!(&encode_first_level(&name)[..], data);
    }
    // Any text as a scope: the name keeps what the wire holds, so it reads
    // back the same.
    if let Ok(text) = std::str::from_utf8(data) {
        let name = Name::new("W", 0x20).with_scope(text);
        let q = Packet::name_query(1, name.clone(), false);
        assert_eq!(Packet::parse(&q.to_bytes()).unwrap().questions[0].name, name);
    }
});
