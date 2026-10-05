//! NetBIOS name service packets, as a world playing the machines on a LAN
//! reads them, and the answers it builds from them.
#![no_main]

use fictionet::stdlib::nbns::{Name, NodeName, Packet, decode_first_level, encode_first_level, rcode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram, and every prefix of it, as if it came a
    // byte at a time. None of them panics.
    for n in 0..data.len() {
        let _ = Packet::parse(&data[..n]);
    }
    if let Ok(p) = Packet::parse(data) {
        // A packet read can be written, and reads back the same, unless
        // the writer had to leave records out to fit a datagram.
        let bytes = p.to_bytes();
        let back = Packet::parse(&bytes).unwrap();
        let lens = |p: &Packet| [p.questions.len(), p.answers.len(), p.authority.len(), p.additional.len()];
        if lens(&back) == lens(&p) {
            assert_eq!(back, p);
        }
        for q in &p.questions {
            let _ = q.name.to_string();
        }
        // Every answer to a request reads back as written.
        if p.request().is_ok() {
            let name = Name::new("WORLD", 0x20);
            for r in [
                p.negative_query_response(name.clone(), rcode::NAM_ERR),
                p.node_status_response(name.clone(), vec![NodeName::unique(&name)], [0; 6]),
                p.wack(name, 2),
            ] {
                assert_eq!(Packet::parse(&r.to_bytes()), Ok(r));
            }
        }
    }
    // Any 32 bytes as a first-level label.
    if let Some(name) = decode_first_level(data) {
        assert_eq!(&encode_first_level(&name)[..], data);
    }
});
