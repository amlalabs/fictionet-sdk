//! VXLAN and VXLAN-GPE datagrams, as a world playing a tunnel endpoint
//! reads them, and packets built from the bytes, as world code writes them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::vxlan::{Error, GpePacket, HEADER_LEN, MAX_DATAGRAM, MAX_PAYLOAD, MAX_VNI, Packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Packet>(data);
    contract::check_wire::<GpePacket>(data);
    // The bytes as a VXLAN datagram. A packet read can be written, at the
    // same length, and reads back the same.
    if let Ok(p) = Packet::parse(data) {
        assert!(p.frame.len() <= MAX_PAYLOAD);
        assert_eq!(p.frame, data[HEADER_LEN..]);
        let bytes = p.to_bytes().unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(Packet::parse(&bytes), Ok(p));
    }

    // The bytes as a VXLAN-GPE datagram, the same way.
    if let Ok(g) = GpePacket::parse(data) {
        assert_ne!(g.next_protocol, Some(0));
        assert_eq!(g.payload, data[HEADER_LEN..]);
        let bytes = g.to_bytes().unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(GpePacket::parse(&bytes), Ok(g));
    }

    // The datagram growing a byte at a time: each prefix reads or fails
    // without a panic. One shorter than the header is Truncated, and the
    // header decides alike for every prefix that holds it. Only the header
    // decides, so the first bytes are enough.
    let whole = (Packet::parse(data).map(|_| ()), GpePacket::parse(data).map(|_| ()));
    for n in 0..data.len().min(4 * HEADER_LEN) {
        let prefix = (Packet::parse(&data[..n]).map(|_| ()), GpePacket::parse(&data[..n]).map(|_| ()));
        if n < HEADER_LEN {
            assert_eq!(prefix, (Err(Error::Truncated(n)), Err(Error::Truncated(n))));
        } else if data.len() <= MAX_DATAGRAM {
            assert_eq!(prefix, whole);
        }
    }

    // Packets built from the bytes, not read from them: any VNI, any next
    // protocol (0 included) and a payload length near the limit or short.
    // A write either keeps the whole value or says why it cannot.
    let Some((head, rest)) = data.split_first_chunk::<8>() else {
        return;
    };
    let vni = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let next_protocol = if head[4] & 1 == 0 { None } else { Some(head[5]) };
    let len = match head[4] >> 6 {
        0 => rest.len(),
        1 => MAX_PAYLOAD,
        2 => MAX_PAYLOAD + 1,
        _ => MAX_PAYLOAD - usize::from(head[6]) + usize::from(head[7]),
    };
    let mut payload = rest.to_vec();
    payload.resize(len, head[6]);
    let p = Packet { vni, frame: payload.clone() };
    contract::check_wire_value(&p);
    assert_eq!(p.to_bytes().is_ok(), vni <= MAX_VNI && len <= MAX_PAYLOAD);
    let g = GpePacket { vni, next_protocol, bum: head[4] & 2 != 0, oam: head[4] & 4 != 0, payload };
    contract::check_wire_value(&g);
    assert_eq!(
        g.to_bytes().is_ok(),
        next_protocol != Some(0) && vni <= MAX_VNI && len <= MAX_PAYLOAD
    );
});
