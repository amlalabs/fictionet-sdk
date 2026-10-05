//! RADIUS packets, attributes and their values, as a world playing a
//! RADIUS server reads them.
#![no_main]

use fictionet::stdlib::radius::{
    Attribute, DataType, Decoder, Extended, MAX_BUFFERED, Packet, PacketError, Value, Vsa,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` in chunks, taking packets out after each feed, as a world
/// does. Every packet, then the error that broke the stream, if one did.
fn split(data: &[u8], bytewise: bool) -> (Vec<Packet>, Option<PacketError>) {
    let mut decoder = Decoder::new();
    let mut packets = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= MAX_BUFFERED);
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(r) = decoder.next_packet() {
                match r {
                    Ok(p) => packets.push(p),
                    Err(e) => return (packets, Some(e)),
                }
                progress = true;
            }
            // A full decoder always gives a packet or an error.
            assert!(progress);
        }
    }
    (packets, None)
}

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram.
    if let Ok(p) = Packet::parse(data) {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
        assert_eq!(Packet::parse(&bytes).as_ref(), Ok(&p));
        for a in &p.attributes {
            // A value read as its type writes back to bytes that read the same.
            if let Ok(v) = a.decode() {
                let t = a.info().map_or(DataType::String, |i| i.data_type);
                assert_eq!(Value::decode(t, &v.to_bytes()), Ok(v.clone()));
                // A value read can be put in an attribute again, with the
                // same bytes it came in or bytes that read the same.
                let again = Attribute::from_value(a.kind, &v).expect("a value read can be written");
                assert_eq!(Value::decode(t, &again.value).as_ref(), Ok(&v));
                if let Value::Vsa(vsa) = &v
                    && let Ok(subs) = vsa.sub_attributes()
                {
                    assert_eq!(&Vsa::from_sub_attributes(vsa.vendor, &subs), vsa);
                }
            }
            for t in [DataType::Tlv, DataType::Ipv6Prefix, DataType::Ipv4Prefix, DataType::Evs] {
                if let Ok(v) = Value::decode(t, &a.value) {
                    assert_eq!(Value::decode(t, &v.to_bytes()), Ok(v));
                }
            }
        }
        // The valid extended attributes, joined, split again and joined
        // again.
        let ext: Vec<Extended> = p.extended().into_iter().flatten().collect();
        let mut q = Packet::new(p.code, p.identifier, p.authenticator);
        for e in &ext {
            q.push_extended(e).unwrap();
        }
        let again: Vec<Extended> = q.extended().into_iter().map(Result::unwrap).collect();
        assert_eq!(again, ext);
        let _ = p.reply(p.code).to_bytes();
    }

    // The bytes as a RADIUS over TCP stream, split two ways: all at once,
    // and a byte at a time.
    assert_eq!(split(data, false), split(data, true));
});
