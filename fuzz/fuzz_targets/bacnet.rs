//! BACnet/IP datagrams, NPDUs, APDUs and tagged values, as a world playing
//! a building controller reads them.
#![no_main]

use fictionet::stdlib::bacnet::{Apdu, Bvlc, IAm, Npdu, Tag, Value, WhoIs};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A whole datagram. Every field is kept, so it writes back the same.
    if let Ok(bvlc) = Bvlc::parse(data) {
        assert_eq!(bvlc.to_bytes(), data);
        // A datagram cut short is never read as a whole one. The length
        // check comes first, so this stays linear.
        for n in 0..data.len() {
            assert!(Bvlc::parse(&data[..n]).is_err());
        }
        if let Some(npdu) = bvlc.npdu() {
            layers(npdu);
        }
    }
    // Any bytes as each layer on its own.
    layers(data);
    let _ = WhoIs::parse(data).map(|w| assert_eq!(WhoIs::parse(&w.to_bytes()), Ok(w)));
    let _ = IAm::parse(data).map(|i| assert_eq!(IAm::parse(&i.to_bytes()), Ok(i)));
    if let Ok((tag, used)) = Tag::parse(data) {
        assert!(used <= data.len());
        let mut out = Vec::new();
        tag.write(&mut out);
        assert_eq!(Tag::parse(&out), Ok((tag, out.len())));
        // The same tag read as a context-tagged primitive of every type.
        for as_tag in 0..=12 {
            if let Ok((v, used)) = Value::parse_context(data, tag.number, as_tag) {
                assert!(used <= data.len());
                let mut once = Vec::new();
                v.write_context(tag.number, &mut once);
                let (again, n) = Value::parse_context(&once, tag.number, as_tag).unwrap();
                assert_eq!(n, once.len());
                let mut twice = Vec::new();
                again.write_context(tag.number, &mut twice);
                assert_eq!(twice, once);
            }
        }
    }
    // Values written once write the same bytes again: NaN payloads stay,
    // and leading zero bytes go on the first write.
    if let Ok(values) = Value::parse_all(data) {
        let once = write_all(&values);
        let again = Value::parse_all(&once).unwrap();
        assert_eq!(write_all(&again), once);
    }
});

/// Reads `b` as an NPDU and as an APDU, and checks each reads back what it
/// writes.
fn layers(b: &[u8]) {
    if let Ok(npdu) = Npdu::parse(b) {
        assert_eq!(Npdu::parse(&npdu.to_bytes()).as_ref(), Ok(&npdu));
        if let Some(apdu) = npdu.apdu() {
            if let Ok(a) = Apdu::parse(apdu) {
                assert_eq!(Apdu::parse(&a.to_bytes()), Ok(a));
            }
        }
    }
    if let Ok(a) = Apdu::parse(b) {
        assert_eq!(Apdu::parse(&a.to_bytes()), Ok(a.clone()));
        assert_eq!(a.data().is_some(), a.service().is_some() && !matches!(a, Apdu::SimpleAck { .. }));
    }
}

fn write_all(values: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        v.write(&mut out);
    }
    out
}
