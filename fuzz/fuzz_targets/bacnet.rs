//! BACnet/IP datagrams, NPDUs, APDUs and tagged values, as a world playing
//! a building controller reads them.
#![no_main]

use fictionet::stdlib::bacnet::{
    Apdu, Bvlc, CharString, Destination, IAm, NetAddress, Npdu, NpduBody, ObjectId, Priority, Segmentation, Tag, Value,
    WhoIs,
};
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
    writers(data);
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

/// Builds public values from `b`, including ones no reader returns, and
/// checks that what the writers make reads back.
fn writers(b: &[u8]) {
    let byte = |i: usize| b.get(i).copied().unwrap_or(0);
    let word = |i: usize| u16::from_be_bytes([byte(i), byte(i + 1)]);
    // Any context tag number, 255 included, writes a tag that reads.
    let mut out = Vec::new();
    Value::Unsigned(u64::from(word(0))).write_context(byte(2), &mut out);
    assert!(Tag::parse(&out).is_ok());
    // Any network numbers write an NPDU that reads.
    let npdu = Npdu {
        destination: (byte(3) & 1 != 0).then(|| Destination {
            address: NetAddress { network: word(4), mac: vec![byte(6); usize::from(byte(3) % 8)] },
            hop_count: byte(7),
        }),
        source: (byte(3) & 2 != 0)
            .then(|| NetAddress { network: word(8), mac: vec![byte(10); usize::from(byte(3) >> 5)] }),
        expecting_reply: byte(3) & 4 != 0,
        priority: Priority::from_bits(byte(3) >> 3),
        body: NpduBody::Apdu(b.to_vec()),
    };
    assert!(Npdu::parse(&npdu.to_bytes()).is_ok());
    assert!(Npdu::parse(&Npdu::local(b.to_vec()).to_bytes()).is_ok());
    // Any I-Am writes one that reads.
    let i_am = IAm {
        device: ObjectId::from_u32(u32::from(word(0)) << 16 | u32::from(word(2))),
        max_apdu: u32::from(word(4)),
        segmentation: [Segmentation::Both, Segmentation::Transmit, Segmentation::Receive, Segmentation::NoSegmentation]
            [usize::from(byte(6) % 4)],
        vendor: word(7),
    };
    assert!(IAm::parse(&i_am.to_bytes()).is_ok());
    // A string of any character set, cut or not, reads back. A UTF-8 one
    // that was valid stays valid.
    let s = CharString { charset: byte(0), bytes: b.to_vec() };
    let written = Value::CharacterString(s.clone()).to_bytes();
    let Ok((Value::CharacterString(back), _)) = Value::parse(&written) else { panic!("string did not read back") };
    if s.as_str().is_some() {
        assert!(back.as_str().is_some());
    }
}
