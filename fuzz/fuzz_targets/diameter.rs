//! Diameter messages and AVPs, as a world playing an HSS or a charging
//! server reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::diameter::{
    Address, Avp, Format, Identity, MAX_AVP_DATA, Message, Uri, Value, base_format, check,
};
use fictionet::stdlib::diameter::harness::FORMATS;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Message>::new, data, 2 * Frames::<Message>::new().capacity());
    contract::check_wire::<Message>(data);
    contract::check_decode_with_alloc_limit(|| Frames::<Message>::with_limit(0), data, 2 * Frames::<Message>::with_limit(0).capacity());
    contract::check_decode_with_alloc_limit(|| Frames::<Message>::with_limit(64), data, 2 * Frames::<Message>::with_limit(64).capacity());
    let mut built = Message::request(u32::from(data.first().copied().unwrap_or(0)) << 20, 0, 1, 2);
    built.error = true;
    built.avps.push(Avp {
        code: 1,
        vendor: Some(0),
        mandatory: true,
        protected: false,
        data: data.to_vec(),
    });
    contract::check_wire_value(&built);
    if data.first() == Some(&0xff) {
        // Keep the command valid so the oversized AVP reaches the length check.
        built.command = 1;
        built.avps[0].data = vec![0; MAX_AVP_DATA + 1];
        contract::check_wire_value(&built);
    }

    let (items, _) = decode_all(Frames::<Message>::new, data);
    for malformed in items.iter().filter_map(|item| item.as_ref().err()) {
        assert!(malformed.header.avps.is_empty());
    }
    let messages: Vec<_> = items.into_iter().flatten().collect();
    for m in &messages {
        // A message read can be written, and reads back the same.
        let bytes = m.to_bytes().unwrap();
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(&back, m);
        let _ = check(&m.avps, |code, vendor| if vendor.is_none() { base_format(code) } else { None });
        // Every AVP read as grouped goes down to the depth limit.
        let _ = check(&m.avps, |_, _| Some(Format::Grouped));
        let reply = m.answer();
        assert_eq!(Message::parse(&reply.to_bytes().unwrap()).unwrap(), reply);
        // Each AVP in every format: a value read writes bytes that read
        // back to the same bytes. Only URIs (case) and grouped AVPs
        // (reserved bits, padding bytes) may first come out as other bytes.
        for avp in &m.avps {
            for f in FORMATS {
                if let Ok(v) = avp.value(f) {
                    let written = Avp::new(avp.code, &v).unwrap();
                    if !matches!(f, Format::Grouped | Format::DiameterUri) && avp.data.len() <= MAX_AVP_DATA {
                        assert_eq!(written.data, avp.data, "{f:?}");
                    }
                    let v2 = written.value(f).unwrap();
                    assert_eq!(Avp::new(avp.code, &v2).unwrap().data, written.data);
                }
            }
        }
    }
    // Any bytes as one message, an AVP list, an address, an identity and
    // a URI on their own.
    contract::check_wire::<Avp>(data);
    contract::check_wire::<Address>(data);
    if let Ok(list) = Avp::parse_list(data)
        && data.len() <= MAX_AVP_DATA
    {
        assert_eq!(Avp::parse_list(&Avp::new(1, &Value::Grouped(list.clone())).unwrap().data), Ok(list));
    }
    if let Ok(a) = Address::parse(data)
        && data.len() <= MAX_AVP_DATA
    {
        assert_eq!(a.to_bytes().unwrap(), data);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(id) = Identity::new(s) {
            assert_eq!(id.as_str(), s);
            assert_eq!(Identity::new(id.as_str()), Some(id));
        }
        if let Some(u) = Uri::parse(s) {
            assert_eq!(Uri::parse(&u.to_string()), Some(u));
        }
    }
});
