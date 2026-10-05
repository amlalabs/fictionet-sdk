//! Diameter messages and AVPs, as a world playing an HSS or a charging
//! server reads them.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::diameter::{
    Address, Avp, Decoder, Format, Frames, Identity, MAX_AVP_DATA, Message, Uri, Value, base_format, check,
};
use libfuzzer_sys::fuzz_target;

const FORMATS: [Format; 14] = [
    Format::OctetString,
    Format::Integer32,
    Format::Integer64,
    Format::Unsigned32,
    Format::Unsigned64,
    Format::Float32,
    Format::Float64,
    Format::Grouped,
    Format::Address,
    Format::Time,
    Format::Utf8String,
    Format::DiameterIdentity,
    Format::DiameterUri,
    Format::Enumerated,
];

/// Feeds all of `data` to `d`, as much at a time as it takes, and returns
/// the messages it gives before the first error.
fn take_all(d: &mut Decoder, data: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut fed = 0;
    loop {
        fed += d.feed(&data[fed..]);
        while let Some(m) = d.next_message() {
            match m {
                Ok(m) => out.push(m),
                Err(_) => {
                    // The header kept for an error answer has no AVPs.
                    assert!(d.failed_header().is_none_or(|h| h.avps.is_empty()));
                    return out;
                }
            }
        }
        if fed == data.len() {
            return out;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Message>(data);
    contract::check_decode(|| Frames::with_limit(0), data);
    contract::check_decode(|| Frames::with_limit(64), data);
    let mut built = Message::request(u32::from(data.first().copied().unwrap_or(0)) << 20, 0, 1, 2);
    built.error = true;
    built.avps.push(Avp {
        code: 1,
        vendor: Some(0),
        mandatory: true,
        protected: false,
        data: data.get(..MAX_AVP_DATA + 1).unwrap_or(data).to_vec(),
    });
    contract::check_wire_value(&built);

    // The stream, split two ways: as much at a time as the decoder takes,
    // and a byte at a time.
    let messages = take_all(&mut Decoder::new(), data);
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    'outer: for b in data {
        assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
        while let Some(m) = bytewise.next_message() {
            match m {
                Ok(m) => again.push(m),
                Err(_) => break 'outer,
            }
        }
    }
    assert_eq!(messages, again);

    for m in &messages {
        // A message read can be written, and reads back the same.
        let bytes = m.to_bytes();
        let (back, used) = Message::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, m);
        assert_eq!(used, bytes.len());
        // The checked writer writes the same bytes, unless RFC 6733
        // forbids sending the message.
        let allowed = m.check_header().is_ok() && m.avps.iter().all(|a| a.vendor != Some(0));
        assert_eq!(m.try_to_bytes(), allowed.then(|| bytes.clone()));
        let _ = check(&m.avps, |code, vendor| if vendor.is_none() { base_format(code) } else { None });
        // Every AVP read as grouped goes down to the depth limit.
        let _ = check(&m.avps, |_, _| Some(Format::Grouped));
        let reply = m.answer();
        assert_eq!(Message::parse(&reply.to_bytes()).unwrap().unwrap().0, reply);
        // Each AVP in every format: a value read writes bytes that read
        // back to the same bytes. Only URIs (case) and grouped AVPs
        // (reserved bits, padding bytes) may first come out as other bytes.
        for avp in &m.avps {
            for f in FORMATS {
                if let Ok(v) = avp.value(f) {
                    let written = Avp { data: v.to_bytes(), ..avp.clone() };
                    if !matches!(f, Format::Grouped | Format::DiameterUri) && avp.data.len() <= MAX_AVP_DATA {
                        assert_eq!(written.data, avp.data, "{f:?}");
                    }
                    let v2 = written.value(f).unwrap();
                    assert_eq!(v2.to_bytes(), written.data);
                }
            }
        }
    }
    // Any bytes as one message, an AVP list, an address, an identity and
    // a URI on their own.
    if let Ok(Some((m, used))) = Message::parse(data) {
        assert!(used <= data.len());
        let bytes = m.to_bytes();
        assert_eq!(Message::parse(&bytes), Ok(Some((m, bytes.len()))));
    }
    if let Ok(list) = Avp::parse_list(data)
        && data.len() <= MAX_AVP_DATA
    {
        assert_eq!(Avp::parse_list(&Value::Grouped(list.clone()).to_bytes()), Ok(list));
    }
    if let Some(a) = Address::parse(data)
        && data.len() <= MAX_AVP_DATA
    {
        assert_eq!(a.to_bytes(), data);
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
