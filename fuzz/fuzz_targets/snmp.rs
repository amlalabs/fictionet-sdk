//! SNMP v1 and v2c messages, BER elements and object identifiers, as a
//! world playing an agent reads them.
#![no_main]

use fictionet::stdlib::snmp::{Decoder, Element, ErrorStatus, Message, Oid};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram.
    if let Ok(m) = Message::parse(data) {
        // A message read can be written, and reads back the same. Writing
        // never makes it longer, so no binding is dropped.
        let bytes = m.to_bytes();
        assert!(bytes.len() <= data.len());
        assert_eq!(Message::parse(&bytes), Ok(m.clone()));
        // Answers to it always read back, keeping the bindings that fit.
        let answers = [m.response(m.pdu.bindings().to_vec()), m.error_response(ErrorStatus::GenErr, 1)];
        for r in answers.into_iter().flatten() {
            let back = Message::parse(&r.to_bytes()).unwrap();
            assert!(r.pdu.bindings().starts_with(back.pdu.bindings()));
        }
    }

    // The bytes as BER of any kind.
    if let Ok((e, used)) = Element::parse(data) {
        assert!(used <= data.len());
        let bytes = e.to_bytes().unwrap();
        assert_eq!(Element::parse(&bytes), Ok((e, bytes.len())));
    }

    // The bytes as an object identifier, encoded and as text.
    if let Ok(o) = Oid::from_ber(data) {
        assert_eq!(Oid::from_ber(&o.to_ber()), Ok(o));
    }
    if let Ok(Ok(o)) = std::str::from_utf8(data).map(str::parse::<Oid>) {
        assert_eq!(o.to_string().parse::<Oid>(), Ok(o));
    }

    // The stream, split two ways: all at once, and a byte at a time. Both
    // give the same messages, then the same error or the same bytes held.
    let take = |d: &mut Decoder, out: &mut Vec<Vec<u8>>| -> Option<fictionet::stdlib::snmp::Error> {
        while let Some(r) = d.next_message() {
            match r {
                Ok(m) => out.push(m),
                Err(e) => return Some(e),
            }
        }
        None
    };
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut messages = Vec::new();
    let whole_err = take(&mut whole, &mut messages);
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    let mut bytewise_err = None;
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        if let Some(e) = take(&mut bytewise, &mut again) {
            bytewise_err.get_or_insert(e);
        }
    }
    assert_eq!(messages, again);
    assert_eq!(whole_err, bytewise_err);
    assert_eq!(whole.buffered(), bytewise.buffered());
    if whole_err.is_none() {
        assert_eq!(messages.iter().map(Vec::len).sum::<usize>() + whole.buffered(), data.len());
    }
    for m in &messages {
        let _ = Message::parse(m);
    }
});
