//! SNMP v1 and v2c messages, BER elements and object identifiers, as a
//! world playing an agent reads them.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::snmp::Frames;
use fictionet::stdlib::snmp::{
    BasicPdu, Decoder, Element, Error, ErrorStatus, MAX_BUFFERED, MAX_MESSAGE, Message, Oid, Pdu, Value, VarBind,
    Version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_decode(|| Frames::with_limit(usize::from(data.first().copied().unwrap_or(0))), data);
    contract::check_wire::<Message>(data);

    // The bytes as one datagram.
    if let Ok(m) = Message::parse(data) {
        // A message read can be written, and reads back the same. Writing
        // never makes it longer.
        let bytes = m.to_bytes().unwrap();
        assert!(bytes.len() <= data.len());
        assert_eq!(Message::parse(&bytes), Ok(m.clone()));
        // Answers to it follow its version and are no longer than it, so
        // they are written whole and read back the same.
        let answers = [m.response(m.pdu.bindings().to_vec()), m.error_response(ErrorStatus::GenErr, 1)];
        for r in answers.into_iter().flatten() {
            assert!(m.follows_version() && r.follows_version());
            let b = r.to_bytes().unwrap();
            assert!(b.len() <= data.len());
            assert_eq!(Message::parse(&b), Ok(r));
        }
    }

    // A message built from the bytes, as world code builds one: it is
    // written whole and reads back the same, or refused as too long.
    let name: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    let copies = usize::from(data.first().copied().unwrap_or(0) % 4);
    let built = Message {
        version: if data.len() % 2 == 0 { Version::V1 } else { Version::V2c },
        community: data.to_vec(),
        pdu: Pdu::Set(BasicPdu::new(
            1,
            vec![
                VarBind::new(name.clone(), Value::OctetString(data.to_vec())),
                VarBind::new(name, Value::Opaque(data.repeat(copies))),
            ],
        )),
    };
    contract::check_wire_value(&built);
    match built.to_bytes() {
        Ok(b) => {
            assert_eq!(b.len(), built.encoded_len());
            assert!(b.len() <= MAX_MESSAGE);
            assert_eq!(Message::parse(&b), Ok(built));
        }
        Err(e) => {
            assert!(built.encoded_len() > MAX_MESSAGE);
            assert_eq!(e, Error::TooLong(built.encoded_len()));
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

    // The stream, split two ways: in pieces as large as the decoder
    // takes, and a byte at a time. Both give the same messages, then the
    // same error or the same bytes held, never more than MAX_BUFFERED.
    let take = |d: &mut Decoder, out: &mut Vec<Vec<u8>>| -> Option<Error> {
        while let Some(r) = d.next_message() {
            match r {
                Ok(m) => out.push(m),
                Err(e) => return Some(e),
            }
        }
        None
    };
    let mut whole = Decoder::new();
    let mut messages = Vec::new();
    let mut whole_err = None;
    let mut rest = data;
    while whole_err.is_none() {
        let n = whole.feed(rest);
        rest = &rest[n..];
        whole_err = take(&mut whole, &mut messages);
        assert!(whole.buffered() <= MAX_BUFFERED);
        if rest.is_empty() {
            break;
        }
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    let mut bytewise_err = None;
    for b in data {
        assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
        if let Some(e) = take(&mut bytewise, &mut again) {
            bytewise_err.get_or_insert(e);
        }
        assert!(bytewise.buffered() <= MAX_BUFFERED);
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
