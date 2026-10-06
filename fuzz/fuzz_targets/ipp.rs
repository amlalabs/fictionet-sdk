//! IPP request and response bodies, as a world playing a printer reads
//! them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::ipp::{
    Attribute, Decoder, Error, Head, Header, MAX_FIELD, MAX_HEAD, Message, Value, tag,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Head::new, data);
    contract::check_decode(|| Head::with_limit(64), data);
    contract::check_wire::<Header>(data);
    let mut message = Message::request(2, 7);
    message.add(
        tag::JOB_ATTRIBUTES,
        Attribute::new(
            "document",
            Value::OctetString(data.get(..MAX_FIELD + 1).unwrap_or(data).to_vec()),
        ),
    );
    let built = Header::from(message);
    contract::check_wire_value(&built);
    let mut body = Wire::to_bytes(&Header {
        version: (1, 1),
        code: 2,
        request_id: 7,
        groups: vec![],
    })
    .unwrap();
    body.extend_from_slice(data.get(..4096).unwrap_or(data));
    contract::check_decode(|| Head::with_limit(64), &body);

    let whole = Message::parse(data);

    // The body, split two ways: all at once, and a byte at a time.
    let mut at_once = Decoder::new();
    at_once.feed(data);
    let first = at_once.next_message();
    let first_data = at_once.take_data();
    // Fed in two pieces with no polling between: the decoder holds no more
    // than MAX_HEAD and a length field while the head is coming.
    let mut lazy = Decoder::new();
    let (x, y) = data.split_at(data.len() / 2);
    lazy.feed(x);
    assert!(lazy.buffered() <= MAX_HEAD + 3 || matches!(Message::parse_head(x), Ok(Some(_))));
    lazy.feed(y);
    let lazy_first = lazy.next_message();
    let lazy_data = lazy.take_data();
    let mut bytewise = Decoder::new();
    let mut got = None;
    let mut rest = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        if got.is_none() {
            got = bytewise.next_message();
        }
        rest.extend(bytewise.take_data());
    }

    // The request ID is known once 8 bytes have come, also after an error.
    let id = data.first_chunk::<8>().map(|h| u32::from_be_bytes([h[4], h[5], h[6], h[7]]));
    assert_eq!(bytewise.request_id(), id);
    assert_eq!(lazy.request_id(), id);

    match &whole {
        Ok(m) => {
            let mut l = lazy_first.unwrap().unwrap();
            l.data = lazy_data;
            assert_eq!(&l, m);
            let mut a = first.unwrap().unwrap();
            a.data = first_data;
            assert_eq!(&a, m);
            let mut b = got.unwrap().unwrap();
            b.data = rest;
            assert_eq!(&b, m);
            // A message read can be written, and reads back the same.
            let bytes = m.to_bytes();
            assert_eq!(Message::parse(&bytes).as_ref(), Ok(m));
            let (_, used) = Message::parse_head(&bytes).unwrap().unwrap();
            assert_eq!(&bytes[used..], &m.data[..]);
        }
        Err(Error::Truncated) => {
            assert_eq!(lazy_first, None);
            assert_eq!(first, None);
            assert_eq!(got, None);
            assert_eq!(Message::parse_head(data), Ok(None));
        }
        Err(e) => {
            assert_eq!(lazy_first, Some(Err(*e)));
            assert_eq!(first, Some(Err(*e)));
            assert_eq!(got, Some(Err(*e)));
            assert_eq!(Message::parse_head(data), Err(*e));
        }
    }
});
