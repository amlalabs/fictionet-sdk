//! IPP request and response bodies, as a world playing a printer reads
//! them.
#![no_main]

use fictionet::stdlib::ipp::{Decoder, Error, MAX_HEAD, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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
