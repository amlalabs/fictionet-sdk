//! IPP request and response bodies, as a world playing a printer reads
//! them.
#![no_main]

use fictionet::stdlib::ipp::{Decoder, Error, Message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let whole = Message::parse(data);

    // The body, split two ways: all at once, and a byte at a time.
    let mut at_once = Decoder::new();
    at_once.feed(data);
    let first = at_once.next_message();
    let first_data = at_once.take_data();
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

    match &whole {
        Ok(m) => {
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
            assert_eq!(first, None);
            assert_eq!(got, None);
            assert_eq!(Message::parse_head(data), Ok(None));
        }
        Err(e) => {
            assert_eq!(first, Some(Err(*e)));
            assert_eq!(got, Some(Err(*e)));
            assert_eq!(Message::parse_head(data), Err(*e));
        }
    }
});
