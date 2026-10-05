//! Internet Message Format headers, addresses, dates, message IDs and
//! encoded words, as a world playing a mail server reads them.
#![no_main]

use fictionet::stdlib::imf::{
    DateTime, Decoder, Error, Header, decode_text, encode_text, parse_address_list, parse_message_ids, split_message,
    write_address_list, write_message_ids,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let first = (whole.header(), whole.take_body());
    let mut bytewise = Decoder::new();
    let mut header = None;
    let mut body = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        if header.is_none() {
            header = bytewise.header();
        }
        body.extend(bytewise.take_body());
    }
    assert_eq!(first, (header, body));

    // A header read can be written, and reads back the same, unless
    // folding makes it too long.
    let mut values = vec![String::from_utf8_lossy(data).into_owned()];
    if let Ok((h, _)) = split_message(data) {
        match h.to_bytes() {
            Ok(bytes) => {
                let (back, used) = Header::parse(&bytes).unwrap().unwrap();
                assert_eq!(back, h);
                assert_eq!(used, bytes.len());
            }
            Err(e) => assert_eq!(e, Error::TooLarge),
        }
        values.extend(h.fields.into_iter().map(|f| f.value));
    }

    // Each value as every kind of structured field.
    for v in &values {
        let _ = decode_text(v);
        assert_eq!(decode_text(&encode_text(v)), v.replace(['\0', '\r', '\n'], ""));
        if let Ok(list) = parse_address_list(v) {
            // Quoting can make a list longer than a value may be. The
            // writer refuses control characters in local parts and
            // literals, which only obsolete text may hold there. A name
            // holding one is written as encoded words instead.
            match write_address_list(&list) {
                Ok(text) => assert_eq!(parse_address_list(&text).unwrap(), list),
                Err(Error::Address) => assert!(v.contains(|c: char| c.is_ascii_control() && c != '\t')),
                Err(e) => assert_eq!(e, Error::TooLarge),
            }
        }
        if let Ok(d) = DateTime::parse(v) {
            assert_eq!(DateTime::parse(&d.to_text().unwrap()), Ok(d));
        }
        if let Ok(ids) = parse_message_ids(v) {
            // Obsolete forms, such as a quoted left part, are not written.
            match write_message_ids(&ids) {
                Ok(text) => assert_eq!(parse_message_ids(&text).unwrap(), ids),
                Err(Error::MessageId) => assert!(ids.iter().any(|id| id.to_text().is_err())),
                Err(e) => assert_eq!(e, Error::TooLarge),
            }
        }
    }
});
