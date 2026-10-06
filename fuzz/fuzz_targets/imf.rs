//! Internet Message Format headers, addresses, dates, message IDs and
//! encoded words, as a world playing a mail server reads them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::imf::{
    DateTime, Decoder, ENCODED_LINE_LEN, Error, Head, Header, MAX_HEADER_BYTES, decode_text,
    encode_text, parse_address_list, parse_message_ids, split_message, write_address_list,
    write_message_ids,
};
use libfuzzer_sys::fuzz_target;

/// Feeds all of `data` in pieces of `step` bytes, asking for the header
/// and taking the body only when the decoder stops taking bytes in, then
/// finishes the stream.
fn read_stream(data: &[u8], step: usize) -> (Option<Result<Header, Error>>, Vec<u8>) {
    let mut d = Decoder::new();
    let (mut header, mut body, mut rest) = (None, Vec::new(), data);
    while !rest.is_empty() {
        let n = d.feed(&rest[..rest.len().min(step)]);
        assert!(d.buffered() <= MAX_HEADER_BYTES);
        rest = &rest[n..];
        if n == 0 {
            if header.is_none() {
                header = d.header();
            }
            assert!(header.is_some());
            body.extend(d.take_body());
        }
    }
    if header.is_none() {
        header = d.finish();
    }
    body.extend(d.take_body());
    (header, body)
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Head::new, data);
    contract::check_decode(|| Head::with_limit(64), data);
    contract::check_wire::<Header>(data);
    let mut built = Header::default();
    built.push(
        "Subject",
        &String::from_utf8_lossy(data.get(..4096).unwrap_or(data)),
    );
    contract::check_wire_value(&built);
    let mut body = Wire::to_bytes(&Header::default()).unwrap();
    body.extend_from_slice(data.get(..4096).unwrap_or(data));
    contract::check_decode(|| Head::with_limit(64), &body);

    // The stream, split three ways: all at once, a byte at a time, and in
    // pieces with the body left to pile up. Each reads what split_message
    // reads.
    let whole = read_stream(data, usize::MAX);
    let step = 1 + usize::from(data.first().copied().unwrap_or(0)) * 97;
    assert_eq!(read_stream(data, step), whole);
    assert_eq!(read_stream(data, 1), whole);
    match split_message(data) {
        Ok((h, b)) => assert_eq!(whole, (Some(Ok(h)), b.to_vec())),
        Err(e) => assert_eq!(whole.0, Some(Err(e))),
    }

    // A header read can be written, and reads back the same, unless
    // folding makes it too long or it holds obsolete control characters.
    let mut values = vec![String::from_utf8_lossy(data).into_owned()];
    if let Ok((h, _)) = split_message(data) {
        match h.to_bytes() {
            Ok(bytes) => {
                let (back, used) = Header::parse(&bytes).unwrap().unwrap();
                assert_eq!(back, h);
                assert_eq!(used, bytes.len());
            }
            Err(Error::FieldValue) => {
                assert!(h.fields.iter().any(|f| f.value.contains(|c: char| c.is_ascii_control() && c != '\t')))
            }
            Err(e) => assert_eq!(e, Error::TooLarge),
        }
        values.extend(h.fields.into_iter().map(|f| f.value));
    }

    // Each value as every kind of structured field.
    for v in &values {
        let _ = decode_text(v);
        let encoded = encode_text(v);
        assert_eq!(decode_text(&encoded), v.replace(['\0', '\r', '\n'], ""));
        // Lines that hold encoded words fit in 76 characters.
        let mut h = Header::default();
        h.push("Subject", &encoded);
        if let Ok(bytes) = h.to_bytes() {
            assert!(bytes.split(|&c| c == b'\n').all(|l| l.len() <= ENCODED_LINE_LEN + 1));
        }
        if let Ok(list) = parse_address_list(v) {
            // Quoting can make a list longer than a value may be. The
            // writer refuses control characters in local parts and
            // literals, which only obsolete text may hold there, and
            // literals that needed the obsolete quoted-pair. A name
            // holding a control character is written as encoded words.
            match write_address_list(&list) {
                Ok(text) => assert_eq!(parse_address_list(&text).unwrap(), list),
                Err(Error::Address) => {
                    assert!(v.contains(|c: char| (c.is_ascii_control() && c != '\t') || c == '\\'))
                }
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
