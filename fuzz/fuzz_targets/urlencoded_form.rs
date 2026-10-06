//! Form bodies, query strings, and percent-encoded URL components.
#![no_main]

use fictionet::stdlib::codec::{Fail, Wire, contract, test_support::decode_all};
use fictionet::stdlib::urlencoded_form::{
    EncodeSet, Field, FieldError, Fields, Form, FormError, MAX_INPUT, MAX_PAIRS, PercentEncoded,
    decode_component, percent_decode, query_of,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Fields::new, data, 2 * (MAX_INPUT + 1));
    contract::check_wire::<Field>(data);
    contract::check_wire::<Form>(data);
    contract::check_wire::<PercentEncoded>(data);
    contract::check_wire_value(&Field((String::from_utf8_lossy(data).into_owned(), String::new())));
    let (fields, error) = decode_all(Fields::new, data);
    assert!(fields.len() <= MAX_PAIRS);
    // Every delivered field corresponds to its original nonempty piece.
    for (field, piece) in fields.iter().zip(data.split(|b| *b == b'&').filter(|p| !p.is_empty())) {
        let (name, value) = piece.iter().position(|b| *b == b'=').map_or((piece, &b""[..]),
            |at| (&piece[..at], &piece[at + 1..]));
        assert_eq!(field.0, (decode_component(name).unwrap(), decode_component(value).unwrap()));
    }
    let form = Form { pairs: fields.into_iter().map(|field| field.0).collect() };
    contract::check_wire_value(&form);
    match Form::parse(data) {
        Ok(whole) => {
            assert_eq!(error, None);
            assert_eq!(whole, form);
        }
        Err(FormError::TooManyPairs) if data.len() <= MAX_INPUT => {
            assert_eq!(
                error,
                Some(Fail::Protocol(FieldError::Form(FormError::TooManyPairs)))
            );
        }
        Err(_) => {}
    }
    if error.is_none() {
        match form.to_bytes() {
            Ok(bytes) => assert_eq!(Form::parse(&bytes), Ok(form)),
            Err(e) => assert_eq!(e, FormError::TooLong),
        }
    }
    assert_eq!(percent_decode(data).is_err(), data.len() > MAX_INPUT);
    for set in EncodeSet::ALL {
        let encoded = match PercentEncoded::new(data, set, set == EncodeSet::Form) {
            Ok(value) => value,
            Err(e) => { assert_eq!(e, FormError::TooLong); continue; }
        };
        contract::check_wire_value(&encoded);
        let bytes = encoded.to_bytes().unwrap();
        if set == EncodeSet::Form {
            assert_eq!(decode_component(&bytes).unwrap(), String::from_utf8_lossy(data));
        } else if set.contains(b'%') {
            assert_eq!(percent_decode(&bytes).unwrap(), data);
        }
    }
    let _ = Form::parse(query_of(data));
});
