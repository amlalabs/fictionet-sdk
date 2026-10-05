//! application/x-www-form-urlencoded bodies and query strings, as a world
//! playing a web server reads them.
#![no_main]

use fictionet::stdlib::urlencoded_form::{
    decode_component, parse, percent_decode, percent_encode, query_of, serialize, Decoder, EncodeSet, FormError,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(pairs) = parse(data) else { return };

    // The body, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    whole.finish();
    let mut again = Vec::new();
    while let Some(p) = whole.next_pair() {
        again.push(p.unwrap());
    }
    assert_eq!(again, pairs);
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(p) = bytewise.next_pair() {
            again.push(p.unwrap());
        }
    }
    bytewise.finish();
    while let Some(p) = bytewise.next_pair() {
        again.push(p.unwrap());
    }
    assert_eq!(again, pairs);

    // Pairs read can be written, and read back the same. Writing can grow
    // a form (a byte that is not UTF-8 becomes U+FFFD, nine bytes once
    // encoded), so the writer may refuse a long one, but only as too long.
    match serialize(&pairs) {
        Ok(form) => assert_eq!(parse(form.as_bytes()).unwrap(), pairs),
        Err(e) => assert_eq!(e, FormError::TooLong),
    }

    // Percent encoding with a set that holds % comes back exactly.
    let raw = percent_decode(data).unwrap();
    assert!(raw.len() <= data.len());
    for set in EncodeSet::ALL {
        let encoded = percent_encode(data, set, set == EncodeSet::Form).unwrap();
        assert!(encoded.is_ascii());
        if set == EncodeSet::Form {
            assert_eq!(decode_component(encoded.as_bytes()), String::from_utf8_lossy(data));
        } else if set.contains(b'%') {
            assert_eq!(percent_decode(encoded.as_bytes()).unwrap(), data);
        }
    }
    let _ = parse(query_of(data));
});
