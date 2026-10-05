//! application/x-www-form-urlencoded bodies and query strings, as a world
//! playing a web server reads them.
#![no_main]
#![allow(deprecated)] // This target also checks the compatibility API.

use fictionet::stdlib::urlencoded_form::{
    decode_component, parse, percent_decode, percent_encode, query_of, serialize, Decoder, EncodeSet, FormError, Pair,
    MAX_INPUT, MAX_PAIRS,
};
use libfuzzer_sys::fuzz_target;
use fictionet::stdlib::codec::contract;

/// Feeds `data` to a decoder in chunks of the sizes `steps` gives, in
/// turn, draining it only after the chunks where `drain` says so. Returns
/// the pairs it handed out and the error it stopped with, if any. A
/// failed decoder must hold nothing and keep failing.
fn stream(data: &[u8], steps: &[u8], drain: u8) -> (Vec<Pair>, Option<FormError>) {
    let mut d = Decoder::new();
    let mut got = Vec::new();
    let mut err = None;
    let pull = |d: &mut Decoder, got: &mut Vec<Pair>| -> Option<FormError> {
        while let Some(p) = d.next_pair() {
            match p {
                Ok(p) => got.push(p),
                Err(e) => return Some(e),
            }
        }
        None
    };
    let mut rest = data;
    let mut i = 0usize;
    while !rest.is_empty() && err.is_none() {
        let step = steps.get(i % steps.len().max(1)).map_or(rest.len(), |&s| usize::from(s).max(1)).min(rest.len());
        d.feed(&rest[..step]);
        rest = &rest[step..];
        if drain & (1 << (i % 8)) != 0 {
            err = pull(&mut d, &mut got);
        }
        i += 1;
    }
    if err.is_none() {
        d.finish();
        err = pull(&mut d, &mut got);
    }
    if let Some(e) = err {
        assert_eq!(d.buffered(), 0);
        d.feed(b"a=b&");
        d.finish();
        assert_eq!(d.next_pair(), Some(Err(e)));
    } else {
        assert_eq!(d.buffered(), 0);
    }
    (got, err)
}

/// Whether `got` is the first pairs of `data`, read as parse would read
/// them with no limits.
fn pairs_prefix(got: &[Pair], data: &[u8]) -> bool {
    let pieces = data.split(|&b| b == b'&').filter(|p| !p.is_empty());
    got.iter().zip(pieces).all(|(pair, piece)| {
        let truncated = piece.len().min(MAX_INPUT);
        let one = parse(&piece[..truncated]).ok();
        truncated < piece.len() || one.as_deref() == Some(std::slice::from_ref(pair))
    })
}

fuzz_target!(|data: &[u8]| {
    use fictionet::stdlib::urlencoded_form::{Frame, Frames};
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Frame>(data);
    contract::check_wire_value(&Frame((String::from_utf8_lossy(data).into_owned(), String::new())));
    let whole = parse(data);

    // The body, split three ways: all at once, a byte at a time, and in
    // pieces of sizes taken from the input, drained now and then. Each
    // gives the pairs parse gives, or a prefix of them and parse's error.
    let steps: &[u8] = &data[..data.len().min(8)];
    let drain = data.first().copied().unwrap_or(0xff) | 1;
    for (got, err) in [stream(data, &[], 0xff), stream(data, &[1], 0xff), stream(data, steps, drain)] {
        match &whole {
            Ok(pairs) => {
                assert_eq!(err, None);
                assert_eq!(&got, pairs);
            }
            Err(e) => {
                // parse checks the length first; a decoder can reach
                // too many pairs before the byte that makes it too long.
                if data.len() > MAX_INPUT {
                    assert!(err.is_some());
                } else {
                    assert_eq!(err, Some(*e));
                }
                assert!(got.len() <= MAX_PAIRS);
                assert!(pairs_prefix(&got, data));
            }
        }
    }
    let Ok(pairs) = whole else {
        assert!(percent_decode(data).is_err() == (data.len() > MAX_INPUT));
        return;
    };

    // Pairs read can be written, and read back the same. Writing can grow
    // a form (a byte that is not UTF-8 becomes U+FFFD, nine bytes once
    // encoded), so the writer may refuse a long one, but only as too long.
    match serialize(&pairs) {
        Ok(form) => assert_eq!(parse(form.as_bytes()).unwrap(), pairs),
        Err(e) => assert_eq!(e, FormError::TooLong),
    }

    // Percent encoding with a set that holds % comes back exactly. The
    // encoder may refuse input that would grow past MAX_INPUT, but what it
    // writes the decoders always read.
    let raw = percent_decode(data).unwrap();
    assert!(raw.len() <= data.len());
    for set in EncodeSet::ALL {
        let encoded = match percent_encode(data, set, set == EncodeSet::Form) {
            Ok(s) => s,
            Err(e) => {
                assert_eq!(e, FormError::TooLong);
                continue;
            }
        };
        assert!(encoded.is_ascii() && encoded.len() <= MAX_INPUT);
        if set == EncodeSet::Form {
            assert_eq!(decode_component(encoded.as_bytes()).unwrap(), String::from_utf8_lossy(data));
        } else if set.contains(b'%') {
            assert_eq!(percent_decode(encoded.as_bytes()).unwrap(), data);
        }
    }
    let _ = parse(query_of(data));
});
