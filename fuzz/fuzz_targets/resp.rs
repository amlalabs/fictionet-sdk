//! RESP, the Redis protocol: values as a world playing a Redis client reads
//! replies, commands as a world playing a server reads requests (arrays of
//! bulk strings and inline lines), and decoders fed the same bytes in two
//! pieces, which must find what one-shot parsing finds.
#![no_main]

use fictionet::stdlib::resp::{Command, Decoder, Limits, ParseError, Value, Version};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((v, used))) = Value::parse(data) {
        assert!(used <= data.len());
        // What was read can be written in either version, that reads again
        // whole, and writing it again gives the same bytes.
        for version in [Version::Resp2, Version::Resp3] {
            let bytes = v.to_bytes(version);
            let (again, n) = Value::parse(&bytes).unwrap().unwrap();
            assert_eq!(n, bytes.len());
            assert_eq!(again.to_bytes(version), bytes);
        }
    }
    if let Ok(Some((c, used))) = Command::parse(data) {
        assert!(used <= data.len());
        let bytes = c.to_bytes();
        assert_eq!(Command::parse(&bytes), Ok(Some((c, bytes.len()))));
    }
    // A decoder fed in two pieces finds what one-shot parsing finds,
    // values and commands, under the default limits and small ones that
    // the input reaches.
    let split = data.first().map_or(0, |&b| usize::from(b) % (data.len() + 1));
    let small = Limits { max_bulk_len: 6, max_elements: 3, max_depth: 2, max_line_len: 6, max_frame_len: 40 };
    for limits in [Limits::DEFAULT, small] {
        let expect = one_shot(data, |b| Value::parse_with(b, &limits), |v| v.to_bytes(Version::Resp3));
        let mut decoder = Decoder::with_limits(limits);
        let got = decode(&mut decoder, data, split, Decoder::next_value, |v| v.to_bytes(Version::Resp3));
        assert_eq!(got, expect);
        let expect = one_shot(data, |b| Command::parse_with(b, &limits), |c| c.args.clone());
        // The decoder skips commands with no arguments, as Redis does.
        let expect: Vec<_> = expect.into_iter().filter(|c| c.as_ref().ok().is_none_or(|a| !a.is_empty())).collect();
        let mut decoder = Decoder::with_limits(limits);
        let got = decode(&mut decoder, data, split, Decoder::next_command, |c| c.args.clone());
        assert_eq!(got, expect);
    }
});

/// Everything one-shot parsing finds in `b`, one after another, up to the
/// first error.
fn one_shot<T, K>(
    mut b: &[u8],
    parse: impl Fn(&[u8]) -> Result<Option<(T, usize)>, ParseError>,
    key: impl Fn(&T) -> K,
) -> Vec<Result<K, ParseError>> {
    let mut out = Vec::new();
    loop {
        match parse(b) {
            Ok(Some((v, used))) => {
                out.push(Ok(key(&v)));
                b = &b[used..];
            }
            Ok(None) => return out,
            Err(e) => {
                out.push(Err(e));
                return out;
            }
        }
    }
}

/// Everything a decoder finds in `b` fed in two pieces cut at `split`, up
/// to the first error.
fn decode<T, K>(
    d: &mut Decoder,
    b: &[u8],
    split: usize,
    next: impl Fn(&mut Decoder) -> Option<Result<T, ParseError>>,
    key: impl Fn(&T) -> K,
) -> Vec<Result<K, ParseError>> {
    let mut out = Vec::new();
    for piece in [&b[..split], &b[split..]] {
        d.feed(piece);
        while let Some(v) = next(d) {
            match v {
                Ok(v) => out.push(Ok(key(&v))),
                Err(e) => {
                    out.push(Err(e));
                    return out;
                }
            }
        }
    }
    out
}
