//! JSON texts and streams of them, as a world playing a web API or a
//! JSON-RPC server reads them.
#![no_main]

use fictionet::stdlib::json::{self, Decoder, Limits, Value};
use libfuzzer_sys::fuzz_target;

/// How the bytes reach the decoder and how its values are taken.
#[derive(Clone, Copy)]
enum Schedule {
    /// All at once, then every value.
    Whole,
    /// A byte at a time, every value after each byte.
    Bytewise,
    /// Chunks of a few bytes, at most one value taken after each, so
    /// read bytes wait in the buffer while more come.
    OnePerFeed(usize),
}

/// Every value the decoder gives, up to and including its first error.
/// With `end`, the stream is then ended with `Decoder::finish` and the
/// rest is taken.
fn decode(data: &[u8], limits: Limits, schedule: Schedule, end: bool) -> Vec<Result<Value, json::Error>> {
    let mut d = Decoder::with_limits(limits);
    let mut out = Vec::new();
    let (chunks, one): (Vec<&[u8]>, bool) = match schedule {
        Schedule::Whole => (vec![data], false),
        Schedule::Bytewise => (data.chunks(1).collect(), false),
        Schedule::OnePerFeed(n) => (data.chunks(n.max(1)).collect(), true),
    };
    let take = |d: &mut Decoder, out: &mut Vec<_>, one: bool| {
        while let Some(v) = d.next_value() {
            let stop = v.is_err();
            out.push(v);
            if stop {
                return true;
            }
            if one {
                break;
            }
        }
        false
    };
    for chunk in chunks {
        d.feed(chunk);
        if take(&mut d, &mut out, one) {
            return out;
        }
        // What is held never passes the bytes fed so far.
        assert!(d.buffered() <= data.len());
    }
    if end {
        d.finish();
    }
    take(&mut d, &mut out, false);
    out
}

/// A value written reads back the same, and writes the same text again.
fn round_trip(v: &Value, limits: &Limits) {
    let text = v.write_with(limits).unwrap();
    let back = json::parse_with(text.as_bytes(), limits).unwrap();
    assert_eq!(&back, v);
    assert_eq!(back.write_with(limits).unwrap(), text);
}

fuzz_target!(|input: &[u8]| {
    // The first two bytes pick tighter limits and a chunk size.
    let (limits, chunk, data) = match input {
        [a, b, rest @ ..] if a & 0x80 != 0 => {
            let limits = Limits { depth: usize::from(a & 0x0f), size: usize::from(*b) * 4, elements: usize::from(a >> 4 & 0x07) * 4 + 1 };
            (limits, usize::from(b % 7) + 1, rest)
        }
        [_, b, rest @ ..] => (Limits::default(), usize::from(b % 7) + 1, rest),
        _ => (Limits::default(), 1, input),
    };
    // The input as one JSON text.
    let parsed = json::parse_with(data, &limits);
    if let Ok(v) = &parsed {
        round_trip(v, &limits);
    }
    // The input as a stream, split three ways. Each split gives the same
    // values, whether or not the stream then ends.
    for end in [false, true] {
        let whole = decode(data, limits, Schedule::Whole, end);
        assert_eq!(whole, decode(data, limits, Schedule::Bytewise, end));
        assert_eq!(whole, decode(data, limits, Schedule::OnePerFeed(chunk), end));
        for v in whole.iter().flatten() {
            round_trip(v, &limits);
        }
        // A whole JSON text, as a stream that then ends, gives just its
        // value.
        if end && let Ok(v) = &parsed {
            assert_eq!(whole, [Ok(v.clone())]);
        }
    }
});
