//! RESP, the Redis protocol: values as a world playing a Redis client reads
//! replies, commands as a world playing a server reads requests (arrays of
//! bulk strings and inline lines), and decoders fed the same bytes in
//! pieces, a byte at a time, or while earlier values still wait, which
//! must find what one-shot parsing finds.
#![no_main]
#![allow(deprecated)] // Also check the unchanged compatibility decoder.

use fictionet::stdlib::codec::{Decode, Wire, contract};
use fictionet::stdlib::resp::{
    Command, Commands, Decoder, Limits, MAX_LINE_LEN, ParseError, Value, Values, Version, WireError, WriteError,
};
use libfuzzer_sys::fuzz_target;

// Equality for the contract harness treats NaN as its RESP wire value.
// Value's existing floating-point PartialEq remains unchanged.
#[derive(Debug)]
struct WireValue(Value);
impl PartialEq for WireValue {
    fn eq(&self, other: &Self) -> bool {
        wire_same(&self.0, &other.0)
    }
}
impl Wire for WireValue {
    type ParseError = WireError;
    type WriteError = WriteError;
    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        <Value as Wire>::parse(bytes).map(Self)
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WriteError> {
        Wire::write(&self.0, out)
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(|| Values::new().map(WireValue), data);
    contract::check_decode(Commands::new, data);
    contract::check_wire::<WireValue>(data);
    contract::check_wire::<Command>(data);
    contract::check_wire_value(&WireValue(Value::simple(
        data.iter().take(MAX_LINE_LEN + 1).copied().collect::<Vec<_>>(),
    )));
    contract::check_wire_value(&Command::new([data.get(..MAX_LINE_LEN).unwrap_or(data)]));
    if let Ok(Some((v, used))) = Value::parse(data) {
        assert!(used <= data.len());
        // What was read can be written in either version, that reads again
        // whole, and writing it again gives the same bytes. RESP3 has
        // every type, so the value itself comes back.
        for version in [Version::Resp2, Version::Resp3] {
            let bytes = v.to_bytes(version);
            let (again, n) = Value::parse(&bytes).unwrap().unwrap();
            assert_eq!(n, bytes.len());
            assert_eq!(again.to_bytes(version), bytes);
            if version == Version::Resp3 {
                assert!(same(&v, &again), "{v:?} {again:?}");
            }
        }
    }
    if let Ok(Some((c, used))) = Command::parse(data) {
        assert!(used <= data.len());
        let bytes = c.to_bytes();
        assert_eq!(Command::parse(&bytes), Ok(Some((c, bytes.len()))));
    }
    // Limits taken from the input, and a depth limit far past what the
    // readers take, which must still not overflow the stack.
    let mut rng =
        Rng(data.iter().fold(0x9e37_79b9_7f4a_7c15, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)));
    let small = Limits { max_bulk_len: 6, max_elements: 3, max_depth: 2, max_line_len: 6, max_frame_len: 40 };
    let drawn = Limits {
        max_bulk_len: rng.below(64),
        max_elements: rng.below(16),
        max_depth: if rng.below(4) == 0 { usize::MAX } else { rng.below(8) },
        max_line_len: rng.below(64),
        max_frame_len: rng.below(data.len() + 2),
    };
    for limits in [Limits::DEFAULT, small, drawn] {
        contract::check_decode(|| Values::with_limits(limits).map(WireValue), data);
        contract::check_decode(|| Commands::with_limits(limits), data);
        let values = one_shot(data, |b| Value::parse_with(b, &limits), |v| v.to_bytes(Version::Resp3));
        // The decoder skips commands with no arguments, as Redis does.
        let commands: Vec<_> = one_shot(data, |b| Command::parse_with(b, &limits), |c| c.args.clone())
            .into_iter()
            .filter(|c| c.as_ref().ok().is_none_or(|a| !a.is_empty()))
            .collect();
        // Cut at random, a byte at a time, and in pieces of up to 64.
        let schedules = [rng.cuts(data.len(), 8), (0..=data.len()).collect(), rng.cuts(data.len(), 64)];
        for (i, cuts) in schedules.iter().enumerate() {
            // The last schedule takes at most one value or command per feed,
            // so the rest wait while more bytes come.
            let one = i == 2;
            let got = decode(&mut Decoder::with_limits(limits), data, cuts, one, Decoder::next_value, |v| {
                v.to_bytes(Version::Resp3)
            });
            assert_eq!(got, values);
            let got =
                decode(&mut Decoder::with_limits(limits), data, cuts, one, Decoder::next_command, |c| c.args.clone());
            assert_eq!(got, commands);
        }
    }
});

/// A small generator seeded from the input, so the cuts do not depend on
/// any one byte.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    /// Where to cut `n` bytes into pieces of 1 to `max` bytes.
    fn cuts(&mut self, n: usize, max: usize) -> Vec<usize> {
        let mut cuts = vec![0];
        let mut at = 0;
        while at < n {
            at = (at + 1 + self.below(max)).min(n);
            cuts.push(at);
        }
        cuts
    }
}

/// Whether two values are the same, as RESP3 can tell: NaN is NaN, and
/// the null array is null.
fn same(a: &Value, b: &Value) -> bool {
    let all = |x: &[Value], y: &[Value]| x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y));
    let pairs = |x: &[(Value, Value)], y: &[(Value, Value)]| {
        x.len() == y.len() && x.iter().zip(y).all(|((a, b), (c, d))| same(a, c) && same(b, d))
    };
    match (a, b) {
        (Value::Null | Value::NullArray, Value::Null | Value::NullArray) => true,
        (Value::Double(x), Value::Double(y)) => x == y || (x.is_nan() && y.is_nan()),
        (Value::Array(x), Value::Array(y)) | (Value::Set(x), Value::Set(y)) | (Value::Push(x), Value::Push(y)) => {
            all(x, y)
        }
        (Value::Map(x), Value::Map(y)) => pairs(x, y),
        (Value::Attribute { attributes: x, value: v }, Value::Attribute { attributes: y, value: w }) => {
            pairs(x, y) && same(v, w)
        }
        _ => a == b,
    }
}

fn wire_same(a: &Value, b: &Value) -> bool {
    let all = |x: &[Value], y: &[Value]| x.len() == y.len() && x.iter().zip(y).all(|(x, y)| wire_same(x, y));
    let pairs = |x: &[(Value, Value)], y: &[(Value, Value)]| {
        x.len() == y.len() && x.iter().zip(y).all(|((a, b), (c, d))| wire_same(a, c) && wire_same(b, d))
    };
    match (a, b) {
        (Value::Double(x), Value::Double(y)) => x == y || (x.is_nan() && y.is_nan()),
        (Value::Array(x), Value::Array(y)) | (Value::Set(x), Value::Set(y)) | (Value::Push(x), Value::Push(y)) => {
            all(x, y)
        }
        (Value::Map(x), Value::Map(y)) => pairs(x, y),
        (Value::Attribute { attributes: x, value: v }, Value::Attribute { attributes: y, value: w }) => {
            pairs(x, y) && wire_same(v, w)
        }
        _ => a == b,
    }
}

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

/// Everything a decoder finds in `b` fed the pieces between `cuts`, up to
/// the first error. With `one`, it takes at most one after each feed, and
/// the rest once all the bytes are in.
fn decode<T, K>(
    d: &mut Decoder,
    b: &[u8],
    cuts: &[usize],
    one: bool,
    next: impl Fn(&mut Decoder) -> Option<Result<T, ParseError>>,
    key: impl Fn(&T) -> K,
) -> Vec<Result<K, ParseError>> {
    let mut out = Vec::new();
    let take = |d: &mut Decoder, out: &mut Vec<_>, all: bool| {
        while let Some(v) = next(d) {
            match v {
                Ok(v) => out.push(Ok(key(&v))),
                Err(e) => {
                    out.push(Err(e));
                    return false;
                }
            }
            if !all {
                break;
            }
        }
        true
    };
    for w in cuts.windows(2) {
        d.feed(&b[w[0]..w[1]]);
        if !take(d, &mut out, !one) {
            return out;
        }
    }
    take(d, &mut out, true);
    out
}
