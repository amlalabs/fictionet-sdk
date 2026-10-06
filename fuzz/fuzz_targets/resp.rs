//! RESP values, commands, custom limits, and strict writer contracts.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::Lcg};
use fictionet::stdlib::resp::{
    Command, Commands, Limits, MAX_FRAME_LEN, MAX_LINE_LEN, Value, Values, WireError,
};
use libfuzzer_sys::fuzz_target;

// The harness needs reflexive equality. NaN has one RESP wire spelling.
#[derive(Debug)]
struct WireValue(Value);
impl PartialEq for WireValue {
    fn eq(&self, other: &Self) -> bool {
        wire_same(&self.0, &other.0)
    }
}
impl Wire for WireValue {
    type ParseError = WireError;
    type WriteError = WireError;
    /// Reads one value. Refuses malformed, incomplete, trailing, or unwritable input.
    fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        Value::parse(bytes).map(Self)
    }
    /// Appends a value. Refuses fields or sizes the strict RESP writer cannot preserve.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        self.0.write(out)
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<WireValue>(data);
    contract::check_wire::<Command>(data);
    contract::check_wire_value(&WireValue(Value::simple(
        data.iter().take(MAX_LINE_LEN + 1).copied().collect::<Vec<_>>(),
    )));
    contract::check_wire_value(&Command::new([data.get(..MAX_LINE_LEN).unwrap_or(data)]));
    let mut rng = Lcg::new(data.iter().fold(0x9e37_79b9_7f4a_7c15, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    }));
    let small = Limits { max_bulk_len: 6, max_elements: 3, max_depth: 2, max_line_len: 6, max_frame_len: 40 };
    let drawn = Limits {
        max_bulk_len: rng.index(64),
        max_elements: rng.index(16),
        max_depth: if rng.index(4) == 0 { usize::MAX } else { rng.index(8) },
        max_line_len: rng.index(64),
        max_frame_len: rng.index(data.len().saturating_add(2)),
    };
    for limits in [Limits::DEFAULT, small, drawn] {
        let allocation = 2 * limits.max_frame_len.clamp(1, MAX_FRAME_LEN);
        contract::check_decode_with_alloc_limit(|| Values::with_limits(limits).map(WireValue), data, allocation);
        contract::check_decode_with_alloc_limit(|| Commands::with_limits(limits), data, allocation);
    }
});

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
