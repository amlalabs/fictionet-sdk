//! RESP values, commands, custom limits, and strict writer contracts.
#![no_main]

use fictionet::stdlib::codec::{Decode, Fail, Lcg, Wire, contract, test_support::decode_all};
use fictionet::stdlib::resp::{
    Command, Commands, Limits, MAX_FRAME_LEN, MAX_LINE_LEN, ParseError, Resp2, Value, Values,
    WireError,
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
    contract::check_wire::<Resp2>(data);
    contract::check_wire_value(&WireValue(Value::simple(
        data.iter().take(MAX_LINE_LEN + 1).copied().collect::<Vec<_>>(),
    )));
    contract::check_wire_value(&Command::new([data.get(..MAX_LINE_LEN).unwrap_or(data)]));
    let mut rng = Lcg::new(data.iter().fold(0x9e37_79b9_7f4a_7c15, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    }));
    let small = Limits { bulk: 6, elements: 3, depth: 2, line: 6, frame: 40 };
    let drawn = Limits {
        bulk: rng.index(64),
        elements: rng.index(16),
        depth: if rng.index(4) == 0 { usize::MAX } else { rng.index(8) },
        line: rng.index(64),
        frame: rng.index(data.len().saturating_add(2)),
    };
    for (index, limits) in [Limits::DEFAULT, small, drawn].into_iter().enumerate() {
        // Default and small limits keep all chunk and prefix checks. Drawn limits
        // exercise whole input without repeating those expensive schedules.
        if index < 2 {
            let allocation = 2 * limits.frame.clamp(1, MAX_FRAME_LEN);
            contract::check_decode_with_alloc_limit(|| Values::with_limits(limits).map(WireValue), data, allocation);
            contract::check_decode_with_alloc_limit(|| Commands::with_limits(limits), data, allocation);
        }
        let values = decode_all(|| Values::with_limits(limits), data);
        let commands = decode_all(|| Commands::with_limits(limits), data);
        if index == 0 {
            // Exact parsing bypasses the stream's scan gate. These parsers use default limits.
            partial_oracle(data, Value::parse(data), &values, |_| false);
            partial_oracle(data, Command::parse(data), &commands, |command| command.args.is_empty());
        }
        for command in commands.0 {
            contract::check_wire_value(&command);
        }
        for value in values.0 {
            if let Ok(bytes) = value.to_bytes() {
                assert_eq!(Value::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
            }
            contract::check_wire_value(&Resp2(value.clone()));
            contract::check_wire_value(&Resp2::mapped(value));
        }
    }
});

fn partial_oracle<T: Wire<ParseError = WireError, WriteError = WireError>>(
    data: &[u8],
    parsed: Result<T, WireError>,
    decoded: &(Vec<T>, Option<Fail<ParseError>>),
    empty: impl Fn(&T) -> bool,
) {
    let expected = match parsed {
        Ok(value) => (if empty(&value) { vec![] } else { vec![value.to_bytes().unwrap()] }, None),
        // An empty stream has no incomplete frame.
        Err(WireError::Incomplete) => (vec![], (!data.is_empty()).then_some(Fail::Truncated { unread: data.len() })),
        Err(WireError::Parse(error)) if error != ParseError::FrameTooLarge => (vec![], Some(Fail::Protocol(error))),
        // Trailing frames need prefix parsing. Size expansion can be refused by
        // Wire::parse after a stream has successfully read the value.
        _ => return,
    };
    let actual: Vec<_> = decoded.0.iter().map(|value| value.to_bytes().unwrap()).collect();
    assert_eq!((actual, decoded.1.clone()), expected);
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
