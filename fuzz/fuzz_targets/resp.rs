//! RESP values, commands, custom limits, and strict writer contracts.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Fail, Lcg, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::resp::harness::wire_same;
use fictionet::stdlib::protocols::resp::{
    Command, Commands, Error, Limits, MAX_FRAME_LEN, MAX_LINE_LEN, Resp2, Value, Values,
};
use fictionet::stdlib::test_support::decode_all;
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
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one value. Refuses malformed, incomplete, trailing, or unwritable input.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Value::parse(bytes).map(Self)
    }
    /// Appends a value. Refuses fields or sizes the strict RESP writer cannot preserve.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.0.write(out)
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = <WireValue as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Command as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Resp2 as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let _ = assert_write(&WireValue(Value::simple(
        data.iter()
            .take(MAX_LINE_LEN + 1)
            .copied()
            .collect::<Vec<_>>(),
    )));
    let _ = assert_write(&Command::new([data.get(..MAX_LINE_LEN).unwrap_or(data)]));
    let mut rng = Lcg::new(data.iter().fold(0x9e37_79b9_7f4a_7c15, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    }));
    let small = Limits {
        bulk: 6,
        elements: 3,
        depth: 2,
        line: 6,
        frame: 40,
    };
    let drawn = Limits {
        bulk: rng.index(64),
        elements: rng.index(16),
        depth: if rng.index(4) == 0 {
            usize::MAX
        } else {
            rng.index(8)
        },
        line: rng.index(64),
        frame: rng.index(data.len().saturating_add(2)),
    };
    for (index, limits) in [Limits::DEFAULT, small, drawn].into_iter().enumerate() {
        // Default and small limits keep all chunk and prefix checks. Drawn limits
        // exercise whole input without repeating those expensive schedules.
        if index < 2 {
            let allocation = 2 * limits.frame.clamp(1, MAX_FRAME_LEN);
            assert_eq!(
                decode_chunks(
                    &mut Stream::new(Values::with_limits(limits).map(WireValue)),
                    chunks(data, &[1, 7, 64]),
                    |s| {
                        assert!(s.allocated() <= allocation);
                    }
                ),
                decode_all(|| Values::with_limits(limits).map(WireValue), data),
            );
            assert_eq!(
                decode_chunks(
                    &mut Stream::new(Commands::with_limits(limits)),
                    chunks(data, &[1, 7, 64]),
                    |s| {
                        assert!(s.allocated() <= allocation);
                    }
                ),
                decode_all(|| Commands::with_limits(limits), data),
            );
        }
        let values = decode_all(|| Values::with_limits(limits), data);
        let commands = decode_all(|| Commands::with_limits(limits), data);
        if index == 0 {
            // Exact parsing bypasses the stream's scan gate. These parsers use default limits.
            partial_oracle(data, Value::parse(data), &values, |_| false);
            partial_oracle(data, Command::parse(data), &commands, |command| {
                command.args.is_empty()
            });
        }
        for command in commands.0 {
            let _ = assert_write(&command);
        }
        for value in values.0 {
            if let Ok(bytes) = value.to_bytes() {
                assert_eq!(Value::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
            }
            let _ = assert_write(&Resp2(value.clone()));
            let _ = assert_write(&Resp2::mapped(value));
        }
    }
});

fn partial_oracle<T: Wire<ParseError = Error, WriteError = Error>>(
    data: &[u8],
    parsed: Result<T, Error>,
    decoded: &(Vec<T>, Option<Fail<Error>>),
    empty: impl Fn(&T) -> bool,
) {
    let expected = match parsed {
        Ok(value) => (
            if empty(&value) {
                vec![]
            } else {
                vec![value.to_bytes().unwrap()]
            },
            None,
        ),
        // An empty stream has no incomplete frame.
        Err(Error::Incomplete) => (
            vec![],
            (!data.is_empty()).then_some(Fail::Truncated { unread: data.len() }),
        ),
        // Trailing frames need prefix parsing. Size expansion can be refused by
        // Wire::parse after a stream has successfully read the value.
        Err(Error::Trailing | Error::Unwritable | Error::FrameTooLarge) => return,
        Err(error) => (vec![], Some(Fail::Protocol(error))),
    };
    let actual: Vec<_> = decoded
        .0
        .iter()
        .map(|value| value.to_bytes().unwrap())
        .collect();
    assert_eq!((actual, decoded.1.clone()), expected);
}
