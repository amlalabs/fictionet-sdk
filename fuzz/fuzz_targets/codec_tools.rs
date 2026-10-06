#![no_main]

use core::time::Duration;
use fictionet::stdlib::{
    codec::{
        ByteFault, Decode, Direction, Ending, Faults, Interceptor, ItemFault, Lines, Recorder,
        Rewrite, Rule, Stream, Trigger, Wire, test_support,
    },
    modbus,
};
use libfuzzer_sys::fuzz_target;

fn forward<D: Decode>(make: impl Fn() -> D, input: &[u8])
where
    D::Item: Clone,
    D::Error: Clone,
{
    let mut stream = Stream::new(make());
    let proxy = Interceptor::new(32768);
    let mut recorder = Recorder::new(8, 512);
    let mut output = Vec::new();
    let mut expected = Vec::new();
    for chunk in input.chunks(1).chain(core::iter::once(&[][..])) {
        if chunk.is_empty() {
            stream.end();
        }
        if !stream.is_done() {
            assert_eq!(stream.push(chunk), chunk.len());
        }
        while let Some(r) =
            recorder.with_next(Direction::ClientToServer, &mut stream, |_, raw, range| {
                let source = &input[range.start as usize..range.end as usize];
                assert_eq!(raw, source);
                expected.extend_from_slice(source);
                proxy.apply::<modbus::Frame>(raw, Rewrite::Forward, &mut output)
            })
        {
            assert!(recorder.len() <= recorder.max_entries());
            assert!(recorder.retained_bytes() <= recorder.max_bytes());
            match r {
                Ok(r) => r.unwrap(),
                Err(_) => break,
            }
        }
        assert!(recorder.len() <= 8);
        assert!(recorder.retained_bytes() <= 512);
        assert_eq!(
            recorder.iter().map(|e| e.bytes.len()).sum::<usize>(),
            recorder.retained_bytes()
        );
    }
    assert_eq!(output, expected);
    assert!(stream.is_done());
}

fn faults<D: Decode>(
    make: impl Fn() -> D,
    input: &[u8],
    seed: u64,
) -> (Vec<u8>, Vec<(usize, Duration)>)
where
    D::Item: Clone,
    D::Error: Clone,
{
    let replacement = modbus::Frame {
        transaction: 1,
        unit: 1,
        pdu: vec![3],
    };
    let byte_plan = [
        Rule {
            when: Trigger::Every(13),
            fault: ByteFault::Replace(replacement.to_bytes().unwrap()),
        },
        Rule {
            when: Trigger::Every(11),
            fault: ByteFault::Duplicate(2),
        },
        Rule {
            when: Trigger::Every(7),
            fault: ByteFault::Delay(Duration::from_millis(1)),
        },
        Rule {
            when: Trigger::Every(5),
            fault: ByteFault::Drop,
        },
        Rule {
            when: Trigger::Every(3),
            fault: ByteFault::Corrupt {
                offset: None,
                xor: 1,
            },
        },
        Rule {
            when: Trigger::Every(2),
            fault: ByteFault::Truncate(2),
        },
    ];
    let item_plan = [
        Rule {
            when: Trigger::Every(7),
            fault: ItemFault::Delay(Duration::from_millis(2)),
        },
        Rule {
            when: Trigger::Every(5),
            fault: ItemFault::Replace(vec![replacement]),
        },
        Rule {
            when: Trigger::Chance { take: 1, out_of: 3 },
            fault: ItemFault::Drop,
        },
        Rule {
            when: Trigger::Chance { take: 1, out_of: 2 },
            fault: ItemFault::Duplicate(2),
        },
    ];
    let mut stream = Stream::new(make());
    let mut faults = Faults::new(seed, 512);
    let proxy = Interceptor::new(65536);
    let mut recorder = Recorder::new(8, 512);
    let mut output = Vec::new();
    let mut markers = Vec::new();
    let mut bytes = Vec::new();
    for chunk in test_support::chunks(input, &[7, 1, 31]).chain(core::iter::once(&[][..])) {
        bytes.clear();
        if let Some(delay) = faults.bytes(&byte_plan, chunk, &mut bytes).unwrap() {
            markers.push((output.len(), delay));
        }
        if chunk.is_empty() {
            stream.end();
        }
        let mut rest = bytes.as_slice();
        loop {
            if stream.is_done() {
                break;
            }
            let taken = stream.push(rest);
            rest = &rest[taken..];
            let before = stream.offset();
            while let Some(r) =
                recorder.with_next(Direction::ServerToClient, &mut stream, |_, raw, _| {
                    let action = faults.item(&item_plan);
                    let start = output.len();
                    if let Some(delay) = action.delay {
                        markers.push((start, delay));
                    }
                    let result = proxy.apply(raw, action.rewrite, &mut output);
                    if result.is_err() {
                        assert_eq!(output.len(), start);
                    }
                    assert!(output.len() <= proxy.limit());
                })
            {
                if r.is_err() {
                    break;
                }
            }
            assert!(recorder.len() <= 8);
            assert!(recorder.retained_bytes() <= 512);
            if rest.is_empty() || stream.is_done() {
                break;
            }
            assert!(taken != 0 || stream.offset() > before);
        }
    }
    (output, markers)
}

fuzz_target!(|data: &[u8]| {
    let input = data.get(..16384).unwrap_or(data);
    let seed = data
        .iter()
        .take(8)
        .fold(0u64, |seed, byte| (seed << 8) | u64::from(*byte));
    forward(|| modbus::Frames, input);
    forward(|| Lines::new(128, Ending::LfOrCrlf), input);
    assert_eq!(
        faults(|| modbus::Frames, input, seed),
        faults(|| modbus::Frames, input, seed)
    );
    assert_eq!(
        faults(|| Lines::new(128, Ending::LfOrCrlf), input, seed),
        faults(|| Lines::new(128, Ending::LfOrCrlf), input, seed)
    );
});
