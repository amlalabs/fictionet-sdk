#![no_main]

use fictionet::stdlib::codec::Frames;
use core::time::Duration;
use fictionet::stdlib::{
    codec::{
        ByteFault, Carry, Decode, Direction, Ending, Faults, Interceptor, ItemFault, Lines, Pipe,
        PumpError, Recorder, Rewrite, Rule, Stream, StreamEvent, Trigger, Wire,
        write_bounded,
    }, test_support,
    json, modbus,
};
use libfuzzer_sys::fuzz_target;

fn forward<D: Decode>(make: impl Fn() -> D, input: &[u8])
where
    D::Item: Clone,
    D::Error: Clone,
{
    // Both policies must preserve every consumed byte in the recording pass.
    for empty_plan in [false, true] {
        let mut stream = Stream::new(make());
        let proxy = Interceptor::new(32768);
        let mut faults = Faults::new(0, 32768, 8);
        let mut recorder = Recorder::new(8, 512);
        let mut output = Vec::new();
        for chunk in input.chunks(1).chain(core::iter::once(&[][..])) {
            if chunk.is_empty() {
                stream.end();
            } else if !stream.is_done() {
                assert_eq!(stream.push(chunk), chunk.len());
            }
            loop {
                let observe = |event: StreamEvent<'_, D::Item, D::Error>| {
                    match &event {
                        StreamEvent::Item { bytes, range, .. }
                        | StreamEvent::Skipped { bytes, range }
                        | StreamEvent::Failed { bytes, range, .. } => {
                            assert_eq!(*bytes, &input[range.start as usize..range.end as usize]);
                        }
                        _ => {}
                    }
                    recorder.observe_tagged(7, Direction::ClientToServer, event);
                };
                let result = if empty_plan {
                    faults
                        .next_with_observed(
                            &mut stream,
                            &mut output,
                            &[],
                            write_bounded::<modbus::Frame>,
                            observe,
                        )
                        .map(|result| result.is_err())
                } else {
                    proxy
                        .next_with_observed(
                            &mut stream,
                            &mut output,
                            |_, _, _| Rewrite::Forward,
                            write_bounded::<modbus::Frame>,
                            observe,
                        )
                        .map(|result| result.is_err())
                };
                assert_eq!(output, input[..stream.offset() as usize]);
                match result {
                    Some(false) => {}
                    Some(true) => {
                        assert!(stream.failed().is_some());
                        break;
                    }
                    None => break,
                }
            }
            assert!(recorder.len() <= 8);
            assert!(recorder.retained_bytes() <= 512);
            assert_eq!(
                recorder.iter().map(|e| e.bytes.len()).sum::<usize>(),
                recorder.retained_bytes()
            );
        }
        faults.flush(&mut output).unwrap();
        assert_eq!(output, input[..stream.offset() as usize]);
        assert!(stream.is_done());
    }
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
            when: Trigger::Every(23),
            fault: ByteFault::Repeat {
                range: Some(1..3),
                copies: 3,
            },
        },
        Rule {
            when: Trigger::Every(19),
            fault: ByteFault::Drop(Some(1..4)),
        },
        Rule {
            when: Trigger::Every(17),
            fault: ByteFault::Split {
                at: 2,
                delay: Duration::from_millis(3),
            },
        },
        Rule {
            when: Trigger::Every(13),
            fault: ByteFault::Replace(replacement.to_bytes().unwrap()),
        },
        Rule {
            when: Trigger::Every(11),
            fault: ByteFault::Repeat {
                range: None,
                copies: 2,
            },
        },
        Rule {
            when: Trigger::Every(7),
            fault: ByteFault::Delay(Duration::from_millis(1)),
        },
        Rule {
            when: Trigger::Every(5),
            fault: ByteFault::Drop(None),
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
            when: Trigger::Every(11),
            fault: ItemFault::Hold { window: 2 },
        },
        Rule {
            when: Trigger::Window { start: 2, end: 3 },
            fault: ItemFault::Action {
                delay: Some(Duration::from_millis(1)),
                rewrite: Rewrite::Raw(vec![0, 1]),
            },
        },
        Rule {
            when: Trigger::Every(7),
            fault: ItemFault::Action {
                delay: Some(Duration::from_millis(2)),
                rewrite: Rewrite::Forward,
            },
        },
        Rule {
            when: Trigger::Every(5),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Replace(vec![replacement]),
            },
        },
        Rule {
            when: Trigger::Chance { take: 1, out_of: 3 },
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Drop,
            },
        },
        Rule {
            when: Trigger::Chance { take: 1, out_of: 2 },
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Repeat(2),
            },
        },
    ];
    let mut stream = Stream::new(make());
    let mut faults = Faults::new(seed, 65536, 8);
    let mut recorder = Recorder::new(8, 512);
    let mut output = Vec::new();
    let mut markers = Vec::new();
    let mut bytes = Vec::new();
    for chunk in test_support::chunks(input, &[7, 1, 31]).chain(core::iter::once(&[][..])) {
        bytes.clear();
        let marker = faults.bytes(&byte_plan, chunk, &mut bytes).unwrap();
        if chunk.is_empty() {
            stream.end();
        }
        let split = marker.map_or(0, |marker| marker.at);
        for (part, mut rest) in [&bytes[..split], &bytes[split..]].into_iter().enumerate() {
            if part == 1 {
                if let Some(marker) = marker {
                    markers.push((output.len(), marker.duration));
                }
            }
            loop {
                if stream.is_done() {
                    break;
                }
                let taken = stream.push(rest);
                rest = &rest[taken..];
                let before = stream.offset();
                loop {
                    let start = output.len();
                    let offset = stream.offset();
                    let result = faults.next_with_observed(
                        &mut stream,
                        &mut output,
                        &item_plan,
                        write_bounded,
                        recorder.observer(3, Direction::ServerToClient),
                    );
                    assert!(output.len() <= 65536);
                    assert!(faults.held_count() <= 8);
                    assert!(faults.held_bytes() <= 65536);
                    match result {
                        Some(Ok(Some(marker))) => markers.push((marker.at, marker.duration)),
                        Some(Ok(None)) => {}
                        Some(Err(PumpError::Handler(_))) => {
                            assert_eq!(output.len(), start);
                            if stream.offset() == offset {
                                break;
                            }
                        }
                        Some(Err(PumpError::Decode(_))) | None => break,
                    }
                }
                assert!(recorder.len() <= 8);
                assert!(recorder.retained_bytes() <= 512);
                if rest.is_empty() || stream.is_done() {
                    break;
                }
                if taken == 0 && stream.offset() == before {
                    break;
                }
            }
        }
    }
    let start = output.len();
    if faults.flush(&mut output).is_err() {
        assert_eq!(output.len(), start);
    } else {
        assert_eq!(faults.held_bytes(), 0);
        assert_eq!(faults.held_count(), 0);
    }
    (output, markers)
}

fuzz_target!(|data: &[u8]| {
    let input = data.get(..16384).unwrap_or(data);
    let seed = data
        .iter()
        .take(8)
        .fold(0u64, |seed, byte| (seed << 8) | u64::from(*byte));
    forward(Frames::<modbus::Frame>::new, input);
    forward(json::Values::new, input);
    forward(
        || {
            Pipe::new(
                Frames::<modbus::Frame>::new(),
                Lines::new(128, Ending::LfOrCrlf),
                |frame: modbus::Frame| Carry::Bytes(frame.pdu),
            )
        },
        input,
    );
    forward(|| Lines::new(128, Ending::LfOrCrlf), input);
    assert_eq!(
        faults(Frames::<modbus::Frame>::new, input, seed),
        faults(Frames::<modbus::Frame>::new, input, seed)
    );
    assert_eq!(
        faults(|| Lines::new(128, Ending::LfOrCrlf), input, seed),
        faults(|| Lines::new(128, Ending::LfOrCrlf), input, seed)
    );
});
