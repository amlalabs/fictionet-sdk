use core::{convert::Infallible, time::Duration};
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::{
    codec::{
        Buffer, ByteFault, Carry, Decode, Demux, Direction, Ending, Fail, Faults, InterceptError,
        Interceptor, ItemFault, Layered, Lines, RecordKind, Recorder, Rewrite, RewriteError, Rule,
        Stream, Trigger, Wire, write_bounded,
    },
    json, modbus, test_support,
    test_support::contract,
};

fn frame(transaction: u16) -> modbus::Frame {
    modbus::Frame {
        transaction,
        unit: 1,
        pdu: vec![3, 0, 2, 0, 1],
    }
}

#[test]
fn modbus_two_direction_proxy_records_input_and_faults_output() {
    let requests: Vec<_> = (1..=4).map(frame).collect();
    let input: Vec<_> = requests
        .iter()
        .flat_map(|f| f.to_bytes().unwrap())
        .collect();
    contract::check_decode(Frames::<modbus::Frame>::new, &input);
    let replacement = modbus::Frame {
        unit: 9,
        ..frame(1)
    };
    contract::check_wire_value(&replacement);
    let rules = [
        Rule {
            when: Trigger::At(1),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Replace(vec![replacement.clone()]),
            },
        },
        Rule {
            when: Trigger::At(2),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Drop,
            },
        },
        Rule {
            when: Trigger::At(3),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Repeat(2),
            },
        },
        Rule {
            when: Trigger::At(4),
            fault: ItemFault::Action {
                delay: Some(Duration::from_millis(10)),
                rewrite: Rewrite::Forward,
            },
        },
    ];
    let mut log = Recorder::new(16, 4096);
    let mut client = Stream::new(Frames::<modbus::Frame>::new());
    let mut server = Stream::new(Frames::<modbus::Frame>::new());
    let downstream = Interceptor::new(4096);
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(42));
    let mut faults = Faults::new(4096, 8);
    let mut sent = Vec::new();
    let mut markers = Vec::new();
    for chunk in test_support::chunks(&input, &[1]) {
        assert_eq!(client.push(chunk), chunk.len());
        while let Some(r) = faults.next_with_observed(
            &entropy,
            &mut client,
            &mut sent,
            &rules,
            write_bounded,
            log.observer(0, Direction::ClientToServer),
        ) {
            if let Some(marker) = r.unwrap() {
                markers.push((marker.at, marker.duration));
            }
        }
    }
    client.end();
    assert!(
        faults
            .next_with_observed(
                &entropy,
                &mut client,
                &mut sent,
                &rules,
                write_bounded,
                log.observer(0, Direction::ClientToServer),
            )
            .is_none()
    );
    let (forwarded, failure) = test_support::decode_all(Frames::<modbus::Frame>::new, &sent);
    assert_eq!(failure, None);
    assert_eq!(forwarded, [replacement, frame(3), frame(3), frame(4)]);
    assert_eq!(markers, [(36, Duration::from_millis(10))]);

    let reply = modbus::Frame {
        transaction: 3,
        unit: 1,
        pdu: vec![3, 2, 0, 7],
    }
    .to_bytes()
    .unwrap();
    let mut received = Vec::new();
    assert_eq!(server.push(&reply), reply.len());
    downstream
        .next_observed(
            &mut server,
            &mut received,
            |_, _, _| Rewrite::Forward,
            log.observer(0, Direction::ServerToClient),
        )
        .unwrap()
        .unwrap();
    assert_eq!(received, reply);
    let entries: Vec<_> = log.iter().collect();
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[0].bytes, &input[..12]);
    assert_eq!(entries[3].range, 36..48);
    assert_eq!(entries[4].kind, RecordKind::Ended);
    assert_eq!(entries[5].range, 0..11);
    assert_eq!(entries[5].direction, Direction::ServerToClient);
    assert_eq!(log.dropped(), 0);
}

fn json_lines() -> impl Decode<Item = Result<json::Value, String>, Error = Infallible> {
    Lines::new(1024, Ending::LfOrCrlf).map(|line| {
        line.map_err(|e| e.to_string())
            .and_then(|bytes| json::Value::parse(&bytes).map_err(|e| e.to_string()))
    })
}

fn write_line(value: &json::Value, out: &mut Buffer) -> Result<(), RewriteError<json::Error>> {
    write_bounded(value, out)?;
    if out.room() == 0 {
        return Err(RewriteError::TooLong { limit: out.limit() });
    }
    if out.push(b"\n") != 1 {
        return Err(RewriteError::Allocation);
    }
    Ok(())
}

#[test]
fn json_line_calls_are_logged_dropped_duplicated_and_results_rewritten() {
    let call = b"{ \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"lookup\"}}\r\n";
    let notification = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/ready\"}\n";
    let result = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"text\":\"original\"}}\n";
    let replacement =
        json::Value::parse(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"text\":\"test result\"}}")
            .unwrap();
    let input = [call.as_slice(), notification.as_slice()].concat();
    contract::check_decode(json_lines, &input);
    let mut log = Recorder::new(8, 4096);
    let mut streams = [Stream::new(json_lines()), Stream::new(json_lines())];
    let proxies = [Interceptor::new(4096), Interceptor::new(4096)];
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(4));
    let mut faults = Faults::new(4096, 8);
    let plan = [
        Rule {
            when: Trigger::At(1),
            fault: ItemFault::<json::Value>::Action {
                delay: None,
                rewrite: Rewrite::Repeat(2),
            },
        },
        Rule {
            when: Trigger::At(2),
            fault: ItemFault::Action {
                delay: None,
                rewrite: Rewrite::Drop,
            },
        },
    ];
    let mut sent = Vec::new();
    let mut call_count = 0;
    for byte in &input {
        assert_eq!(streams[0].push(&[*byte]), 1);
        while let Some(r) = faults.next_with_observed(
            &entropy,
            &mut streams[0],
            &mut sent,
            &plan,
            write_line,
            |event| {
                if let fictionet::stdlib::codec::StreamEvent::Item {
                    item: Ok(value), ..
                } = &event
                    && value.get("method").and_then(json::Value::as_str) == Some("tools/call")
                {
                    call_count += 1;
                }
                log.observe_tagged(0, Direction::ClientToServer, event);
            },
        ) {
            r.unwrap();
        }
    }
    assert_eq!(sent, call.repeat(2)); // CRLF and spacing survive duplication.
    assert_eq!(call_count, 1);
    let mut received = Vec::new();
    assert_eq!(streams[1].push(result), result.len());
    proxies[1]
        .next_with_observed(
            &mut streams[1],
            &mut received,
            |item, _, _| {
                assert!(item.as_ref().unwrap().get("result").is_some());
                Rewrite::Replace(vec![replacement.clone()])
            },
            write_line,
            log.observer(0, Direction::ServerToClient),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        test_support::decode_all(json_lines, &received).0,
        [Ok(replacement)]
    );
    assert_eq!(log.iter().last().unwrap().bytes, result);
    assert_eq!(log.iter().next().unwrap().bytes, call);
    assert_eq!(log.iter().nth(1).unwrap().range.start, call.len() as u64);
}

#[test]
fn byte_faults_run_before_modbus_and_line_decoding() {
    let input = frame(1).to_bytes().unwrap();
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(3));
    let mut faults = Faults::new(4096, 8);
    let mut damaged = Vec::new();
    faults
        .bytes(
            &entropy,
            &[Rule {
                when: Trigger::Always,
                fault: ByteFault::Truncate(7),
            }],
            &input,
            &mut damaged,
        )
        .unwrap();
    let mut stream = Stream::new(Frames::<modbus::Frame>::new());
    let mut log = Recorder::new(8, 4096);
    assert_eq!(stream.push(&damaged), 7);
    stream.end();
    assert_eq!(
        stream.with_next_observed(|_, _, _| (), log.observer(0, Direction::ClientToServer)),
        Some(Err(Fail::Truncated { unread: 7 }))
    );
    assert_eq!(log.iter().next().unwrap().bytes, damaged);
    damaged.clear();
    faults
        .bytes(
            &entropy,
            &[Rule {
                when: Trigger::Always,
                fault: ByteFault::Corrupt {
                    offset: Some(3),
                    xor: 1,
                },
            }],
            &input,
            &mut damaged,
        )
        .unwrap();
    assert!(matches!(
        test_support::decode_all(Frames::<modbus::Frame>::new, &damaged).1,
        Some(Fail::Protocol(modbus::Error::Protocol(1)))
    ));

    let line = b"{\"result\":true}\n";
    let mut edited = Vec::new();
    faults
        .bytes(
            &entropy,
            &[Rule {
                when: Trigger::Always,
                fault: ByteFault::Replace(b"{\"result\":false}\n".to_vec()),
            }],
            line,
            &mut edited,
        )
        .unwrap();
    assert_eq!(
        test_support::decode_all(json_lines, &edited).0,
        [Ok(json::Value::parse(b"{\"result\":false}").unwrap())]
    );
}

#[test]
fn pipe_inner_items_require_explicit_outer_framing() {
    let make = || {
        fictionet::stdlib::codec::Pipe::new(
            Frames::<modbus::Frame>::new(),
            Lines::new(64, Ending::LfOrCrlf),
            |frame: modbus::Frame| Carry::Bytes(frame.pdu),
        )
    };
    let outer = modbus::Frame {
        transaction: 7,
        unit: 1,
        pdu: b"ab\n".to_vec(),
    };
    let bytes = outer.to_bytes().unwrap();
    contract::check_decode(make, &bytes);
    let mut stream = Stream::new(make());
    let mut log = Recorder::new(8, 256);
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
    let mut faults = Faults::new(256, 8).with_skips(fictionet::stdlib::codec::SkipPolicy::Drop);
    let plan = [Rule {
        when: Trigger::Always,
        fault: ItemFault::Action {
            delay: None,
            rewrite: Rewrite::Replace(vec![b"xy".to_vec()]),
        },
    }];
    let mut out = Vec::new();
    assert_eq!(stream.push(&bytes), bytes.len());
    faults
        .next_with_observed(
            &entropy,
            &mut stream,
            &mut out,
            &plan,
            |line, target| {
                let mut pdu = line.clone();
                pdu.push(b'\n');
                write_bounded(
                    &modbus::Frame {
                        transaction: 7,
                        unit: 1,
                        pdu,
                    },
                    target,
                )
            },
            |event| {
                if let fictionet::stdlib::codec::StreamEvent::Item {
                    item,
                    bytes: raw,
                    range,
                } = &event
                {
                    assert_eq!(*item, &Layered::Inner(Ok(b"ab".to_vec())));
                    assert!(raw.is_empty());
                    assert_eq!(*range, bytes.len() as u64..bytes.len() as u64);
                }
                log.observe_tagged(0, Direction::ClientToServer, event);
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        test_support::decode_all(make, &out).0,
        [Layered::Inner(Ok(b"xy".to_vec()))]
    );
    assert_eq!(log.iter().next().unwrap().kind, RecordKind::Skipped);
    assert_eq!(log.iter().next().unwrap().bytes, bytes);
    assert!(log.iter().nth(1).unwrap().bytes.is_empty());
    assert_eq!(
        stream.decoder().spans().iter().next().unwrap().outer,
        0..bytes.len() as u64
    );
}

#[test]
fn demux_stream_access_composes_with_all_tools_and_shared_budget() {
    let mut demux = Demux::new(2, 1024, |_: &u8| Frames::<modbus::Frame>::new());
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(8));
    let mut faults = Faults::new(1024, 8);
    let mut log = Recorder::new(8, 512);
    let mut out = [Vec::new(), Vec::new()];
    for key in 0..2u8 {
        let input = frame(u16::from(key)).to_bytes().unwrap();
        assert_eq!(demux.push(&key, &input), input.len());
        let plan = [Rule {
            when: Trigger::Always,
            fault: ItemFault::<modbus::Frame>::Action {
                delay: None,
                rewrite: Rewrite::Repeat(2),
            },
        }];
        while let Some(r) = faults.next_with_observed(
            &entropy,
            demux.get_mut(&key).unwrap(),
            &mut out[usize::from(key)],
            &plan,
            write_bounded,
            log.observer(u64::from(key), Direction::ClientToServer),
        ) {
            r.unwrap();
        }
        assert_eq!(out[usize::from(key)], input.repeat(2));
        assert!(demux.total() <= 1024);
    }
    assert_eq!(demux.total(), 0);
    assert_eq!(log.len(), 2);
    for (key, entry) in log.iter().enumerate() {
        assert_eq!(entry.range.start, 0);
        assert_eq!(entry.tag, key as u64);
    }
    assert!(log.retained_bytes() <= log.max_bytes());
}

#[test]
fn seeded_item_plans_are_repeatable_across_input_chunking() {
    let input: Vec<_> = (0..64).flat_map(|n| frame(n).to_bytes().unwrap()).collect();
    let run = |chunking: &[usize]| {
        let mut stream = Stream::new(Frames::<modbus::Frame>::new());
        let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(27));
        let mut faults = Faults::new(4096, 8);
        let mut out = Vec::new();
        let plan = [
            Rule {
                when: Trigger::Chance { take: 1, out_of: 3 },
                fault: ItemFault::<modbus::Frame>::Action {
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
        for mut chunk in test_support::chunks(&input, chunking) {
            while !chunk.is_empty() {
                let n = stream.push(chunk);
                chunk = &chunk[n..];
                while let Some(r) = faults.next(&entropy, &mut stream, &mut out, &plan) {
                    r.unwrap();
                }
            }
        }
        stream.end();
        while let Some(r) = faults.next(&entropy, &mut stream, &mut out, &plan) {
            r.unwrap();
        }
        out
    };
    assert_eq!(run(&[1]), run(&[73, 2, 1000]));
    assert_eq!(run(&[1]), run(&[]));
}

#[test]
fn recorded_end_leaves_handoff_bytes_and_is_not_repeated() {
    use fictionet::stdlib::proxy_protocol;
    let header = b"PROXY UNKNOWN\r\n";
    let tail = frame(7).to_bytes().unwrap();
    let bytes = [header.as_slice(), tail.as_slice()].concat();
    let mut stream = Stream::new(proxy_protocol::Headers::new());
    let mut log = Recorder::new(8, 512);
    let mut out = Vec::new();
    let proxy = Interceptor::new(512);
    assert_eq!(stream.push(&bytes), bytes.len());
    proxy
        .next_with_observed(
            &mut stream,
            &mut out,
            |item, _, _| {
                assert!(item.is_ok());
                Rewrite::Forward
            },
            write_bounded::<modbus::Frame>,
            log.observer(0, Direction::ClientToServer),
        )
        .unwrap()
        .unwrap();
    for _ in 0..2 {
        assert!(
            proxy
                .next_with_observed(
                    &mut stream,
                    &mut out,
                    |_, _, _| Rewrite::Forward,
                    write_bounded::<modbus::Frame>,
                    log.observer(0, Direction::ClientToServer)
                )
                .is_none()
        );
    }
    assert_eq!(out, header);
    assert_eq!(log.len(), 2);
    assert_eq!(
        log.iter().last().unwrap().range,
        header.len() as u64..header.len() as u64
    );
    assert_eq!(stream.unread(), tail);
    let mut stream = stream.swap(Frames::<modbus::Frame>::new());
    proxy
        .next(&mut stream, &mut out, |_, _, _| {
            Rewrite::<modbus::Frame>::Forward
        })
        .unwrap()
        .unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn failed_write_consumes_only_its_item_and_preserves_prior_output() {
    let input = frame(1).to_bytes().unwrap().repeat(2);
    let mut stream = Stream::new(Frames::<modbus::Frame>::new());
    let proxy = Interceptor::new(128);
    let mut out = vec![42];
    assert_eq!(stream.push(&input), input.len());
    let invalid = modbus::Frame {
        pdu: vec![],
        ..frame(2)
    };
    assert!(matches!(
        proxy.next(&mut stream, &mut out, |_, _, _| Rewrite::Replace(vec![
            frame(2),
            invalid
        ])),
        Some(Err(fictionet::stdlib::codec::InterceptError::Rewrite(
            fictionet::stdlib::codec::RewriteError::Write(modbus::Error::EmptyPdu)
        )))
    ));
    assert_eq!(out, [42]);
    assert_eq!(stream.offset(), 12);
    assert!(stream.failed().is_none());
    proxy
        .next(&mut stream, &mut out, |_, _, _| {
            Rewrite::<modbus::Frame>::Forward
        })
        .unwrap()
        .unwrap();
    assert_eq!(&out[1..], &input[12..]);
}

fn assert_forwarded<D: Decode>(decoder: D, input: &[u8])
where
    D::Error: Clone,
{
    let mut stream = Stream::new(decoder);
    let proxy = Interceptor::new(4096);
    let mut out = Vec::new();
    for chunk in test_support::chunks(input, &[1]) {
        assert_eq!(
            rewrite_input(
                &proxy,
                &mut stream,
                chunk,
                &mut out,
                |_, _, _| Rewrite::Forward,
                write_bounded::<modbus::Frame>
            )
            .unwrap(),
            chunk.len()
        );
    }
    stream.end();
    rewrite_input(
        &proxy,
        &mut stream,
        &[],
        &mut out,
        |_, _, _| Rewrite::Forward,
        write_bounded::<modbus::Frame>,
    )
    .unwrap();
    assert_eq!(out, input);
}

#[test]
fn forward_keeps_oversized_line_skips() {
    assert_forwarded(Lines::new(4, Ending::LfOrCrlf), b"abcdefgh\nok\n");
}

#[test]
fn forward_keeps_json_whitespace() {
    assert_forwarded(json::Values::new(), b"{\"a\":1}\n  {\"b\":2}\n");
}

#[test]
fn forward_keeps_pipe_payloads() {
    let pipe = fictionet::stdlib::codec::Pipe::new(
        Frames::<modbus::Frame>::new(),
        Lines::new(64, Ending::LfOrCrlf),
        |frame: modbus::Frame| Carry::Bytes(frame.pdu),
    );
    let input = modbus::Frame {
        pdu: b"ok\n".to_vec(),
        ..frame(1)
    }
    .to_bytes()
    .unwrap();
    assert_forwarded(pipe, &input);
}

#[test]
fn hold_delivers_second_item_before_first() {
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(7));
    let mut faults = Faults::new(128, 2);
    let plan = [Rule {
        when: Trigger::At(1),
        fault: ItemFault::<modbus::Frame>::Hold { window: 1 },
    }];
    let first = frame(1).to_bytes().unwrap();
    let second = frame(2).to_bytes().unwrap();
    let mut out = Vec::new();
    faults.item(&entropy, &plan, &first, &mut out).unwrap();
    assert!(out.is_empty());
    faults.item(&entropy, &plan, &second, &mut out).unwrap();
    assert_eq!(
        test_support::decode_all(Frames::<modbus::Frame>::new, &out).0,
        [frame(2), frame(1)]
    );
    faults.flush(&mut out).unwrap();
    assert_eq!(out, [second, first].concat());
}

#[test]
fn split_delivers_two_chunks_with_a_delay_between() {
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(7));
    let mut faults = Faults::new(128, 2);
    let delay = Duration::from_millis(3);
    let plan = [Rule {
        when: Trigger::Always,
        fault: ByteFault::Split { at: 2, delay },
    }];
    let mut out = b"!".to_vec();
    let marker = faults
        .bytes(&entropy, &plan, b"abcd", &mut out)
        .unwrap()
        .unwrap();
    let pushes = [&out[1..marker.at], &out[marker.at..]];
    assert_eq!(pushes, [b"ab".as_slice(), b"cd".as_slice()]);
    assert_eq!(marker.duration, delay);
}

#[test]
fn recorder_preserves_oversized_failure_ranges_with_truncation() {
    for max_bytes in [0, 4] {
        let mut log = Recorder::new(16, max_bytes);
        let mut stream = Stream::new(Frames::<modbus::Frame>::new());
        assert_eq!(stream.push(&[0, 0, 0, 1, 0, 2, 1, 3]), 8);
        assert!(
            stream
                .with_next_observed(|_, _, _| (), log.observer(0, Direction::ClientToServer))
                .unwrap()
                .is_err()
        );
        let record = log.iter().next().unwrap();
        assert_eq!(
            record.kind,
            RecordKind::Failed(Fail::Protocol(modbus::Error::Protocol(1)))
        );
        assert_eq!(record.range, 0..8);
        assert_eq!(record.bytes.len(), max_bytes);
        assert!(record.truncated);
        assert_eq!(log.dropped(), 0);
    }
    let mut bytes = vec![0; 40];
    bytes[5] = 200;
    let mut stream = Stream::new(Frames::<modbus::Frame>::new());
    let mut log = Recorder::new(8, 32);
    assert_eq!(stream.push(&bytes), 40);
    stream.end();
    assert!(
        stream
            .with_next_observed(|_, _, _| (), log.observer(0, Direction::ClientToServer))
            .unwrap()
            .is_err()
    );
    let record = log.iter().next().unwrap();
    assert_eq!(
        record.kind,
        RecordKind::Failed(Fail::Truncated { unread: 40 })
    );
    assert_eq!(record.range, 0..40);
    assert_eq!(record.bytes.len(), 32);
    assert!(record.truncated);
}

#[test]
fn skip_output_is_transactional_on_limits_writes_and_decode_failure() {
    use fictionet::stdlib::codec::{InterceptError, RewriteError, SkipPolicy};
    let input = b" \n{}";
    let mut stream = Stream::new(json::Values::new());
    assert_eq!(stream.push(input), input.len());
    let mut out = vec![42];
    let result = Interceptor::new(4).next(&mut stream, &mut out, |_, _, _| {
        Rewrite::<json::Value>::Forward
    });
    assert!(matches!(
        result,
        Some(Err(InterceptError::Rewrite(RewriteError::TooLong { .. })))
    ));
    assert_eq!(out, [42]);

    let mut stream = Stream::new(json::Values::new());
    assert_eq!(stream.push(input), input.len());
    let result = Interceptor::new(64).next_with(
        &mut stream,
        &mut out,
        |_, _, _| Rewrite::Replace(vec![()]),
        |_, _| Err(RewriteError::Write("refused")),
    );
    assert_eq!(
        result,
        Some(Err(InterceptError::Rewrite(RewriteError::Write("refused"))))
    );
    assert_eq!(out, [42]);

    let mut stream = Stream::new(json::Values::new());
    assert_eq!(stream.push(b" \n!"), 3);
    stream.end();
    assert!(
        Interceptor::new(64)
            .next(&mut stream, &mut out, |_, _, _| {
                Rewrite::<json::Value>::Forward
            })
            .unwrap()
            .is_err()
    );
    assert_eq!(out, b"* \n");
    assert_eq!(
        [out[1..].to_vec(), stream.unread().to_vec()].concat(),
        b" \n!"
    );
    out.truncate(1);

    let mut stream = Stream::new(json::Values::new());
    let proxy = Interceptor::new(64).with_skips(SkipPolicy::Drop);
    forward_input(&proxy, &mut stream, input, &mut out, |_, _, _| {
        Rewrite::Forward
    })
    .unwrap();
    assert_eq!(out, b"*{}");
    let mut stream = Stream::new(json::Values::new());
    assert_eq!(stream.push(b"   "), 3);
    assert!(
        Interceptor::new(2)
            .next(&mut stream, &mut Vec::new(), |_, _, _| {
                Rewrite::<json::Value>::Forward
            })
            .unwrap()
            .is_err()
    );
}

#[test]
fn forward_composes_with_collect_and_assemble() {
    use fictionet::stdlib::codec::{Assemble, Collect, Fragment};
    let input = b" {\"result\": true} \n";
    assert_forwarded(Collect::<json::Value>::new(128), input);
    let input = b"ab\ncd\n";
    let make = || {
        Assemble::new(
            Lines::new(64, Ending::LfOrCrlf),
            128,
            |line: Result<Vec<u8>, fictionet::stdlib::codec::LineError>| match line {
                Ok(data) => Fragment::Part {
                    last: data == b"cd",
                    data,
                },
                Err(error) => Fragment::Whole(error),
            },
        )
    };
    contract::check_decode(make, input);
    assert_forwarded(make(), input);
}

#[test]
fn intercept_helper_keeps_prior_items_and_handoff_bytes() {
    let proxy = Interceptor::new(128);
    let mut stream = Stream::new(Frames::<modbus::Frame>::new());
    let input = frame(1).to_bytes().unwrap().repeat(2);
    let mut calls = 0;
    let mut out = vec![42];
    let error = forward_input(&proxy, &mut stream, &input, &mut out, |_, _, _| {
        calls += 1;
        if calls == 1 {
            Rewrite::Forward
        } else {
            Rewrite::Replace(vec![modbus::Frame {
                pdu: vec![],
                ..frame(2)
            }])
        }
    })
    .unwrap_err();
    assert_eq!(error.0, input.len());
    assert!(matches!(
        error.1,
        fictionet::stdlib::codec::InterceptError::Rewrite(
            fictionet::stdlib::codec::RewriteError::Write(modbus::Error::EmptyPdu)
        )
    ));
    assert_eq!(&out[1..], &input[..12]);
    assert_eq!(stream.offset(), input.len() as u64);

    out.truncate(1);
    let header = b"PROXY UNKNOWN\r\n";
    let input = [header.as_slice(), b"rest"].concat();
    let mut stream = Stream::new(fictionet::stdlib::proxy_protocol::Headers::new());
    let taken = rewrite_input(
        &proxy,
        &mut stream,
        &input,
        &mut out,
        |_, _, _| Rewrite::Forward,
        write_bounded::<modbus::Frame>,
    )
    .unwrap();
    assert_eq!(taken, input.len());
    assert_eq!(&out[1..], header);
    assert_eq!(stream.unread(), b"rest");
}

#[test]
fn intercept_after_eof_does_not_accept_new_input() {
    let mut stream = Stream::new(json::Values::new());
    let proxy = Interceptor::new(32);
    let mut out = Vec::new();
    assert_eq!(stream.push(b"1"), 1);
    stream.end();
    assert_eq!(
        forward_input(&proxy, &mut stream, b"2", &mut out, |_, _, _| {
            Rewrite::Forward
        })
        .unwrap(),
        0
    );
    assert_eq!(out, b"1");
    assert_eq!(
        forward_input(&proxy, &mut stream, b"3", &mut out, |_, _, _| {
            Rewrite::Forward
        })
        .unwrap(),
        0
    );
    assert_eq!(out, b"1");
}

#[test]
fn intercept_keeps_good_frame_before_decode_failure() {
    let first = frame(1).to_bytes().unwrap();
    let input = [first.as_slice(), &[0, 2, 0, 1, 0, 2]].concat();
    let mut stream = Stream::new(Frames::<modbus::Frame>::new());
    let mut out = Vec::new();
    let (accepted, error) = forward_input(
        &Interceptor::new(128),
        &mut stream,
        &input,
        &mut out,
        |_, _, _| Rewrite::Forward,
    )
    .unwrap_err();
    assert_eq!(accepted, input.len());
    assert!(matches!(
        error,
        fictionet::stdlib::codec::InterceptError::Decode(Fail::Protocol(modbus::Error::Protocol(
            1
        )))
    ));
    assert_eq!(out, first);
    assert_eq!(stream.unread(), &input[first.len()..]);
}

#[test]
fn skip_limit_does_not_consume_the_next_item() {
    let mut stream = Stream::new(json::Values::new());
    let input = b"    1 ";
    assert_eq!(stream.push(input), input.len());
    let mut calls = 0;
    let mut out = Vec::new();
    assert!(
        Interceptor::new(2)
            .next(&mut stream, &mut out, |_, _, _| {
                calls += 1;
                Rewrite::Forward
            })
            .unwrap()
            .is_err()
    );
    assert_eq!(calls, 0);
    assert_eq!(stream.offset(), 0);
    assert_eq!(stream.unread(), input);
    Interceptor::new(16)
        .next(&mut stream, &mut out, |value, _, _| {
            assert_eq!(*value, json::Value::parse(b"1").unwrap());
            calls += 1;
            Rewrite::Forward
        })
        .unwrap()
        .unwrap();
    assert_eq!(calls, 1);
}

fn assert_recorded_empty_plan<D: Decode>(decoder: D, input: &[u8])
where
    D::Item: Clone,
    D::Error: Clone,
{
    let mut stream = Stream::new(decoder);
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
    let mut faults = Faults::new(4096, 16);
    let mut log = Recorder::new(128, 4096);
    let mut out = Vec::new();
    for chunk in test_support::chunks(input, &[1]).chain(core::iter::once(&[][..])) {
        if chunk.is_empty() {
            stream.end();
        } else {
            assert_eq!(stream.push(chunk), chunk.len());
        }
        while let Some(result) = faults.next_with_observed(
            &entropy,
            &mut stream,
            &mut out,
            &[],
            write_bounded::<modbus::Frame>,
            log.observer(0, Direction::ClientToServer),
        ) {
            result.unwrap();
        }
    }
    assert_eq!(out, input);
    assert_eq!(
        log.iter()
            .flat_map(|r| r.bytes.iter().copied())
            .collect::<Vec<_>>(),
        input
    );
    assert!(log.iter().any(|r| matches!(r.kind, RecordKind::Skipped)));
    assert!(log.iter().any(|r| matches!(r.kind, RecordKind::Item(_))));
}

#[test]
fn empty_plan_records_and_forwards_json_scalars() {
    assert_recorded_empty_plan(json::Values::new(), b"1 2\n");
}

#[test]
fn empty_plan_records_and_forwards_json_objects() {
    assert_recorded_empty_plan(json::Values::new(), b"{\"a\":1}\n  {\"b\":2}\n");
}

#[test]
fn empty_plan_records_and_forwards_refused_lines() {
    assert_recorded_empty_plan(Lines::new(4, Ending::LfOrCrlf), b"abcdefgh\nok\n");
}

#[test]
fn skip_reservation_failure_leaves_decode_failure_for_retry() {
    use fictionet::stdlib::codec::{InterceptError, RewriteError};
    let input = b" \n!";
    let mut stream = Stream::new(json::Values::new());
    assert_eq!(stream.push(input), input.len());
    let mut out = Vec::new();
    assert!(matches!(
        Interceptor::new(1).next(&mut stream, &mut out, |_, _, _| Rewrite::Forward),
        Some(Err(InterceptError::Rewrite(RewriteError::Capacity {
            buffered: 3,
            limit: 1
        })))
    ));
    assert_eq!(stream.offset(), 0);
    assert!(stream.failed().is_none());
    assert!(matches!(
        Interceptor::new(16).next(&mut stream, &mut out, |_, _, _| Rewrite::Forward),
        Some(Err(InterceptError::Decode(_)))
    ));
    assert!(stream.failed().is_some());
    assert_eq!(out, b" \n");
    assert_eq!([out.clone(), stream.unread().to_vec()].concat(), input);
    assert!(
        Interceptor::new(16)
            .next(&mut stream, &mut out, |_, _, _| Rewrite::Forward)
            .is_none()
    );
}

#[test]
fn holds_and_delays_share_recording_and_forwarded_skips() {
    let input = b" 1 2\n";
    let mut stream = Stream::new(json::Values::new());
    assert_eq!(stream.push(input), input.len());
    stream.end();
    let duration = Duration::from_millis(5);
    let plan = [
        Rule {
            when: Trigger::At(1),
            fault: ItemFault::<json::Value>::Hold { window: 1 },
        },
        Rule {
            when: Trigger::At(2),
            fault: ItemFault::Action {
                delay: Some(duration),
                rewrite: Rewrite::Forward,
            },
        },
    ];
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
    let mut faults = Faults::new(128, 4);
    let mut log = Recorder::new(16, 128);
    let mut out = Vec::new();
    let mut markers = Vec::new();
    while let Some(result) = faults.next_with_observed(
        &entropy,
        &mut stream,
        &mut out,
        &plan,
        write_bounded,
        log.observer(9, Direction::ServerToClient),
    ) {
        if let Some(marker) = result.unwrap() {
            markers.push(marker);
        }
    }
    faults.flush(&mut out).unwrap();
    assert_eq!(out, b"  21\n");
    assert_eq!(
        markers,
        [fictionet::stdlib::codec::FaultDelay { at: 2, duration }]
    );
    assert_eq!(
        log.iter()
            .flat_map(|r| r.bytes.iter().copied())
            .collect::<Vec<_>>(),
        input
    );
    assert!(
        log.iter()
            .all(|r| r.tag == 9 && r.direction == Direction::ServerToClient)
    );
    assert_eq!(
        log.iter()
            .filter(|r| matches!(r.kind, RecordKind::Item(_)))
            .count(),
        2
    );
    assert_eq!(
        log.iter()
            .filter(|r| matches!(r.kind, RecordKind::Skipped))
            .count(),
        3
    );
}

#[test]
fn empty_plan_records_and_forwards_pipe_payloads() {
    let pipe = fictionet::stdlib::codec::Pipe::new(
        Frames::<modbus::Frame>::new(),
        Lines::new(4, Ending::LfOrCrlf),
        |frame: modbus::Frame| Carry::Bytes(frame.pdu),
    );
    let input = modbus::Frame {
        pdu: b"abcdefgh\nok\n".to_vec(),
        ..frame(1)
    }
    .to_bytes()
    .unwrap();
    assert_recorded_empty_plan(pipe, &input);
}

#[test]
fn intercept_reports_accepted_prefix_before_unaccepted_suffix() {
    let first = frame(1).to_bytes().unwrap();
    let mut input = [first.as_slice(), &[0, 2, 0, 1, 0, 2]].concat();
    input.resize(1024, 0);
    let mut stream = Stream::new(Frames::<modbus::Frame>::new());
    let mut out = Vec::new();
    let (accepted, error) = forward_input(
        &Interceptor::new(4096),
        &mut stream,
        &input,
        &mut out,
        |_, _, _| Rewrite::Forward,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        fictionet::stdlib::codec::InterceptError::Decode(_)
    ));
    assert!(accepted < input.len());
    assert_eq!(accepted, Frames::<modbus::Frame>::new().capacity());
    assert_eq!(out, first);
    assert_eq!(
        [out.as_slice(), stream.unread(), &input[accepted..]].concat(),
        input
    );
}

#[test]
fn intercept_accepts_only_what_output_can_hold_and_resumes_after_draining() {
    let input = b"1 ".repeat(16);
    let proxy = Interceptor::new(16);
    let mut stream = Stream::new(json::Values::new());
    let mut out = Vec::new();
    let mut spaces = 0;
    let mut accepted = 0;
    for _ in 0..64 {
        let result = forward_input(
            &proxy,
            &mut stream,
            &input[accepted..],
            &mut out,
            |_, _, _| Rewrite::<json::Value>::Drop,
        );
        let taken = match result {
            Ok(taken) => taken,
            Err((taken, InterceptError::Rewrite(RewriteError::TooLong { limit: 16 }))) => taken,
            Err((_, error)) => panic!("unexpected {error:?}"),
        };
        assert!(stream.buffered() <= proxy.limit());
        accepted += taken;
        spaces += out.len();
        out.clear();
        if accepted == input.len() {
            break;
        }
    }
    assert_eq!(accepted, input.len());
    stream.end();
    assert_eq!(
        forward_input(&proxy, &mut stream, b"", &mut out, |_, _, _| {
            Rewrite::<json::Value>::Drop
        }),
        Ok(0)
    );
    assert_eq!(spaces + out.len(), 16);
    assert_eq!(stream.buffered(), 0);
}

// Drive input under the interceptor budget and retain accepted-byte assertions.
#[allow(clippy::type_complexity)]
fn forward_input<D: Decode>(
    proxy: &Interceptor,
    stream: &mut Stream<D>,
    bytes: &[u8],
    out: &mut Vec<u8>,
    policy: impl FnMut(&D::Item, &[u8], core::ops::Range<u64>) -> Rewrite<D::Item>,
) -> Result<
    usize,
    (
        usize,
        InterceptError<D::Error, <D::Item as Wire>::WriteError>,
    ),
>
where
    D::Item: Wire,
    D::Error: Clone,
{
    rewrite_input(proxy, stream, bytes, out, policy, write_bounded)
}

fn rewrite_input<D: Decode, T, E>(
    proxy: &Interceptor,
    stream: &mut Stream<D>,
    mut bytes: &[u8],
    out: &mut Vec<u8>,
    mut policy: impl FnMut(&D::Item, &[u8], core::ops::Range<u64>) -> Rewrite<T>,
    mut write: impl FnMut(&T, &mut Buffer) -> Result<(), RewriteError<E>>,
) -> Result<usize, (usize, InterceptError<D::Error, E>)>
where
    D::Error: Clone,
{
    let length = bytes.len();
    loop {
        // Drain first so EOF and handoff leave new input unaccepted.
        while let Some(result) = proxy.next_with(stream, out, &mut policy, &mut write) {
            if let Err(error) = result {
                return Err((length - bytes.len(), error));
            }
        }
        if bytes.is_empty() || stream.is_done() {
            return Ok(length - bytes.len());
        }
        let room = proxy.room(stream, out);
        if room == 0 {
            return Err((
                length - bytes.len(),
                InterceptError::Rewrite(RewriteError::TooLong {
                    limit: proxy.limit(),
                }),
            ));
        }
        let taken = stream.push(&bytes[..bytes.len().min(room)]);
        if taken == 0 {
            // A live, drained stream has room. A refused push means
            // its buffer could not reserve storage. Do not retry here.
            return Err((
                length - bytes.len(),
                InterceptError::Rewrite(RewriteError::Allocation),
            ));
        }
        bytes = &bytes[taken..];
    }
}
