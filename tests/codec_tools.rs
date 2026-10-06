use core::{convert::Infallible, time::Duration};
use fictionet::stdlib::{
    codec::{
        ByteFault, Carry, Decode, Demux, Direction, Ending, Fail, Faults, Interceptor, ItemFault,
        Layered, Lines, RecordKind, Recorder, Rewrite, Rule, Stream, Trigger, Wire, contract,
        test_support,
    },
    json, modbus,
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
    contract::check_decode(|| modbus::Frames, &input);
    let replacement = modbus::Frame {
        unit: 9,
        ..frame(1)
    };
    contract::check_wire_value(&replacement);
    let rules = [
        Rule {
            when: Trigger::At(1),
            fault: ItemFault::Replace(vec![replacement.clone()]),
        },
        Rule {
            when: Trigger::At(2),
            fault: ItemFault::Drop,
        },
        Rule {
            when: Trigger::At(3),
            fault: ItemFault::Duplicate(2),
        },
        Rule {
            when: Trigger::At(4),
            fault: ItemFault::Delay(Duration::from_millis(10)),
        },
    ];
    let mut log = Recorder::new(16, 4096);
    let mut client = Stream::new(modbus::Frames);
    let mut server = Stream::new(modbus::Frames);
    let upstream = Interceptor::new(4096);
    let downstream = Interceptor::new(4096);
    let mut faults = Faults::new(42, 4096);
    let mut sent = Vec::new();
    let mut markers = Vec::new();
    for chunk in test_support::chunks(&input, &[1]) {
        assert_eq!(client.push(chunk), chunk.len());
        while let Some(r) = log.with_next(Direction::ClientToServer, &mut client, |_, raw, _| {
            let action = faults.item(&rules);
            if let Some(delay) = action.delay {
                markers.push((sent.len(), delay));
            }
            upstream.apply(raw, action.rewrite, &mut sent)
        }) {
            r.unwrap().unwrap();
        }
    }
    client.end();
    assert!(
        log.with_next(Direction::ClientToServer, &mut client, |_, _, _| ())
            .is_none()
    );
    let (forwarded, failure) = test_support::decode_all(|| modbus::Frames, &sent);
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
    log.with_next(Direction::ServerToClient, &mut server, |_, raw, _| {
        downstream.apply(raw, Rewrite::<modbus::Frame>::Forward, &mut received)
    })
    .unwrap()
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

fn write_line(value: &json::Value, out: &mut Vec<u8>) -> Result<(), json::Error> {
    value.write(out)?;
    out.push(b'\n');
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
    let mut faults = Faults::new(4, 4096);
    let plan = [
        Rule {
            when: Trigger::At(1),
            fault: ItemFault::<json::Value>::Duplicate(2),
        },
        Rule {
            when: Trigger::At(2),
            fault: ItemFault::Drop,
        },
    ];
    let mut sent = Vec::new();
    let mut call_count = 0;
    for byte in &input {
        assert_eq!(streams[0].push(&[*byte]), 1);
        while let Some(r) = log.with_next(
            Direction::ClientToServer,
            &mut streams[0],
            |item, raw, _| {
                let value = item.unwrap();
                if value.get("method").and_then(json::Value::as_str) == Some("tools/call") {
                    call_count += 1;
                }
                proxies[0].apply_with(raw, faults.item(&plan).rewrite, &mut sent, write_line)
            },
        ) {
            r.unwrap().unwrap();
        }
    }
    assert_eq!(sent, call.repeat(2)); // CRLF and spacing survive duplication.
    assert_eq!(call_count, 1);
    let mut received = Vec::new();
    assert_eq!(streams[1].push(result), result.len());
    log.with_next(
        Direction::ServerToClient,
        &mut streams[1],
        |item, raw, _| {
            assert!(item.unwrap().get("result").is_some());
            proxies[1].apply_with(
                raw,
                Rewrite::Replace(vec![replacement.clone()]),
                &mut received,
                write_line,
            )
        },
    )
    .unwrap()
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
    let mut faults = Faults::new(3, 4096);
    let mut damaged = Vec::new();
    faults
        .bytes(
            &[Rule {
                when: Trigger::Always,
                fault: ByteFault::Truncate(7),
            }],
            &input,
            &mut damaged,
        )
        .unwrap();
    let mut stream = Stream::new(modbus::Frames);
    let mut log = Recorder::new(8, 4096);
    assert_eq!(stream.push(&damaged), 7);
    stream.end();
    assert_eq!(
        log.with_next(Direction::ClientToServer, &mut stream, |_, _, _| ()),
        Some(Err(Fail::Truncated { unread: 7 }))
    );
    assert_eq!(log.iter().next().unwrap().bytes, damaged);
    damaged.clear();
    faults
        .bytes(
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
        test_support::decode_all(|| modbus::Frames, &damaged).1,
        Some(Fail::Protocol(modbus::FrameError::Protocol(1)))
    ));

    let line = b"{\"result\":true}\n";
    let mut edited = Vec::new();
    faults
        .bytes(
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
            modbus::Frames,
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
    contract::check_stack(make, &bytes);
    let mut stream = Stream::new(make());
    let mut log = Recorder::new(8, 256);
    let proxy = Interceptor::new(256);
    let mut faults = Faults::new(1, 256);
    let plan = [Rule {
        when: Trigger::Always,
        fault: ItemFault::Replace(vec![b"xy".to_vec()]),
    }];
    let mut out = Vec::new();
    assert_eq!(stream.push(&bytes), bytes.len());
    log.with_next(
        Direction::ClientToServer,
        &mut stream,
        |item, raw, range| {
            assert_eq!(item, Layered::Inner(Ok(b"ab".to_vec())));
            assert!(raw.is_empty());
            assert_eq!(range, bytes.len() as u64..bytes.len() as u64);
            proxy
                .apply::<modbus::Frame>(raw, Rewrite::Forward, &mut out)
                .unwrap();
            assert!(out.is_empty());
            proxy.apply_with(raw, faults.item(&plan).rewrite, &mut out, |line, target| {
                let mut pdu = line.clone();
                pdu.push(b'\n');
                modbus::Frame {
                    transaction: 7,
                    unit: 1,
                    pdu,
                }
                .write(target)
            })
        },
    )
    .unwrap()
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
    let mut demux = Demux::new(2, 1024, |_: &u8| modbus::Frames);
    let proxy = Interceptor::new(1024);
    let mut faults = Faults::new(8, 1024);
    let mut logs = [Recorder::new(4, 256), Recorder::new(4, 256)];
    let mut out = [Vec::new(), Vec::new()];
    for key in 0..2u8 {
        let input = frame(u16::from(key)).to_bytes().unwrap();
        assert_eq!(demux.push(&key, &input), input.len());
        let plan = [Rule {
            when: Trigger::Always,
            fault: ItemFault::<modbus::Frame>::Duplicate(2),
        }];
        while let Some(r) = logs[usize::from(key)].with_next(
            Direction::ClientToServer,
            demux.get_mut(&key).unwrap(),
            |_, raw, _| proxy.apply(raw, faults.item(&plan).rewrite, &mut out[usize::from(key)]),
        ) {
            r.unwrap().unwrap();
        }
        assert_eq!(out[usize::from(key)], input.repeat(2));
        assert!(demux.total() <= 1024);
    }
    assert_eq!(demux.total(), 0);
    assert_eq!(logs[0].iter().next().unwrap().range.start, 0);
    assert_eq!(logs[1].iter().next().unwrap().range.start, 0);
}

#[test]
fn seeded_item_plans_are_repeatable_across_input_chunking() {
    let input: Vec<_> = (0..64).flat_map(|n| frame(n).to_bytes().unwrap()).collect();
    let run = |chunking: &[usize]| {
        let mut stream = Stream::new(modbus::Frames);
        let mut faults = Faults::new(27, 4096);
        let proxy = Interceptor::new(4096);
        let mut out = Vec::new();
        let plan = [
            Rule {
                when: Trigger::Chance { take: 1, out_of: 3 },
                fault: ItemFault::<modbus::Frame>::Drop,
            },
            Rule {
                when: Trigger::Chance { take: 1, out_of: 2 },
                fault: ItemFault::Duplicate(2),
            },
        ];
        for mut chunk in test_support::chunks(&input, chunking) {
            while !chunk.is_empty() {
                let n = stream.push(chunk);
                chunk = &chunk[n..];
                while let Some(r) =
                    proxy.next(&mut stream, &mut out, |_, _, _| faults.item(&plan).rewrite)
                {
                    r.unwrap();
                }
            }
        }
        stream.end();
        while let Some(r) = proxy.next(&mut stream, &mut out, |_, _, _| faults.item(&plan).rewrite)
        {
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
    log.with_next(Direction::ClientToServer, &mut stream, |item, raw, _| {
        assert!(item.is_ok());
        proxy.apply::<proxy_protocol::Header>(raw, Rewrite::Forward, &mut out)
    })
    .unwrap()
    .unwrap()
    .unwrap();
    for _ in 0..2 {
        assert!(
            log.with_next(Direction::ClientToServer, &mut stream, |_, _, _| ())
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
    let mut stream = stream.swap(modbus::Frames);
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
    let mut stream = Stream::new(modbus::Frames);
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
            fictionet::stdlib::codec::RewriteError::Write(modbus::EncodeError::EmptyPdu)
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
