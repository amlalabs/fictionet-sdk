//! JSON-RPC envelopes and stdio/HTTP framing through public codec tools.

use fictionet::stdlib::codec::{
    Carry, Collect, CollectError, Demux, Ending, Fail, Layered, Lcg, Lines, Pipe, Stream, Wire,
    contract, finish, pump,
    test_support::{chunks, decode_all, mutate},
    try_pump,
};
use fictionet::stdlib::json::{self, Limits, Value};
use fictionet::stdlib::jsonrpc::{self, Batch, Body, ErrorKind, Id, Message, Messages, Request};

#[test]
fn line_write_decode_round_trips_under_all_chunkings() {
    let inputs = [
        br#"{"id":1.0,"method":"tools/call","jsonrpc":"2.0","params":{"z":1e400,"a":-0},"x":-0}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"ready"}"#,
        br#"{"extra":-0,"jsonrpc":"2.0","result":{"b":1e400,"a":"line\nline"},"id":1.0}"#,
        br#"{"jsonrpc":"2.0","error":{"data":{"z":-0,"a":1.0},"code":-32000,"message":"x"},"id":null}"#,
    ];
    let messages: Vec<_> = inputs.iter().map(|b| Message::parse(b).unwrap()).collect();
    let mut bytes = Vec::new();
    for (message, input) in messages.iter().zip(inputs) {
        contract::check_wire::<Message>(input);
        contract::check_wire_value(message);
        message.write_line(&mut bytes).unwrap();
    }
    let expected: Vec<_> = messages.into_iter().map(Ok).collect();
    contract::check_decode(Messages::new, &bytes);
    contract::check_decode_with_held_limit(Messages::new, &bytes, 0);
    assert_eq!(decode_all(Messages::new, &bytes), (expected, None));
}

#[test]
fn body_wire_and_collection_contracts() {
    for bytes in [
        br#"{"jsonrpc":"2.0","method":"ping","id":-0}"#.as_slice(),
        br#"[{"jsonrpc":"2.0","method":"ping","id":1e400},{"jsonrpc":"2.0","method":"ready"}]"#,
        br#"[{"jsonrpc":"2.0","result":null,"id":1.0}]"#,
    ] {
        contract::check_wire::<Body>(bytes);
        contract::check_wire::<Batch>(bytes);
        contract::check_wire::<Message>(bytes);
        let make = || Collect::<Body>::new(json::MAX_SIZE);
        contract::check_decode(make, bytes);
        let body = Body::parse(bytes).unwrap();
        let written = body.to_bytes().unwrap();
        assert_eq!(decode_all(make, &written), (vec![body], None));
    }
}

#[test]
fn server_body_collection_preserves_mixed_batch_entries() {
    let bytes = br#"[{"jsonrpc":"2.0","method":"ping","id":"1"},{"foo":"boo"},{"jsonrpc":"2.0","method":"ready"},{"result":null}]"#;
    let make = || Collect::<Value>::new(json::MAX_SIZE);
    contract::check_decode(make, bytes);
    let (values, failure) = decode_all(make, bytes);
    assert_eq!(failure, None);
    assert_eq!(values.len(), 1);
    let mut replies = Vec::new();
    for value in values {
        let jsonrpc::Incoming::Batch(entries) = jsonrpc::Incoming::from_value(value).unwrap()
        else {
            panic!("expected a batch");
        };
        assert_eq!(entries.len(), 4);
        for entry in entries {
            match entry {
                Ok(Message::Request(request)) => {
                    replies.push(Message::Response(request.success(Value::Null).unwrap()));
                }
                Err(error) if !error.is_response() => {
                    assert_eq!(error.batch_index, Some(1));
                    replies.push(Message::Response(error.response()));
                }
                _ => {}
            }
        }
    }
    let reply = Batch { messages: replies };
    assert_eq!(reply.to_bytes().unwrap(), br#"[{"jsonrpc":"2.0","result":null,"id":"1"},{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null}]"#);
    contract::check_wire_value(&reply);
}

#[test]
fn server_body_json_errors_have_public_rpc_conversion() {
    for bytes in [b"{".as_slice(), b"", b"[{\"jsonrpc\":\"2.0\",]"] {
        let make = || Collect::<Value>::new(json::MAX_SIZE);
        contract::check_decode(make, bytes);
        let (items, failure) = decode_all(make, bytes);
        assert!(items.is_empty());
        let Some(Fail::Protocol(CollectError::Parse(json_error))) = failure else {
            panic!("expected a JSON parse error");
        };
        let error = jsonrpc::ParseError::from(json_error);
        assert_eq!(error.kind, ErrorKind::Json(json_error));
        assert_eq!(error.id, Id::Null);
        assert_eq!(error.batch_index, None);
        assert!(!error.is_response());
        let reply = Message::Response(error.response());
        assert_eq!(
            reply.to_bytes().unwrap(),
            br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#
        );
        contract::check_wire_value(&reply);
    }
    let bytes = vec![b'1'; json::MAX_NUMBER_LEN + 1];
    let (items, failure) = decode_all(|| Collect::<Value>::new(json::MAX_SIZE), &bytes);
    assert!(items.is_empty());
    let Some(Fail::Protocol(CollectError::Parse(json_error))) = failure else {
        panic!("expected a JSON limit error");
    };
    let error = jsonrpc::ParseError::from(json_error);
    assert_eq!(error.rpc_code(), jsonrpc::INVALID_REQUEST);
    contract::check_wire_value(&Message::Response(error.response()));
}

#[test]
fn mcp_dispatch_can_skip_blank_lines_by_public_kind() {
    let bytes = b"\n \t\r\n{\n{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}\n";
    contract::check_decode(Messages::new, bytes);
    let (items, failure) = decode_all(Messages::new, bytes);
    assert_eq!(failure, None);
    assert_eq!(items.len(), 4);
    let mut replies = Vec::new();
    let mut blanks = 0;
    for item in items {
        let reply = match item {
            Err(error) if error.kind == ErrorKind::BlankLine => {
                blanks += 1;
                continue;
            }
            Err(error) if !error.is_response() => error.response(),
            Ok(Message::Request(request)) => request.success(Value::Null).unwrap(),
            _ => continue,
        };
        Message::Response(reply).write_line(&mut replies).unwrap();
    }
    assert_eq!(blanks, 2);
    let (items, failure) = decode_all(Messages::new, &replies);
    assert_eq!(failure, None);
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0]
            .as_ref()
            .unwrap()
            .value()
            .get("error")
            .unwrap()
            .get("code"),
        Some(&Value::from(jsonrpc::PARSE_ERROR))
    );
    assert_eq!(
        items[1].as_ref().unwrap().value().get("id"),
        Some(&Value::from(1))
    );
}

#[test]
fn stdio_answers_objects_without_method_or_response_members() {
    for (bytes, id) in [
        (b"{}\n".as_slice(), Value::Null),
        (b"{\"id\":1}\n", Value::from(1)),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":5,\"params\":[1]}\n",
            Value::from(5),
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":5,\"methood\":\"ping\"}\n",
            Value::from(5),
        ),
    ] {
        contract::check_decode(Messages::new, bytes);
        let (items, failure) = decode_all(Messages::new, bytes);
        assert_eq!(failure, None);
        assert_eq!(items.len(), 1);
        let error = items.into_iter().next().unwrap().unwrap_err();
        assert!(!error.is_response());
        let reply = Message::Response(error.response());
        assert_eq!(reply.value().get("id"), Some(&id));
        assert_eq!(
            reply.value().get("error").unwrap().get("code"),
            Some(&Value::from(jsonrpc::INVALID_REQUEST))
        );
        contract::check_wire_value(&reply);
    }
}

#[test]
fn recoverable_errors_and_eof_contracts() {
    let bytes = b"\n{\n0\n{\"jsonrpc\":\"2.0\",\"method\":false,\"id\":1e400}\r\n{\"jsonrpc\":\"2.0\",\"method\":\"ok\"}\npartial";
    contract::check_decode(Messages::new, bytes);
    let (items, failure) = decode_all(Messages::new, bytes);
    assert_eq!(failure, None);
    assert!(items.iter().any(Result::is_ok));
    for error in items.into_iter().filter_map(Result::err) {
        contract::check_wire_value(&Message::Response(error.response()));
    }
    let oversized = [
        vec![b'x'; 200],
        b"\n{\"jsonrpc\":\"2.0\",\"method\":\"ok\"}\n".to_vec(),
    ]
    .concat();
    let make = || Messages::with_limits(40, Limits::default());
    contract::check_decode(make, &oversized);
    let (items, failure) = decode_all(make, &oversized);
    assert_eq!(failure, None);
    assert_eq!(items.len(), 2);
    assert!(matches!(
        items.first().unwrap().as_ref().unwrap_err().kind,
        ErrorKind::Line(_)
    ));
    assert!(items.last().unwrap().is_ok());
    for limit in [0, 1, 2, 32, 64] {
        contract::check_decode(|| Messages::with_limits(limit, Limits::default()), bytes);
        contract::check_decode(|| Collect::<Body>::new(limit), bytes);
    }
}

#[test]
fn parse_error_with_near_limit_id_always_has_a_writable_response() {
    let body = format!(
        r#"{{"jsonrpc":"bad","id":"{}"}}"#,
        "x".repeat(json::MAX_SIZE - 40)
    );
    assert!(body.len() <= jsonrpc::MAX_LINE);
    let mut line = body.as_bytes().to_vec();
    line.push(b'\n');
    let (items, failure) = decode_all(Messages::new, &line);
    assert_eq!(failure, None);
    assert_eq!(items.len(), 1);
    let jsonrpc::Incoming::Message(Err(body_error)) =
        jsonrpc::parse_incoming(body.as_bytes()).unwrap()
    else {
        panic!("expected an invalid envelope");
    };
    for error in [items.into_iter().next().unwrap().unwrap_err(), body_error] {
        assert_eq!(error.kind, ErrorKind::Version);
        assert!(matches!(error.id, Id::String(_)));
        let reply = Message::Response(error.response());
        assert!(reply.to_bytes().is_ok(), "parse error response must fit");
        assert_eq!(reply.value().get("id"), Some(&Value::Null));
        let mut out = Vec::new();
        reply.write_line(&mut out).unwrap();
        contract::check_wire_value(&reply);
    }
}

fn assert_error_response_writes(error: jsonrpc::ParseError) {
    let reply = Message::Response(error.response());
    let bytes = reply.to_bytes().expect("parse error response must fit");
    assert_eq!(Message::parse(&bytes).unwrap(), reply);
    reply.write_line(&mut Vec::new()).unwrap();
    contract::check_wire_value(&reply);
}

#[test]
fn default_line_and_body_errors_always_have_writable_responses() {
    let mut inputs = [
        "",
        " \t\r",
        "{",
        "null",
        "[]",
        "[[],1,{}]",
        "{}",
        r#"{"jsonrpc":"bad","method":"x","id":"kept"}"#,
        r#"{"jsonrpc":"2.0","method":1,"id":null}"#,
        r#"{"jsonrpc":"2.0","method":"x","params":null,"id":1}"#,
        r#"{"jsonrpc":"2.0","method":"x","id":true}"#,
        r#"{"jsonrpc":"2.0","method":"x","id":1,"id":2}"#,
        r#"{"jsonrpc":"2.0","method":"x","result":1}"#,
        r#"{"jsonrpc":"2.0","result":1}"#,
        r#"{"jsonrpc":"2.0","id":5,"result":1,"error":{}}"#,
        r#"{"jsonrpc":"2.0","id":5,"error":null}"#,
        r#"{"jsonrpc":"2.0","id":5,"error":{"code":0.1,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":5,"error":{"code":0,"message":false}}"#,
    ]
    .map(str::to_owned)
    .to_vec();
    inputs.push(format!(
        "{}0{}",
        "[".repeat(json::MAX_DEPTH + 1),
        "]".repeat(json::MAX_DEPTH + 1)
    ));
    inputs.push(format!("[{}null]", "null,".repeat(json::MAX_ELEMENTS)));
    inputs.push("1".repeat(json::MAX_NUMBER_LEN + 1));
    inputs.push("x".repeat(json::MAX_SIZE + 1));
    for input in inputs {
        if let Err(error) = Body::parse(input.as_bytes()) {
            assert_error_response_writes(error);
        }
        match jsonrpc::parse_incoming(input.as_bytes()) {
            Err(error) => assert_error_response_writes(error),
            Ok(incoming) => {
                let items = match incoming {
                    jsonrpc::Incoming::Message(item) => vec![item],
                    jsonrpc::Incoming::Batch(items) => items,
                };
                for error in items.into_iter().filter_map(Result::err) {
                    assert_error_response_writes(error);
                }
            }
        }
        for ending in ["", "\n", "\r\n"] {
            let line = format!("{input}{ending}");
            let (items, failure) = decode_all(Messages::new, line.as_bytes());
            assert_eq!(failure, None);
            for error in items.into_iter().filter_map(Result::err) {
                assert_error_response_writes(error);
            }
        }
    }
}

#[test]
fn dispatch_continues_after_refused_reply_and_ignores_responses() {
    let request = Message::Request(Request::new(
        "missing",
        None,
        Id::String("x".repeat(json::MAX_SIZE - 64)),
    ));
    let mut input = request.to_bytes().unwrap();
    input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":1,\"error\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":7}\n");
    let mut stream = Stream::new(Messages::new());
    let mut output = Vec::new();
    let mut refusals = 0;
    try_pump(&mut stream, &input, |item| {
        let reply = match item {
            Ok(Message::Request(req)) => {
                req.error(jsonrpc::METHOD_NOT_FOUND, "Method not found")?
            }
            Err(error) if !error.is_response() => error.response(),
            _ => return Ok(()),
        };
        if Message::Response(reply).write_line(&mut output).is_err() {
            refusals += 1;
        }
        Ok::<_, jsonrpc::ParseError>(())
    })
    .unwrap();
    assert_eq!(refusals, 1);
    let (replies, failure) = decode_all(Messages::new, &output);
    assert_eq!(failure, None);
    assert_eq!(replies.len(), 1);
    assert_eq!(
        replies[0].as_ref().unwrap().value().get("id"),
        Some(&Value::from(7))
    );
}

#[test]
fn lines_take_one_byte_at_a_time_in_linear_time() {
    let mut bytes = format!(
        r#"{{"jsonrpc":"2.0","method":"{}"}}"#,
        "x".repeat(jsonrpc::MAX_LINE - 64)
    )
    .into_bytes();
    bytes.push(b'\n');
    bytes.extend(vec![b'x'; jsonrpc::MAX_LINE + 100]);
    bytes.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"method\":\"ok\"}\n");
    let started = std::time::Instant::now();
    let mut stream = Stream::new(Messages::new());
    let mut items = Vec::new();
    for part in chunks(&bytes, &[1]) {
        pump(&mut stream, part, |item| items.push(item)).unwrap();
    }
    finish(&mut stream, |item| items.push(item)).unwrap();
    assert_eq!(items.len(), 3);
    assert!(items[0].is_ok());
    assert!(matches!(
        items[1].as_ref().unwrap_err().kind,
        ErrorKind::Line(fictionet::stdlib::codec::LineError::TooLong { .. })
    ));
    assert!(items[2].is_ok());
    assert!(
        started.elapsed().as_secs() < 10,
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn edited_envelopes_are_checked_before_writing() {
    let mut message = Message::Request(Request::new("x", None, Id::Null));
    for replacement in [
        Value::Bool(false),
        Value::Array(vec![]),
        Value::Object(vec![]),
    ] {
        if let Value::Object(members) = message.value_mut() {
            let (_, id) = members.iter_mut().find(|(key, _)| key == "id").unwrap();
            *id = replacement;
        }
        contract::check_wire_value(&message);
        contract::check_wire_value(&Body::Message(message.clone()));
        contract::check_wire_value(&Batch {
            messages: vec![message.clone()],
        });
        let mut out = b"unchanged".to_vec();
        assert!(message.write_line(&mut out).is_err());
        assert_eq!(out, b"unchanged");
    }
}

#[test]
fn bounded_body_pipe_and_independent_stdio_streams() {
    let make = || {
        Pipe::new(
            Lines::new(128, Ending::LfOrCrlf),
            Collect::<Body>::new(256),
            |line| match line {
                Ok(bytes) => Carry::Bytes(bytes),
                error => Carry::Through(error),
            },
        )
    };
    let bytes = b"{\"jsonrpc\":\"2.0\",\n\"method\":\"ping\",\"id\":1}\n";
    contract::check_decode(make, bytes);
    let expected = Body::parse(br#"{"jsonrpc":"2.0","method":"ping","id":1}"#).unwrap();
    assert_eq!(
        decode_all(make, bytes),
        (vec![Layered::Inner(expected)], None)
    );

    let mut streams = Demux::new(2, 1024, |_| Messages::with_limits(64, Limits::default()));
    let bytes = b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n";
    for key in [1, 2] {
        assert_eq!(streams.push(&key, bytes), bytes.len());
        streams.end(&key);
    }
    let mut count = 0;
    while let Some((_key, item)) = streams.next() {
        assert!(item.unwrap().is_ok());
        count += 1;
    }
    assert_eq!(count, 2);
}

#[test]
fn mutations_preserve_decoder_and_writer_contracts() {
    let seed = br#"{"jsonrpc":"2.0","method":"ping","id":1}"#;
    let mut rng = Lcg::new(9);
    for _ in 0..40 {
        let mut input = seed.to_vec();
        mutate(&mut rng, &mut input);
        contract::check_decode(|| Collect::<Body>::new(256), &input);
        contract::check_wire::<Message>(&input);
        contract::check_wire::<Batch>(&input);
        contract::check_wire::<Body>(&input);
        input.push(b'\n');
        contract::check_decode(|| Messages::with_limits(256, Limits::default()), &input);
    }
}
