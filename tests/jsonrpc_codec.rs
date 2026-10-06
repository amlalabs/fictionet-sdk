//! JSON-RPC envelopes and stdio/HTTP framing through public codec tools.

use fictionet::stdlib::codec::{
    Carry, Collect, Decode, Demux, Ending, Layered, Lines, Pipe, Stream, Wire, contract, finish,
    pump,
    test_support::{Lcg, chunks, decode_all, mutate, random_chunks},
};
use fictionet::stdlib::json::{self, Limits, Value};
use fictionet::stdlib::jsonrpc::{self, Batch, Body, ErrorKind, Id, Message, Messages, Request};
use std::fmt::Debug;

fn partitioned<'a, D: Decode>(decoder: D, parts: impl Iterator<Item = &'a [u8]>) -> Vec<D::Item>
where
    D::Error: Clone + Debug,
{
    let mut stream = Stream::new(decoder);
    let mut items = Vec::new();
    for part in parts {
        assert_eq!(
            pump(&mut stream, part, |item| items.push(item)).unwrap(),
            part.len()
        );
        assert!(stream.buffered() <= stream.decoder().capacity());
    }
    finish(&mut stream, |item| items.push(item)).unwrap();
    assert!(stream.is_done());
    assert!(stream.failed().is_none());
    items
}

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
    assert_eq!(partitioned(Messages::new(), chunks(&bytes, &[1])), expected);
    for seed in 0..12 {
        assert_eq!(
            partitioned(
                Messages::new(),
                random_chunks(&bytes, &mut Lcg::new(seed), 37)
            ),
            expected
        );
    }
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
        let body = jsonrpc::parse(bytes).unwrap();
        let written = body.to_bytes().unwrap();
        assert_eq!(decode_all(make, &written), (vec![body.clone()], None));
        assert_eq!(
            partitioned(make(), chunks(bytes, &[1])),
            std::slice::from_ref(&body)
        );
        assert_eq!(
            partitioned(make(), random_chunks(bytes, &mut Lcg::new(71), 19)),
            [body]
        );
    }
}

#[test]
fn recoverable_errors_and_eof_contracts() {
    let bytes = b"\n{\n0\n{\"jsonrpc\":\"2.0\",\"method\":false,\"id\":1e400}\r\n{\"jsonrpc\":\"2.0\",\"method\":\"ok\"}\npartial";
    contract::check_decode(Messages::new, bytes);
    let (items, failure) = decode_all(Messages::new, bytes);
    assert_eq!(failure, None);
    assert_eq!(partitioned(Messages::new(), chunks(bytes, &[1])), items);
    assert_eq!(
        partitioned(Messages::new(), random_chunks(bytes, &mut Lcg::new(99), 13)),
        items
    );
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
    let expected = jsonrpc::parse(br#"{"jsonrpc":"2.0","method":"ping","id":1}"#).unwrap();
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
