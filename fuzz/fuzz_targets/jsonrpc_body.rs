//! Complete JSON-RPC bodies, batch errors, bounded collection, and writes.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Collect, CollectError, Decode, Fail, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::{
    json::{self, Limits, Value},
    jsonrpc::{self, Batch, Body, Error, Incoming, Message},
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fn check_error(error: Error) {
    let reply = Message::Response(error.response());
    reply.to_bytes().expect("parse error response must fit");
    reply.write_line(&mut Vec::new()).unwrap();
    let _ = assert_write(&reply);
}

fn check_incoming(incoming: Result<Incoming, Error>) {
    match incoming {
        Ok(incoming) => {
            let items = match incoming {
                Incoming::Message(m) => vec![m],
                Incoming::Batch(ms) => ms,
            };
            for item in items {
                match item {
                    Ok(message) => {
                        let _ = assert_write(&message);
                    }
                    Err(error) => check_error(error),
                }
            }
        }
        Err(error) => check_error(error),
    }
}

fuzz_target!(|input: &[u8]| {
    let (limit, limits, data) = match input {
        [a, b, rest @ ..] if a & 0x80 != 0 => (
            usize::from(*b) * 8,
            Limits {
                size: usize::from(*b) * 8,
                depth: usize::from(a & 15),
                elements: usize::from(a >> 4 & 7) * 8 + 1,
            },
            rest,
        ),
        _ => (json::MAX_SIZE, Limits::default(), input),
    };
    let make = || Collect::<Body>::new(limit);
    let bound = 2 * make().capacity();
    assert_eq!(
        decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= bound);
        }),
        decode_all(make, data),
    );
    let server = || Collect::<Value>::new(limit);
    let bound = 2 * server().capacity();
    assert_eq!(
        decode_chunks(&mut Stream::new(server()), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= bound);
        }),
        decode_all(server, data),
    );
    let (values, failure) = decode_all(server, data);
    if let Some(Fail::Protocol(CollectError::Parse(error))) = failure {
        check_error(error.into());
    }
    for value in values {
        check_incoming(Incoming::from_value(value));
    }
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Batch as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Body as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let (bodies, failure) = decode_all(make, data);
    if let Some(Fail::Protocol(CollectError::Parse(error))) = failure {
        check_error(error);
    }
    for error in [
        Message::parse(data).err(),
        Batch::parse(data).err(),
        Body::parse(data).err(),
    ]
    .into_iter()
    .flatten()
    {
        check_error(error);
    }
    for body in bodies {
        let _ = assert_write(&body);
        let bytes = body.to_bytes().unwrap();
        assert_eq!(decode_all(make, &bytes), (vec![body], None));
    }
    if let Ok(value) = json::parse_with(data, &limits) {
        match Body::from_value(value) {
            Ok(body) => {
                let bytes = body.to_bytes().unwrap();
                assert_eq!(
                    Body::from_value(json::parse_with(&bytes, &limits).unwrap()),
                    Ok(body)
                );
            }
            Err(error) => check_error(error),
        }
    }
    check_incoming(jsonrpc::parse_incoming_with(data, &limits));
    if let Ok(Value::Array(values)) = &mut Value::parse(data) {
        let batch = Batch {
            messages: core::mem::take(values)
                .into_iter()
                .map(|value| Message::Response(jsonrpc::Response { value }))
                .collect(),
        };
        let _ = assert_write(&batch);
        let _ = assert_write(&Body::Batch(batch));
    }
});
