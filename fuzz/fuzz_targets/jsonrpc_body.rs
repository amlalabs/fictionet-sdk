//! Complete JSON-RPC bodies, batch errors, bounded collection, and writes.
#![no_main]

use fictionet::stdlib::codec::{Collect, CollectError, Decode, Fail, Wire};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::{
    json::{self, Limits, Value},
    jsonrpc::{self, Batch, Body, Error, Incoming, Message},
};
use libfuzzer_sys::fuzz_target;

fn check_error(error: Error) {
    let reply = Message::Response(error.response());
    reply.to_bytes().expect("parse error response must fit");
    reply.write_line(&mut Vec::new()).unwrap();
    contract::check_wire_value(&reply);
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
                    Ok(message) => contract::check_wire_value(&message),
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
    contract::check_decode_with_alloc_limit(make, data, 2 * make().capacity());
    let server = || Collect::<Value>::new(limit);
    contract::check_decode_with_alloc_limit(server, data, 2 * server().capacity());
    let (values, failure) = decode_all(server, data);
    if let Some(Fail::Protocol(CollectError::Parse(error))) = failure {
        check_error(error.into());
    }
    for value in values {
        check_incoming(Incoming::from_value(value));
    }
    contract::check_wire::<Message>(data);
    contract::check_wire::<Batch>(data);
    contract::check_wire::<Body>(data);
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
        contract::check_wire_value(&body);
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
        contract::check_wire_value(&batch);
        contract::check_wire_value(&Body::Batch(batch));
    }
});
