//! Complete JSON-RPC bodies, batch errors, bounded collection, and writes.
#![no_main]

use fictionet::stdlib::codec::{Collect, Decode, Wire, contract, test_support::decode_all};
use fictionet::stdlib::{
    json::{Limits, Value},
    jsonrpc::{self, Batch, Body, Incoming, Message},
};
use libfuzzer_sys::fuzz_target;

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
        _ => (4096, Limits::default(), input),
    };
    let make = || Collect::<Body>::new(limit);
    contract::check_decode_with_alloc_limit(make, data, 2 * make().capacity());
    contract::check_wire::<Message>(data);
    contract::check_wire::<Batch>(data);
    contract::check_wire::<Body>(data);
    let (bodies, _) = decode_all(make, data);
    for body in bodies {
        contract::check_wire_value(&body);
        let bytes = body.to_bytes().unwrap();
        assert_eq!(decode_all(make, &bytes), (vec![body], None));
    }
    if let Ok(body) = jsonrpc::parse_with(data, &limits) {
        let bytes = body.to_bytes().unwrap();
        assert_eq!(jsonrpc::parse_with(&bytes, &limits), Ok(body));
    }
    if let Ok(incoming) = jsonrpc::parse_incoming_with(data, &limits) {
        let items = match incoming {
            Incoming::Message(m) => vec![m],
            Incoming::Batch(ms) => ms,
        };
        for item in items {
            match item {
                Ok(message) => contract::check_wire_value(&message),
                Err(error) => contract::check_wire_value(&Message::Response(error.response())),
            }
        }
    }
    if let Ok(Value::Array(values)) = Value::parse(data) {
        let batch = Batch {
            messages: values
                .into_iter()
                .map(|value| Message::Response(jsonrpc::Response { value }))
                .collect(),
        };
        contract::check_wire_value(&batch);
        contract::check_wire_value(&Body::Batch(batch));
    }
});
