//! Recoverable JSON-RPC stdio lines, boundaries, limits, and reply writes.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::{
    json::Limits,
    jsonrpc::{Message, Messages},
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let (limits, data) = match input {
        [a, b, rest @ ..] if a & 0x80 != 0 => (
            Limits {
                size: usize::from(*b) * 4,
                depth: usize::from(a & 15),
                elements: usize::from(a >> 4 & 7) * 8 + 1,
            },
            rest,
        ),
        _ => (Limits::default(), input),
    };
    let make = || Messages::with_limits(limits);
    let bound = 2 * make().capacity();
    assert_eq!(
        decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= bound);
            assert_eq!(s.held(), 0);
        }),
        decode_all(make, data),
    );
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let (items, failure) = decode_all(make, data);
    assert_eq!(failure, None);
    for item in items {
        match item {
            Ok(message) => {
                let _ = assert_write(&message);
                let mut bytes = Vec::new();
                message.write_line(&mut bytes).unwrap();
                assert_eq!(decode_all(make, &bytes), (vec![Ok(message)], None));
            }
            Err(error) => {
                let reply = Message::Response(error.response());
                reply.to_bytes().expect("parse error response must fit");
                reply.write_line(&mut Vec::new()).unwrap();
                let _ = assert_write(&reply);
            }
        }
    }
    // Direct envelope edits must either round-trip or refuse transactionally.
    if let Ok(value) = fictionet::stdlib::protocols::json::Value::parse(data) {
        let message = Message::Response(fictionet::stdlib::protocols::jsonrpc::Response { value });
        let _ = assert_write(&message);
        let mut out = vec![42];
        if message.write_line(&mut out).is_err() {
            assert_eq!(out, [42]);
        }
    }
});
