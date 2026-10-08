#![no_main]

use fictionet::stdlib::codec::Collect;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::http1::{
    Header, Limits, MAX_PENDING_REQUESTS, Response, ResponseEvents, ResponseHead, Version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        start_line: 256,
        header_line: 256,
        headers: 16,
        head: 2048,
        body_chunk: 31,
        ..Limits::default()
    };
    for method in ["GET", "HEAD", "CONNECT"] {
        let make = || {
            let mut decoder = ResponseEvents::with_limits(limits);
            decoder.expect_method(method).unwrap();
            decoder.expect_method("GET").unwrap();
            decoder
        };
        contract::check_decode_with_held_limit(make, data, MAX_PENDING_REQUESTS);
        if let Ok(response) = Response::parse_for(data, method) {
            let mut out = Vec::new();
            response.write_for(method, &mut out).unwrap();
            assert_eq!(Response::parse_for(&out, method), Ok(response));
        }
    }
    contract::check_decode_with_alloc_limit(|| ResponseEvents::with_limits(limits), data, 4096);
    contract::check_decode(|| Collect::<Response>::new(4096), data);
    contract::check_wire::<Response>(data);
    contract::check_wire::<ResponseHead>(data);
    let bounded = &data[..data.len().min(512)];
    let response = Response {
        head: ResponseHead {
            version: Version::Http11,
            status: data
                .first()
                .map_or(200, |b| u16::from(*b).saturating_mul(3)),
            reason: bounded.to_vec(),
            headers: vec![Header {
                name: "Content-Length".into(),
                value: bounded.len().to_string().into_bytes(),
            }],
        },
        body: bounded.to_vec(),
    };
    contract::check_wire_value(&response);
});
