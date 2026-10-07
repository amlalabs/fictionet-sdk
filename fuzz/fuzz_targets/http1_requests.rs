#![no_main]

use fictionet::stdlib::codec::{Collect, contract};
use fictionet::stdlib::http1::{Chunk, Header, Limits, Request, RequestHead, Requests, Version};
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
    contract::check_decode_with_held_limit(|| Requests::with_limits(limits), data, 0);
    contract::check_decode_with_alloc_limit(|| Requests::with_limits(limits), data, 4096);
    contract::check_decode(|| Collect::<Request>::new(4096), data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<RequestHead>(data);
    contract::check_wire::<Chunk>(data);
    let bounded = &data[..data.len().min(512)];
    let request = Request {
        head: RequestHead {
            method: "POST".into(),
            target: "/".into(),
            version: Version::Http11,
            headers: vec![
                Header {
                    name: "Host".into(),
                    value: b"example.test".to_vec(),
                },
                Header {
                    name: "Content-Length".into(),
                    value: bounded.len().to_string().into_bytes(),
                },
                Header {
                    name: String::from_utf8_lossy(bounded).into_owned(),
                    value: bounded.to_vec(),
                },
            ],
        },
        body: bounded.to_vec(),
    };
    contract::check_wire_value(&request);
    contract::check_wire_value(&Chunk(bounded.to_vec()));
});
