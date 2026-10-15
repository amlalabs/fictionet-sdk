#![no_main]

use fictionet::stdlib::codec::Collect;
use fictionet::stdlib::http1::{Chunk, Header, Request, RequestEvents, RequestHead, Version};
use fictionet::stdlib::test_support::contract;
use fictionet_fuzz::http1::event_limits;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = event_limits();
    contract::check_decode_limits(|| RequestEvents::with_limits(limits), data, 0, 4096);
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
