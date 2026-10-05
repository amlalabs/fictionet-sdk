//! Kafka frames, requests and responses, as a world playing a broker reads
//! them.
#![no_main]

use fictionet::stdlib::kafka::{Decoder, Reader, Request, Response, api_key};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut frames = Vec::new();
    while let Some(Ok(f)) = whole.next_frame() {
        frames.push(f);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(f)) = bytewise.next_frame() {
            again.push(f);
        }
    }
    assert_eq!(frames, again);

    // Each payload, and the bytes on their own, as a request and as a
    // response to the APIs with full bodies.
    let mut payloads: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    payloads.push(data);
    for p in payloads {
        // A request read can be written, and reads back the same.
        if let Ok(req) = Request::parse(p) {
            let bytes = req.to_bytes().unwrap();
            assert_eq!(Request::parse(&bytes), Ok(req.clone()));
            let framed = req.to_frame().unwrap();
            let mut d = Decoder::new();
            d.feed(&framed);
            assert_eq!(d.next_frame(), Some(Ok(bytes)));
        }
        for key in [api_key::API_VERSIONS, api_key::METADATA] {
            for version in 0..=13 {
                if let Ok(resp) = Response::parse(p, key, version) {
                    let bytes = resp.to_bytes(key, version).unwrap();
                    assert_eq!(Response::parse(&bytes, key, version), Ok(resp));
                }
            }
        }
        // The primitive readers on their own.
        let mut r = Reader::new(p);
        let _ = r.tagged_fields();
        let _ = r.varlong();
        let _ = r.compact_nullable_string();
        let _ = r.compact_array_len();
        let _ = r.nullable_bytes();
    }
});
