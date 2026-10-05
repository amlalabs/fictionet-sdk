//! Kafka frames, requests and responses, as a world playing a broker reads
//! them.
#![no_main]
#![allow(deprecated)] // Also exercise the compatibility decoder.

use fictionet::stdlib::codec::{Decode, contract};
use fictionet::stdlib::kafka::{
    Decoder, Frame, Frames, MAX_FRAME, Reader, Request, Response, api_key,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Frame>(data);
    contract::check_decode(
        || Frames::with_limit(usize::from(data.first().copied().unwrap_or(0))),
        data,
    );
    contract::check_decode(|| Frames::new().map(|frame| Request::parse(&frame.0)), data);
    contract::check_wire_value(&Frame(data.iter().take(MAX_FRAME + 1).copied().collect()));

    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut frames = Vec::new();
    while let Some(f) = whole.next_frame() {
        match f {
            Ok(f) => frames.push(f),
            // A broken stream keeps nothing.
            Err(_) => {
                assert_eq!(whole.buffered(), 0);
                break;
            }
        }
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(f)) = bytewise.next_frame() {
            again.push(f);
        }
        // Nothing past one frame and its size is held.
        assert!(bytewise.buffered() <= 4 + MAX_FRAME);
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
                // ApiVersions answers that read in version 0 are taken for
                // any version, and must write back in the one asked for.
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
